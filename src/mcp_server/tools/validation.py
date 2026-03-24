from fastmcp import FastMCP, Context
from datetime import datetime
from pathlib import Path

from src.core.ioc_extractor import ExtractionPipeline
from src.core.validator import ValidationPipeline
from src.config.settings import settings
from src.mcp_server.tools.execution import (
    get_latest_stored_plugin_results,
    get_stored_plugin_results,
)
from src.mcp_server.tools.reporting import write_json_report, load_json_report


def _safe_int(value) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _infer_processor_arch(malicious_entries: list[dict], suspicious_entries: list[dict]) -> str:
    # If any observed memory address exceeds 32-bit range, infer x64 user/kernel address space.
    max_32 = 4294967295
    for entry in malicious_entries + suspicious_entries:
        ctx = entry.get("context", {}) if isinstance(entry, dict) else {}
        for key in ("start_vpn", "virtual", "offset", "address"):
            num = _safe_int(ctx.get(key))
            if num is not None and num > max_32:
                return "x64 (inferred)"
    return "unknown"


def _build_compromise_assessment(
    os_type: str,
    malicious_entries: list[dict],
    suspicious_entries: list[dict],
    benign_entries: list[dict],
    source_system_profile: dict | None = None,
) -> dict:
    source_system_profile = source_system_profile or {}
    process_counts: dict[str, int] = {}
    techniques: set[str] = set()
    malicious_hashes: list[str] = []
    injection_count = 0

    for entry in malicious_entries + suspicious_entries:
        ioc_type = str(entry.get("type", "")).lower()
        ctx = entry.get("context", {}) if isinstance(entry, dict) else {}

        proc = ctx.get("process")
        if proc:
            process_counts[str(proc)] = process_counts.get(str(proc), 0) + 1

        tech = ctx.get("technique")
        if tech:
            techniques.add(str(tech))

        if ioc_type == "injection":
            injection_count += 1

        if ioc_type in {"md5", "sha1", "sha256"} and entry.get("verdict") == "malicious":
            malicious_hashes.append(str(entry.get("value", "")))

    top_processes = [
        {"name": name, "count": count}
        for name, count in sorted(process_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    ]

    likely_type = "undetermined"
    rationale: list[str] = []

    has_powershell = any(p.get("name", "").lower() == "powershell.exe" for p in top_processes)
    if injection_count >= 3:
        likely_type = "in-memory injector / fileless trojan"
        rationale.append(f"{injection_count} injection findings (T1055-like behavior)")
    if has_powershell and injection_count >= 1:
        likely_type = "script-assisted in-memory loader"
        rationale.append("injection observed in powershell.exe")
    if malicious_hashes:
        rationale.append(f"{len(malicious_hashes)} malicious hash IOC(s) confirmed")

    malicious_count = len(malicious_entries)
    suspicious_count = len(suspicious_entries)

    if malicious_count >= 5 or (malicious_count >= 1 and injection_count >= 3):
        compromise_level = "high"
    elif malicious_count >= 1 or suspicious_count >= 10:
        compromise_level = "medium"
    else:
        compromise_level = "low"

    confidence = min(
        0.95,
        0.4
        + (0.03 * malicious_count)
        + (0.01 * injection_count)
        + (0.05 if malicious_hashes else 0.0),
    )

    return {
        "system_profile": {
            "os_type": source_system_profile.get("os_type", os_type),
            "version": source_system_profile.get("version", "unknown"),
            "build": source_system_profile.get("build", "unknown"),
            "processor_arch": source_system_profile.get(
                "arch",
                _infer_processor_arch(malicious_entries, suspicious_entries),
            ),
        },
        "malware_assessment": {
            "likely_type": likely_type,
            "compromise_level": compromise_level,
            "confidence": round(confidence, 3),
            "evidence": {
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "benign_count": len(benign_entries),
                "injection_count": injection_count,
                "malicious_hashes": malicious_hashes[:10],
                "top_affected_processes": top_processes,
                "techniques": sorted(techniques),
            },
            "rationale": rationale,
        },
    }


def _escape_md(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _build_forensic_markdown(validation_report: dict, source_report_path: str) -> str:
    malicious  = validation_report.get("malicious",  [])
    suspicious = validation_report.get("suspicious", [])
    benign     = validation_report.get("benign",     [])
    summary    = validation_report.get("summary",    {})
    system_profile    = validation_report.get("system_profile",    {})
    malware_assessment = validation_report.get("malware_assessment", {})

    # ── Categorise entries ────────────────────────────────────────────────────
    HASH_TYPES = {"md5", "sha1", "sha256"}

    injections  = [m for m in malicious  if str(m.get("type", "")).lower() == "injection"]
    hash_iocs   = [m for m in malicious  if str(m.get("type", "")).lower() in HASH_TYPES]

    # Persistence = suspicious services/processes; evasion = suspicious filepaths; hashes = suspicious hashes
    susp_hashes = [s for s in suspicious if str(s.get("type", "")).lower() in HASH_TYPES]
    persist_entries = [
        s for s in suspicious
        if str(s.get("type", "")).lower() not in HASH_TYPES
    ]

    # ── MITRE technique → name lookup ─────────────────────────────────────────
    TECHNIQUE_NAMES: dict[str, str] = {
        "T1055":     "Process Injection",
        "T1055.012": "Process Hollowing",
        "T1059":     "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
        "T1071":     "Application Layer Protocol",
        "T1071.001": "Web Protocols",
        "T1036":     "Masquerading",
        "T1204":     "User Execution / Malicious File",
        "T1543.003": "Windows Service",
        "T1547":     "Boot or Logon Autostart Execution",
        "T1547.001": "Registry Run Keys",
        "T1564.001": "Hidden Files and Directories",
        "T1112":     "Modify Registry",
    }

    def _technique_label(tid: str) -> str:
        name = TECHNIQUE_NAMES.get(tid, "")
        return f"{tid} ({name})" if name else tid

    # ── Build technique → evidence mapping ───────────────────────────────────
    # Maps technique_id → list of brief evidence strings
    technique_evidence: dict[str, list[str]] = {}

    def _add_evidence(tid: str, evidence: str) -> None:
        if not tid:
            return
        technique_evidence.setdefault(tid, [])
        if evidence not in technique_evidence[tid]:
            technique_evidence[tid].append(evidence)

    for inj in injections:
        ctx  = inj.get("context") or {}
        proc = ctx.get("process", "unknown")
        pid  = ctx.get("pid", "?")
        prot = ctx.get("protection", "?")
        _add_evidence("T1055", f"PAGE_EXECUTE_READWRITE anomaly in {proc} (PID {pid})")
        if prot not in ("PAGE_EXECUTE_READWRITE", "?"):
            _add_evidence("T1055", f"Protection={prot} in {proc} (PID {pid})")

    for entry in persist_entries:
        ctx = entry.get("context") or {}
        tid = ctx.get("technique", "")
        val = entry.get("value", "")
        typ = str(entry.get("type", "")).lower()
        if typ == "process":
            bin_path = ctx.get("binary_path", "")
            desc = f"Service '{val}'"
            if bin_path:
                desc += f" → {bin_path[:60]}"
            _add_evidence(tid, desc)
        elif typ == "filepath":
            _add_evidence(tid, f"Obfuscated path: {val[:60]}")
        else:
            _add_evidence(tid, f"{typ}: {val[:60]}")

    for h in hash_iocs + susp_hashes:
        ctx = h.get("context") or {}
        tid = ctx.get("technique", "T1204")
        src = h.get("source_plugin", "unknown")
        _add_evidence(tid, f"{str(h.get('type','hash')).upper()} in {src}")

    all_techniques = sorted({
        str((e.get("context") or {}).get("technique"))
        for e in (malicious + suspicious)
        if (e.get("context") or {}).get("technique")
    })

    # ── Per-process injection summary ─────────────────────────────────────────
    process_counts: dict[str, int] = {}
    process_pid: dict[str, str] = {}
    for inj in injections:
        ctx  = inj.get("context") or {}
        proc = str(ctx.get("process", "unknown"))
        pid  = str(ctx.get("pid", "?"))
        process_counts[proc] = process_counts.get(proc, 0) + 1
        process_pid[proc] = pid
    top_processes = sorted(process_counts.items(), key=lambda kv: kv[1], reverse=True)

    # ── Artifact-type label helper ─────────────────────────────────────────────
    def _artifact_type(entry: dict) -> str:
        typ = str(entry.get("type", "")).lower()
        ctx = entry.get("context") or {}
        if typ == "process":
            svc = ctx.get("service_name", "")
            return "Service" if svc else "Process"
        if typ == "filepath":
            return "Filepath"
        if typ in HASH_TYPES:
            return typ.upper()
        return typ.title()

    # ─────────────────────────────────────────────────────────────────────────
    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines.append("# Forensic Incident Report")
    lines.append("")
    lines.append(f"- **Source validation file:** {source_report_path}")
    lines.append(f"- **Generated at:** {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")

    # ── 1. Executive Summary ──────────────────────────────────────────────────
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"- **Malicious IOCs:** {summary.get('malicious', len(malicious))}")
    lines.append(f"- **Suspicious IOCs:** {summary.get('suspicious', len(suspicious))}")
    lines.append(f"- **Benign IOCs:** {summary.get('benign', len(benign))}")
    lines.append(f"- **Process injection regions:** {len(injections)}"
                 + (f" across {len(process_counts)} process(es)" if process_counts else ""))
    lines.append(f"- **Malicious hashes confirmed:** {len(hash_iocs)}")
    lines.append(f"- **Suspicious hashes:** {len(susp_hashes)}")
    lines.append(f"- **Persistence/evasion artifacts:** {len(persist_entries)}")
    if malware_assessment:
        lines.append(f"- **Likely malware type:** {malware_assessment.get('likely_type', 'undetermined')}")
        lines.append(f"- **Compromise level:** {malware_assessment.get('compromise_level', 'unknown')}")
    lines.append("")

    # ── 2. Host/System Profile ────────────────────────────────────────────────
    lines.append("## 2. Host/System Profile")
    lines.append("")
    lines.append(f"- OS type: {system_profile.get('os_type', 'unknown')}")
    lines.append(f"- OS version: {system_profile.get('version', 'unknown')}")
    lines.append(f"- OS build: {system_profile.get('build', 'unknown')}")
    lines.append(f"- Processor architecture: {system_profile.get('processor_arch', 'unknown')}")
    lines.append("")

    # ── 3. Malware Actions Observed ───────────────────────────────────────────
    lines.append("## 3. Malware Actions Observed")
    lines.append("")

    # ── 3.1 Process Injection ─────────────────────────────────────────────────
    lines.append("### 3.1 Process Injection Actions (T1055)")
    lines.append("")
    if top_processes:
        summary_parts = [f"**{proc}** was targeted {count} time(s) (PID {process_pid[proc]})"
                         for proc, count in top_processes]
        lines.append("**Summary:** " + "; ".join(summary_parts) + ".")
        lines.append("")
    if injections:
        lines.append("| # | Target Process | PID | PPID | Start VPN | Region Size | Memory Protection | Header / Hex (first 16 B) | MZ? | Source Plugin |")
        lines.append("|---|---------------|-----|------|-----------|-------------|-------------------|--------------------------|-----|---------------|")
        for idx, inj in enumerate(injections, 1):
            ctx  = inj.get("context") or {}
            proc = _escape_md(ctx.get("process", "unknown"))
            pid  = _escape_md(ctx.get("pid", "?"))
            ppid = _escape_md(ctx.get("ppid", "—") if ctx.get("ppid") is not None else "—")
            vpn  = _escape_md(ctx.get("start_vpn", "?"))
            prot = _escape_md(ctx.get("protection", "?"))
            src  = _escape_md(inj.get("source_plugin", "?"))
            has_mz = ctx.get("has_pe_header", False)
            mz_flag = "**MZ ✓**" if has_mz else "—"

            # Region size — bytes already computed in extractor; format nicely
            raw_size = ctx.get("region_size", 0)
            try:
                sz = int(raw_size)
                if sz >= 1024 * 1024:
                    size_str = f"{sz / (1024*1024):.2f} MB"
                elif sz >= 1024:
                    size_str = f"{sz / 1024:.1f} KB"
                elif sz > 0:
                    size_str = f"{sz} B"
                else:
                    size_str = "—"
            except (ValueError, TypeError):
                size_str = "—"

            # Header hex — already trimmed to 16 bytes in extractor
            header_hex = ctx.get("header_hex", "")
            if header_hex:
                # Bold it if MZ header present
                hex_cell = f"**{_escape_md(header_hex)}**" if has_mz else f"`{_escape_md(header_hex)}`"
            else:
                hex_cell = "—"

            lines.append(f"| {idx} | {proc} | {pid} | {ppid} | {vpn} | {size_str} | {prot} | {hex_cell} | {mz_flag} | {src} |")
    else:
        lines.append("_No process injection evidence found._")
    lines.append("")

    # ── 3.2 Persistence & Suspicious Actions ─────────────────────────────────
    lines.append("### 3.2 Persistence & Suspicious Actions")
    lines.append("")
    if persist_entries:
        lines.append("| # | Artifact Type | Value | Binary / Path | Associated Technique | Detecting Plugin |")
        lines.append("|---|--------------|-------|--------------|----------------------|-----------------|")
        for idx, entry in enumerate(persist_entries, 1):
            ctx       = entry.get("context") or {}
            art_type  = _escape_md(_artifact_type(entry))
            value     = _escape_md(entry.get("value", ""))
            bin_path  = _escape_md(
                ctx.get("binary_path", "")
                or ctx.get("data", "")
                or "—"
            )
            tid       = ctx.get("technique", "")
            technique = _escape_md(_technique_label(tid) if tid else "—")
            plugin    = _escape_md(entry.get("source_plugin", "unknown"))
            lines.append(f"| {idx} | {art_type} | {value} | {bin_path} | {technique} | {plugin} |")
    else:
        lines.append("_No persistence or evasion artifacts found._")
    lines.append("")

    # ── 3.3 Confirmed Malicious Hashes ───────────────────────────────────────
    lines.append("### 3.3 Confirmed Malicious Hashes")
    lines.append("")
    HASH_DISPLAY_LIMIT = 5
    all_hashes = hash_iocs  # only malicious-verdict hashes here
    if all_hashes:
        display_hashes = all_hashes[:HASH_DISPLAY_LIMIT]
        lines.append("| # | Hash Type | Value | Source Plugin |")
        lines.append("|---|----------|-------|--------------|")
        for idx, h in enumerate(display_hashes, 1):
            ctx = h.get("context") or {}
            htype  = _escape_md(str(h.get("type", "hash")).upper())
            value  = _escape_md(h.get("value", ""))
            plugin = _escape_md(h.get("source_plugin", "unknown"))
            lines.append(f"| {idx} | {htype} | `{value}` | {plugin} |")
        if len(all_hashes) > HASH_DISPLAY_LIMIT:
            remaining = len(all_hashes) - HASH_DISPLAY_LIMIT
            lines.append("")
            lines.append(
                f"*{len(all_hashes)} total hashes confirmed malicious. "
                f"Showing first {HASH_DISPLAY_LIMIT}; "
                f"{remaining} additional hash(es) omitted. See raw JSON for full list.*"
            )
    else:
        lines.append("_No malicious hashes confirmed._")
    lines.append("")

    # ── 3.4 Suspicious Hashes (if any) ───────────────────────────────────────
    if susp_hashes:
        lines.append("### 3.4 Suspicious Hashes (Unconfirmed)")
        lines.append("")
        lines.append("| # | Hash Type | Value | Source Plugin |")
        lines.append("|---|----------|-------|--------------|")
        display = susp_hashes[:HASH_DISPLAY_LIMIT]
        for idx, h in enumerate(display, 1):
            htype  = _escape_md(str(h.get("type", "hash")).upper())
            value  = _escape_md(h.get("value", ""))
            plugin = _escape_md(h.get("source_plugin", "unknown"))
            lines.append(f"| {idx} | {htype} | `{value}` | {plugin} |")
        if len(susp_hashes) > HASH_DISPLAY_LIMIT:
            lines.append("")
            lines.append(
                f"*{len(susp_hashes)} total suspicious hashes. "
                f"Showing first {HASH_DISPLAY_LIMIT}. See raw JSON for full list.*"
            )
        lines.append("")

    # ── 4. MITRE ATT&CK Mapping ───────────────────────────────────────────────
    lines.append("## 4. MITRE ATT&CK Techniques Observed")
    lines.append("")
    if all_techniques:
        for tid in all_techniques:
            label    = _technique_label(tid)
            evidence = technique_evidence.get(tid, [])
            # Deduplicate and trim evidence to 3 examples max
            evidence_str = "; ".join(evidence[:3])
            if evidence:
                lines.append(f"- **{label}:** Evidenced by {evidence_str}.")
            else:
                lines.append(f"- **{label}**")
    else:
        lines.append("- None explicitly tagged in IOC context")
    lines.append("")

    # ── 5. Conclusion ─────────────────────────────────────────────────────────
    lines.append("## 5. Conclusion")
    lines.append("")
    # Dynamic conclusion based on actual findings
    parts = []
    if injections:
        primary_proc = top_processes[0][0] if top_processes else "unknown"
        primary_cnt  = top_processes[0][1] if top_processes else 0
        parts.append(
            f"**{primary_cnt} PAGE_EXECUTE_READWRITE memory injection region(s)** detected "
            f"in `{primary_proc}` and {len(process_counts) - 1} other process(es) — "
            f"consistent with reflective DLL injection or shellcode staging (T1055)."
        )
    if hash_iocs:
        parts.append(
            f"**{len(hash_iocs)} malicious hash(es)** confirmed by local scoring "
            f"from `{hash_iocs[0].get('source_plugin', 'filescan')}` and related modules."
        )
    if persist_entries:
        svc_entries = [e for e in persist_entries if _artifact_type(e) == "Service"]
        if svc_entries:
            svc_names = ", ".join(f"`{e.get('value','?')}`" for e in svc_entries[:3])
            parts.append(
                f"**Persistence via Windows service(s)** ({svc_names}) detected — "
                f"review binary paths for tampering (T1543.003)."
            )
    if not parts:
        parts.append("No significant compromise indicators were found in this analysis.")

    lines.append(" ".join(parts))
    lines.append("")
    lines.append("**Recommended actions:**")
    if injections:
        pids = sorted({str((i.get("context") or {}).get("pid", "?")) for i in injections})
        lines.append(f"1. Dump memory of PID(s) {', '.join(pids)} for deeper analysis.")
    if hash_iocs:
        lines.append(f"2. Submit top hashes to VirusTotal for external reputation check.")
    if persist_entries:
        lines.append(f"3. Review and disable suspicious services listed in Section 3.2.")
    lines.append("")

    return "\n".join(lines)


def _write_forensic_report(validation_report: dict, source_report_path: str) -> str:
    reports_dir = Path(settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%dT%H%M%SZ")
    out_path = reports_dir / f"forensic_incident_report_{ts}.md"
    out_path.write_text(
        _build_forensic_markdown(validation_report, source_report_path),
        encoding="utf-8",
    )
    return str(out_path)


async def _extract_iocs_from_results(
    ctx: Context,
    plugin_results: dict,
    os_type: str,
    result_id: str | None = None,
    return_iocs: bool = False,
    include_preview: bool = False,
) -> dict:
    plugin_results = plugin_results or {}
    source_system_profile = (
        plugin_results.get("_meta", {}).get("os_profile")
        if isinstance(plugin_results.get("_meta"), dict)
        else None
    ) or {"os_type": os_type}

    network_data = plugin_results.get("network_data", {})
    host_data = plugin_results.get("host_data", {})

    if not network_data and not host_data:
        await ctx.warning(
            f"Both network_data and host_data are empty. "
            f"Keys received: {list(plugin_results.keys())}. "
            "Pass the full run_plugins output directly."
        )
        return {
            "network_iocs": [],
            "host_iocs": [],
            "summary": {
                "total": 0,
                "network_count": 0,
                "host_count": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "warning": "No plugin data — pass full run_plugins output",
        }

    await ctx.info(
        f"Processing {len(network_data)} network plugins + {len(host_data)} host plugins"
    )

    pipeline = ExtractionPipeline(os_type)

    # ExtractionPipeline expects a flat plugin map, so merge both categories first.
    merged_plugin_data = {}
    merged_plugin_data.update(network_data)
    merged_plugin_data.update(host_data)

    all_iocs = await pipeline.extract(merged_plugin_data)
    network_iocs = [ioc for ioc in all_iocs if getattr(ioc, "category", "host") == "network"]
    host_iocs = [ioc for ioc in all_iocs if getattr(ioc, "category", "host") != "network"]
    high = [i for i in all_iocs if i.confidence >= 0.85]
    medium = [i for i in all_iocs if 0.65 <= i.confidence < 0.85]
    low = [i for i in all_iocs if i.confidence < 0.65]

    await ctx.info(
        f"Network IOCs: {len(network_iocs)} | Host IOCs: {len(host_iocs)} | "
        f"high={len(high)}, medium={len(medium)}, low={len(low)}"
    )

    if not all_iocs:
        await ctx.warning(
            "Zero IOCs extracted. Possible causes: "
            "(1) Plugin results empty, "
            "(2) os_type mismatch, "
            "(3) all filtered by whitelist. "
            f"Network plugins: {list(network_data.keys())} | "
            f"Host plugins: {list(host_data.keys())}"
        )

    def _serialize(iocs):
        return [ioc.to_dict() for ioc in sorted(iocs, key=lambda x: -x.confidence)]

    def _top_counts(items, key_fn, limit=5):
        counts = {}
        for item in items:
            key = key_fn(item)
            counts[key] = counts.get(key, 0) + 1
        return [
            {"name": name, "count": count}
            for name, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        ]

    from src.core.ioc_extractor import group_iocs_by_process
    process_groups, unattributed = group_iocs_by_process(all_iocs)

    full_output = {
        "network_iocs": _serialize(network_iocs),
        "host_iocs": _serialize(host_iocs),
        "by_process": [g.to_dict() for g in process_groups],
        "unattributed_count": len(unattributed),
        "result_id": result_id,
        "system_profile": source_system_profile,
        "summary": {
            "total": len(all_iocs),
            "network_count": len(network_iocs),
            "host_count": len(host_iocs),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "process_groups": len(process_groups),
            "unattributed": len(unattributed),
        },
    }

    report_path = write_json_report(
        prefix="ioc_extract",
        payload=full_output,
        result_id=result_id,
    )

    compact = {
        "result_id": result_id,
        "report_path": report_path,
        "system_profile": source_system_profile,
        "summary": full_output["summary"],
        "by_process": [g.to_dict() for g in process_groups[:10]],  # top-10 in compact response
        "stats": {
            "top_network_types": _top_counts(network_iocs, lambda i: i.ioc_type),
            "top_host_types": _top_counts(host_iocs, lambda i: i.ioc_type),
            "top_network_sources": _top_counts(network_iocs, lambda i: i.source_plugin),
            "top_host_sources": _top_counts(host_iocs, lambda i: i.source_plugin),
        },
        "next_step": "Use ioc_validate_from_report(report_path=<path>)",
    }
    if include_preview:
        compact["preview"] = {
            "network": _serialize(network_iocs)[:5],
            "host": _serialize(host_iocs)[:5],
        }
    if return_iocs:
        compact["network_iocs"] = full_output["network_iocs"]
        compact["host_iocs"] = full_output["host_iocs"]
    return compact


async def _validate_ioc_entries(
    ctx: Context,
    network_iocs: list,
    host_iocs: list,
    os_type: str = "windows",
    include_findings: bool = False,
    source_system_profile: dict | None = None,
) -> dict:
    all_iocs = network_iocs + host_iocs
    if not all_iocs:
        return {
            "malicious": [],
            "suspicious": [],
            "benign": [],
            "summary": {
                "malicious": 0,
                "suspicious": 0,
                "benign": 0,
                "vt_checked": 0,
            },
        }

    await ctx.info(
        f"Validating {len(all_iocs)} IOCs "
        f"({len(network_iocs)} network + {len(host_iocs)} host)..."
    )

    from src.models.ioc import IOC

    ioc_objects: list[IOC] = []
    parse_errors = 0
    for entry in all_iocs:
        try:
            ioc_objects.append(
                IOC(
                    ioc_type=entry.get("type") or entry.get("ioc_type", "unknown"),
                    value=entry["value"],
                    confidence=entry.get("confidence", 0.5),
                    source_plugin=entry.get("source_plugin") or entry.get("source", "unknown"),
                    context=entry.get("context", {}),
                    extracted_at=datetime.now(),
                )
            )
        except Exception:
            parse_errors += 1
            continue

    if not ioc_objects:
        return {
            "malicious": [],
            "suspicious": [],
            "benign": [],
            "summary": {
                "malicious": 0,
                "suspicious": 0,
                "benign": 0,
                "vt_checked": 0,
                "input_count": len(all_iocs),
                "parsed_count": 0,
                "parse_errors": parse_errors,
                "status": "degraded",
            },
            "warning": "Validation skipped because all IOC entries failed parsing",
        }

    validator = ValidationPipeline(
        config={
            "enable_threat_intel": settings.enable_threat_intel,
            "vt_api_key": settings.vt_api_key,
            "abuse_api_key": settings.abuseipdb_key,
        }
    )
    try:
        validated = await validator.validate_batch(ioc_objects, os_type=os_type)
    except Exception as e:
        return {
            "malicious": [],
            "suspicious": [],
            "benign": [],
            "summary": {
                "malicious": 0,
                "suspicious": 0,
                "benign": 0,
                "vt_checked": 0,
                "input_count": len(all_iocs),
                "parsed_count": len(ioc_objects),
                "parse_errors": parse_errors,
                "status": "error",
            },
            "error": str(e),
        }
    finally:
        await validator.close()

    malicious = [v for v in validated if v.verdict == "malicious"]
    suspicious = [v for v in validated if v.verdict == "suspicious"]
    benign = [v for v in validated if v.verdict == "benign"]
    vt_checked = sum(1 for v in validated if getattr(v, "vt_checked", False))

    await ctx.info(
        f"Results: {len(malicious)} malicious, "
        f"{len(suspicious)} suspicious, {len(benign)} benign | "
        f"VT checked: {vt_checked}"
    )

    def _fmt(validated_list):
        return [
            {
                "type": v.ioc.ioc_type,
                "value": v.ioc.value,
                "verdict": v.verdict,
                "confidence": v.final_confidence,
                "reason": v.reason or "",
                "source_plugin": v.ioc.source_plugin,
                "context": v.ioc.context,
            }
            for v in sorted(validated_list, key=lambda x: -x.final_confidence)
        ]

    from src.core.ioc_extractor import group_iocs_by_process
    process_groups, unattributed = group_iocs_by_process([v.ioc for v in validated])

    full_output = {
        "malicious": _fmt(malicious),
        "suspicious": _fmt(suspicious),
        "benign": _fmt(benign),
        "by_process": [g.to_dict() for g in process_groups],
        "unattributed_count": len(unattributed),
        "summary": {
            "malicious": len(malicious),
            "suspicious": len(suspicious),
            "benign": len(benign),
            "vt_checked": vt_checked,
            "input_count": len(all_iocs),
            "parsed_count": len(ioc_objects),
            "parse_errors": parse_errors,
            "validated_count": len(validated),
            "process_groups": len(process_groups),
            "unattributed": len(unattributed),
            "status": "ok" if validated else "degraded",
        },
        "warning": (
            "Validation pipeline produced no classified output" if not validated else ""
        ),
    }

    full_output.update(
        _build_compromise_assessment(
            os_type=os_type,
            malicious_entries=full_output["malicious"],
            suspicious_entries=full_output["suspicious"],
            benign_entries=full_output["benign"],
            source_system_profile=source_system_profile,
        )
    )

    report_path = write_json_report(prefix="ioc_validate", payload=full_output)
    compact = {
        "report_path": report_path,
        "summary": full_output["summary"],
        "system_profile": full_output["system_profile"],
        "malware_assessment": full_output["malware_assessment"],
        "by_process": [g.to_dict() for g in process_groups[:10]],  # top-10 in compact response
    }
    if include_findings:
        compact.update(
            {
                "malicious": full_output["malicious"],
                "suspicious": full_output["suspicious"],
                "benign": full_output["benign"],
                "warning": full_output["warning"],
            }
        )
    return compact


def register_validation_tools(mcp: FastMCP):

    @mcp.tool(
        name="ioc_extract",
                description="Extract phase 4 IOCs from run_plugins output or a stored result_id and return summary/report-path by default.",
    )
    async def ioc_extract(
        ctx: Context,
        plugin_results: dict | None = None,
        result_id: str | None = None,
        os_type: str = "windows",
        return_iocs: bool = False,
        include_preview: bool = False,
    ) -> dict:
        """
        Parameters
        ----------
        plugin_results : dict | None
            Full output from run_plugins. Must contain "network_data" and "host_data" keys.
        result_id : str | None
            ID returned by run_plugins. If provided, plugin_results is optional.
        os_type : str
            "windows" or "linux".
        """
        await ctx.info("Extracting IOCs from plugin results")

        if result_id and not plugin_results:
            plugin_results = get_stored_plugin_results(result_id)
            if not plugin_results:
                return {
                    "network_iocs": [],
                    "host_iocs": [],
                    "summary": {
                        "total": 0,
                        "network_count": 0,
                        "host_count": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    },
                    "warning": f"Unknown result_id: {result_id}",
                }

        return await _extract_iocs_from_results(
            ctx=ctx,
            plugin_results=plugin_results,
            os_type=os_type,
            result_id=result_id,
            return_iocs=return_iocs,
            include_preview=include_preview,
        )

    @mcp.tool(
        name="ioc_extract_from_store",
        description="Extract IOCs from stored run_plugins payloads (latest or by result_id) to avoid large MCP transfers.",
    )
    async def ioc_extract_from_store(
        ctx: Context,
        result_id: str | None = None,
        os_type: str = "windows",
        return_iocs: bool = False,
        include_preview: bool = False,
    ) -> dict:
        await ctx.info("Extracting IOCs from stored plugin results")

        resolved_result_id = result_id
        plugin_results = None

        if resolved_result_id:
            plugin_results = get_stored_plugin_results(resolved_result_id)
            if not plugin_results:
                return {
                    "network_iocs": [],
                    "host_iocs": [],
                    "summary": {
                        "total": 0,
                        "network_count": 0,
                        "host_count": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    },
                    "warning": f"Unknown result_id: {resolved_result_id}",
                }
        else:
            latest = get_latest_stored_plugin_results()
            if not latest:
                return {
                    "network_iocs": [],
                    "host_iocs": [],
                    "summary": {
                        "total": 0,
                        "network_count": 0,
                        "host_count": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    },
                    "warning": "No stored run_plugins payload found",
                }
            resolved_result_id, plugin_results = latest

        # Auto-detect os_type from stored _meta if caller left the default.
        # run_plugins always writes _meta.os_type so we can trust it.
        stored_os = (plugin_results.get("_meta") or {}).get("os_type")
        if stored_os and os_type == "windows" and stored_os != "windows":
            await ctx.info(
                f"os_type auto-corrected from default 'windows' to '{stored_os}' "
                f"based on stored _meta for result_id={resolved_result_id}"
            )
            os_type = stored_os

        return await _extract_iocs_from_results(
            ctx=ctx,
            plugin_results=plugin_results,
            os_type=os_type,
            result_id=resolved_result_id,
            return_iocs=return_iocs,
            include_preview=include_preview,
        )

    @mcp.tool(
        name="ioc_validate",
                description="Validate phase 5 IOC arrays via whitelist and optional threat-intel checks, returning compact assessment output.",
    )
    async def ioc_validate(
        ctx: Context,
        network_iocs: list,
        host_iocs: list,
        os_type: str = "windows",
        include_findings: bool = False,
        source_system_profile: dict | None = None,
    ) -> dict:
        """
        Parameters
        ----------
        network_iocs : list
            network_iocs from ioc_extract output.
        host_iocs : list
            host_iocs from ioc_extract output.
        os_type : str
            "windows" or "linux".
        """
        return await _validate_ioc_entries(
            ctx=ctx,
            network_iocs=network_iocs,
            host_iocs=host_iocs,
            os_type=os_type,
            include_findings=include_findings,
            source_system_profile=source_system_profile,
        )

    @mcp.tool(
        name="ioc_validate_from_report",
        description="Validate IOCs from an extraction report file and return summary plus path to full classified findings.",
    )
    async def ioc_validate_from_report(
        ctx: Context,
        report_path: str,
        os_type: str = "windows",
        include_findings: bool = False,
    ) -> dict:
        report = load_json_report(report_path)
        network_iocs = report.get("network_iocs", [])
        host_iocs = report.get("host_iocs", [])
        return await _validate_ioc_entries(
            ctx=ctx,
            network_iocs=network_iocs,
            host_iocs=host_iocs,
            os_type=os_type,
            include_findings=include_findings,
            source_system_profile=report.get("system_profile", {}),
        )

    @mcp.tool(
        name="forensic_report_from_validation",
        description="Generate a forensic markdown incident report from a validation JSON report path.",
    )
    async def forensic_report_from_validation(ctx: Context, report_path: str) -> dict:
        report = load_json_report(report_path)
        await ctx.info(f"Generating forensic report from {report_path}")
        out_path = _write_forensic_report(report, report_path)

        malicious = report.get("malicious", [])
        suspicious = report.get("suspicious", [])
        benign = report.get("benign", [])
        injections = [m for m in malicious if str(m.get("type", "")).lower() == "injection"]

        return {
            "source_report_path": report_path,
            "forensic_report_path": out_path,
            "summary": {
                "malicious": len(malicious),
                "suspicious": len(suspicious),
                "benign": len(benign),
                "injection_actions": len(injections),
            },
        }
