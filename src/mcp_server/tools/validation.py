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
    malicious = validation_report.get("malicious", [])
    suspicious = validation_report.get("suspicious", [])
    benign = validation_report.get("benign", [])
    summary = validation_report.get("summary", {})
    system_profile = validation_report.get("system_profile", {})
    malware_assessment = validation_report.get("malware_assessment", {})

    injections = [m for m in malicious if str(m.get("type", "")).lower() == "injection"]
    hash_iocs = [
        m for m in malicious if str(m.get("type", "")).lower() in {"md5", "sha1", "sha256"}
    ]

    techniques = sorted({
        str((e.get("context") or {}).get("technique"))
        for e in (malicious + suspicious)
        if (e.get("context") or {}).get("technique")
    })

    process_counts: dict[str, int] = {}
    for inj in injections:
        proc = str((inj.get("context") or {}).get("process", "unknown"))
        process_counts[proc] = process_counts.get(proc, 0) + 1
    top_processes = sorted(process_counts.items(), key=lambda kv: kv[1], reverse=True)

    lines: list[str] = []
    lines.append("# Forensic Incident Report")
    lines.append("")
    lines.append(f"- Source validation file: {source_report_path}")
    lines.append(f"- Generated at: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"- Malicious IOCs: {summary.get('malicious', len(malicious))}")
    lines.append(f"- Suspicious IOCs: {summary.get('suspicious', len(suspicious))}")
    lines.append(f"- Benign IOCs: {summary.get('benign', len(benign))}")
    lines.append(f"- Injection actions: {len(injections)}")
    lines.append(f"- Malicious hashes confirmed: {len(hash_iocs)}")
    if malware_assessment:
        lines.append(
            f"- Likely malware type: {malware_assessment.get('likely_type', 'undetermined')}"
        )
        lines.append(
            f"- Compromise level: {malware_assessment.get('compromise_level', 'unknown')}"
        )
    lines.append("")
    lines.append("## 2. Host/System Profile")
    lines.append("")
    lines.append(f"- OS type: {system_profile.get('os_type', 'unknown')}")
    lines.append(f"- OS version: {system_profile.get('version', 'unknown')}")
    lines.append(f"- OS build: {system_profile.get('build', 'unknown')}")
    lines.append(f"- Processor architecture: {system_profile.get('processor_arch', 'unknown')}")
    lines.append("")
    lines.append("## 3. Malware Actions Observed")
    lines.append("")
    lines.append("### 3.1 Process Injection Actions (T1055)")
    lines.append("")
    lines.append("| # | Process | PID | Start VPN | Protection | Source Plugin |")
    lines.append("|---|---------|-----|-----------|------------|---------------|")
    for idx, inj in enumerate(injections, 1):
        ctx = inj.get("context") or {}
        lines.append(
            "| "
            + f"{idx} | {_escape_md(ctx.get('process', 'unknown'))}"
            + f" | {_escape_md(ctx.get('pid', 'unknown'))}"
            + f" | {_escape_md(ctx.get('start_vpn', 'unknown'))}"
            + f" | {_escape_md(ctx.get('protection', 'unknown'))}"
            + f" | {_escape_md(inj.get('source_plugin', 'unknown'))} |"
        )
    lines.append("")
    lines.append("Injection distribution by process:")
    for proc, count in top_processes:
        lines.append(f"- {proc}: {count}")
    lines.append("")
    lines.append("### 3.2 Malicious Hash Artifacts")
    lines.append("")
    lines.append("| # | Type | Value | Evidence |")
    lines.append("|---|------|-------|----------|")
    for idx, h in enumerate(hash_iocs, 1):
        lines.append(
            "| "
            + f"{idx} | {_escape_md(h.get('type', 'unknown'))}"
            + f" | {_escape_md(h.get('value', ''))}"
            + f" | {_escape_md(h.get('reason', ''))} |"
        )
    lines.append("")
    lines.append("### 3.3 Persistence and Other Suspicious Actions")
    lines.append("")
    lines.append("| # | IOC Type | Value | Technique | Source Plugin | Verdict |")
    lines.append("|---|----------|-------|-----------|---------------|---------|")
    for idx, entry in enumerate(suspicious, 1):
        ctx = entry.get("context") or {}
        lines.append(
            "| "
            + f"{idx} | {_escape_md(entry.get('type', 'unknown'))}"
            + f" | {_escape_md(entry.get('value', ''))}"
            + f" | {_escape_md(ctx.get('technique', ''))}"
            + f" | {_escape_md(entry.get('source_plugin', 'unknown'))}"
            + f" | {_escape_md(entry.get('verdict', 'suspicious'))} |"
        )
    lines.append("")
    lines.append("## 4. ATT&CK Techniques Observed")
    lines.append("")
    if techniques:
        for t in techniques:
            lines.append(f"- {t}")
    else:
        lines.append("- None explicitly tagged in IOC context")
    lines.append("")
    lines.append("## 5. Conclusion")
    lines.append("")
    lines.append(
        "The evidence indicates host compromise with repeated in-memory injection activity and"
        " confirmed malicious artifact(s). Review suspicious persistence actions to identify"
        " active footholds and startup mechanisms."
    )
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
