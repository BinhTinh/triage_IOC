from typing import List, Optional
from datetime import datetime

from fastmcp import FastMCP, Context

from src.core.ioc_extractor import ExtractionPipeline
from src.core.validator import ValidationPipeline
from src.core.mitre_mapper import MITREMapper
from src.core.report_generator import ReportGenerator
from src.models.ioc import IOC, ValidatedIOC
from src.config.settings import settings
from src.mcp_server.tools.triage import get_case, update_case_status


_pipeline_cache: dict = {}


async def _get_pipeline(config: dict) -> ValidationPipeline:
    key = f"{config.get('vt_api_key', '')}:{config.get('abuse_api_key', '')}:{config.get('deepseek_api_key', '')}"
    if key not in _pipeline_cache:
        import redis.asyncio as aioredis, os
        redis_client = await aioredis.from_url(
            os.getenv("REDIS_URL", "redis://redis:6379"), decode_responses=True
        )
        ValidationPipeline.set_redis_client(redis_client)
        _pipeline_cache[key] = ValidationPipeline(config, redis_client=redis_client)
    return _pipeline_cache[key]


def _rebuild_validated_iocs(validated_iocs: dict, verdicts: list) -> List[ValidatedIOC]:
    iocs = []
    for verdict in verdicts:
        for ioc_data in validated_iocs.get(verdict, []):
            if not isinstance(ioc_data, dict):
                continue
            iocs.append(ValidatedIOC(
                ioc=IOC(
                    ioc_type=ioc_data.get("type", "unknown"),
                    value=ioc_data.get("value", ""),
                    confidence=ioc_data.get("confidence", 0.5),
                    source_plugin=ioc_data.get("source", "unknown"),
                    context=ioc_data.get("context", {}),
                    extracted_at=datetime.now(),
                ),
                final_confidence=ioc_data.get("confidence", 0.5),
                verdict=verdict,
                validation_results=[],
                reason=ioc_data.get("reason", ""),
            ))
    return iocs


def register_validation_tools(mcp: FastMCP):

    @mcp.tool(
        name="ioc_extract",
        description="""
Extract Indicators of Compromise from Volatility3 plugin output using a two-layer strategy.

## EXTRACTION STRATEGY
Layer 1 — Regex broad scan (IOCExtractor):
  Scans raw JSON text of plugin output using patterns for:
  IPv4, IPv6, domain, MD5, SHA256, Windows file path, registry keys.
  High recall — intentionally over-extracts, false positives removed in ioc_validate.
  Active plugins for regex scan: cmdline, bash, malfind, netscan, netstat,
  dlllist, handles, mftparser, filescan, psscan.

Layer 2 — Context-aware analysis (ContextAwareExtractor):
  Analyzes structured plugin data with OS-specific rules:
  • Process relationships: detects suspicious parent→child (winword→cmd, nginx→bash)
  • Command line: detects encoded PowerShell (-enc), certutil download, regsvr32 bypass
  • Malfind: RWX memory regions with MZ header = confidence 0.9, without = 0.7
  • Network: flags unexpected connections from notepad/calc, C2 ports (4444, 1337, 31337)
  • Registry (Windows only): Run keys, LSA, AppInit_DLLs, Defender exclusions, Winlogon, IFEO

## INPUT FORMAT
Pass the FULL batch_plugins output dict — the "data" key is extracted internally:
  ioc_extract(plugin_results=batch_plugins_result, os_type="windows")

Do NOT pass plugin_results["data"] directly — the tool handles that.

## CONFIDENCE SCORING
  ≥ 0.7  → high    (context-confirmed: process relationship, RWX+MZ, suspicious cmdline)
  0.4–0.7 → medium  (regex match in relevant plugin, network connection)
  < 0.4  → low     (regex match in low-confidence plugin context)

## IOC TYPES EXTRACTED
Windows: ip, domain, md5, sha256, filepath, registry, process, injection, command
         registry subtypes: registry_persistence, registry_defense_evasion,
                            registry_credential_access, registry_execution
Linux:   ip, domain, md5, sha256, process, injection, command

## OUTPUT SCHEMA
{
  "total": 47,
  "by_confidence": {"high": 8, "medium": 21, "low": 18},
  "by_type": {"ip": 5, "domain": 3, "injection": 2, "process": 4, ...},
  "iocs": [                             // sorted high→low confidence
    {
      "type": "injection",
      "value": "PID 1234 @ 0x7f000000",
      "confidence": 0.9,
      "source": "windows.malware.malfind.Malfind",
      "context": {"technique": "T1055", "has_pe_header": true, ...}
    }
  ],
  "registry_findings": 3,
  "next_action": "Call ioc_validate to verify against threat intelligence"
}

## NEXT STEP
→ ioc_validate(result["iocs"], os_type)
→ Focus validation on high-confidence IOCs first to conserve API quota
""",
    )
    async def ioc_extract(ctx: Context, plugin_results: dict, os_type: str = "windows") -> dict:
        """
        Parameters
        ----------
        plugin_results : dict
            Full output from batch_plugins. Must contain "data" key.
            Pass the entire batch_plugins result, not a subset.

        os_type : str
            "windows" or "linux".
            Controls which context rules and registry analyzers are applied.
            Must match the os_type from detect_os — mismatches produce 0 IOCs.
        """
        await ctx.info("Extracting IOCs from plugin results")

        raw_data = plugin_results.get("data", {})
        if not raw_data:
            await ctx.warning(
                f"plugin_results['data'] is empty. "
                f"Keys received: {list(plugin_results.keys())}. "
                "Pass the full batch_plugins output directly."
            )
            return {
                "total": 0,
                "by_confidence": {"high": 0, "medium": 0, "low": 0},
                "by_type": {},
                "iocs": [],
                "registry_findings": 0,
                "warning": "No plugin data — pass full batch_plugins output",
            }

        await ctx.info(f"Processing {len(raw_data)} plugins: {list(raw_data.keys())}")

        pipeline = ExtractionPipeline(os_type)
        iocs = await pipeline.extract(raw_data)
        await ctx.info(f"ExtractionPipeline: {len(iocs)} IOCs extracted")

        registry_iocs: list = []
        if os_type == "windows":
            registry_data: list = []
            for plugin_key, plugin_rows in raw_data.items():
                base_key = plugin_key.split("#")[0].lower()
                if any(k in base_key for k in ["registry", "hivelist", "userassist", "amcache", "printkey"]):
                    if isinstance(plugin_rows, list):
                        registry_data.extend(plugin_rows)

            if registry_data:
                await ctx.info(f"Running RegistryAnalyzer on {len(registry_data)} registry entries...")
                try:
                    from src.core.registry_analyzer import RegistryAnalyzer
                    severity_to_confidence = {"critical": 0.9, "high": 0.75, "medium": 0.6, "low": 0.45}
                    findings = RegistryAnalyzer().analyze(registry_data)
                    await ctx.info(f"RegistryAnalyzer: {len(findings)} suspicious findings")

                    for finding in findings:
                        confidence = finding.get(
                            "confidence",
                            severity_to_confidence.get(finding.get("severity", "medium"), 0.6)
                        )
                        ioc_value = (
                            f"{finding['key']}\\{finding['value']}"
                            if finding.get("value") else finding["key"]
                        )
                        registry_iocs.append(IOC(
                            ioc_type="registry",
                            value=ioc_value[:300],
                            confidence=min(confidence, 1.0),
                            source_plugin="registry_analyzer",
                            context={
                                "category": finding.get("category"),
                                "technique": finding.get("mitre"),
                                "severity": finding.get("severity"),
                                "description": finding.get("description"),
                                "reasons": finding.get("reasons", []),
                                "data": finding.get("data", "")[:100],
                                "malware_families": finding.get("malware_families", []),
                            },
                            extracted_at=datetime.now(),
                        ))

                    iocs.extend(registry_iocs)
                    await ctx.info(f"Added {len(registry_iocs)} registry IOCs")
                except Exception as e:
                    await ctx.warning(f"RegistryAnalyzer failed (non-fatal): {e}")
            else:
                await ctx.info(
                    "No registry plugin data found — add windows.registry.printkey / "
                    "windows.registry.userassist to plugin list for persistence analysis"
                )

        high   = [i for i in iocs if i.confidence >= 0.7]
        medium = [i for i in iocs if 0.4 <= i.confidence < 0.7]
        low    = [i for i in iocs if i.confidence < 0.4]

        by_type: dict = {}
        for ioc in iocs:
            by_type.setdefault(ioc.ioc_type, []).append(ioc.to_dict())

        await ctx.info(
            f"Total: {len(iocs)} IOCs "
            f"(high: {len(high)}, medium: {len(medium)}, low: {len(low)}) "
            f"| registry: {len(registry_iocs)}"
        )

        if len(iocs) == 0:
            await ctx.warning(
                "Zero IOCs extracted. Possible causes: "
                "(1) Plugin results empty, "
                "(2) All matched whitelist, "
                "(3) os_type mismatch. "
                f"Plugin sizes: { {k: len(v) if isinstance(v, list) else type(v).__name__ for k, v in raw_data.items()} }"
            )

        return {
            "total": len(iocs),
            "by_confidence": {"high": len(high), "medium": len(medium), "low": len(low)},
            "by_type": {k: len(v) for k, v in by_type.items()},
            "iocs": [ioc.to_dict() for ioc in sorted(iocs, key=lambda x: -x.confidence)],
            "registry_findings": len(registry_iocs),
            "next_action": "Call ioc_validate to verify against threat intelligence",
        }

    @mcp.tool(
        name="ioc_validate",
        description="""
Validate extracted IOCs against threat intelligence sources with multi-factor confidence scoring.

## VALIDATION PIPELINE (in order)
Step 1 — Whitelist check (instant, no API call):
  Known-safe IPs: 8.8.8.8, 8.8.4.4, 1.1.1.1
  Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
  Known-safe domains: *.microsoft.com, *.google.com, *.windows.com
  Known system processes: C:\\Windows\\System32\\svchost.exe, lsass.exe, etc.
  → If whitelisted: verdict=benign immediately, no API calls made

Step 2 — VirusTotal (IPs, domains, MD5/SHA1/SHA256 only):
  Rate limit: 4 requests/min (free tier) — 15s enforced delay between requests
  Cache TTL: 6 hours in Redis
  Threshold: score > 0.35 = malicious flag
  Skip condition: IOC confidence < 0.35 (avoids wasting API quota on low-confidence IOCs)

Step 3 — AbuseIPDB (IPv4 only):
  Confidence threshold: > 50% = malicious flag
  Cache TTL: 6 hours in Redis

Step 4 — DeepSeek (optional, if configured):
  Applied only to suspicious IOCs (score 0.4–0.7) after Steps 1-3
  Provides context-aware re-evaluation using full IOC context

## CONFIDENCE FORMULA
Without DeepSeek: confidence = VT×0.4 + AbuseIPDB×0.3 + whitelist×0.3
With DeepSeek:    confidence = DeepSeek×0.35 + VT×0.30 + AbuseIPDB×0.20 + whitelist×0.15

## VERDICT THRESHOLDS
malicious   → confidence ≥ 0.70  (block immediately, high confidence IOC)
suspicious  → confidence 0.40–0.69 (investigate, possible true positive)
benign      → confidence < 0.40   (likely safe, log for audit)

## API QUOTA MANAGEMENT
With 50 IOCs and free VT tier (4 req/min): ~12.5 minutes for full validation.
To reduce time: pass only high+medium confidence IOCs from ioc_extract.
Example: ioc_validate(iocs=[i for i in result["iocs"] if i["confidence"] >= 0.4])

## OUTPUT SCHEMA
{
  "total": 23,
  "summary": {"malicious": 5, "suspicious": 8, "benign": 10},
  "malicious": [
    {
      "type": "ip", "value": "185.220.101.45",
      "confidence": 0.87, "verdict": "malicious",
      "reason": "VT: 48/94 malicious | AbuseIPDB: 95% confidence, 1847 reports",
      "source": "windows.handles.Handles",
      "context": {"technique": "T1071", "process": "notepad.exe", "remote_port": 4444}
    }
  ],
  "suspicious": [...],
  "benign": [...],
  "next_action": "Call ioc_map_mitre to map findings to ATT&CK techniques"
}

## NEXT STEP
→ ioc_map_mitre(result)
→ Or ioc_generate_report directly if MITRE mapping is not needed
""",
    )
    async def ioc_validate(ctx: Context, iocs: List[dict], os_type: str = "windows") -> dict:
        """
        Parameters
        ----------
        iocs : list[dict]
            IOC dicts from ioc_extract["iocs"].
            Each item must have "type" and "value" keys.
            Recommended: filter to confidence >= 0.4 to conserve API quota.

        os_type : str
            "windows" or "linux".
            Used for process whitelist lookup (System32 paths vs /usr/sbin/).
        """
        if not iocs:
            await ctx.warning("ioc_validate received empty IOC list — skipping validation")
            return {
                "total": 0,
                "summary": {"malicious": 0, "suspicious": 0, "benign": 0},
                "malicious": [],
                "suspicious": [],
                "benign": [],
                "warning": "No IOCs to validate. Check ioc_extract output.",
            }

        await ctx.info(f"Validating {len(iocs)} IOCs")
        config = {
            "vt_api_key":       settings.vt_api_key,
            "abuse_api_key":    settings.abuseipdb_key,
            "use_deepseek":     getattr(settings, "use_deepseek", False),
            "deepseek_api_key": getattr(settings, "deepseek_api_key", None),
        }
        pipeline = await _get_pipeline(config)

        ioc_objects = [
            IOC(
                ioc_type=i["type"],
                value=i["value"],
                confidence=i.get("confidence", 0.5),
                source_plugin=i.get("source", "unknown"),
                context=i.get("context", {}),
                extracted_at=(
                    datetime.fromisoformat(i["extracted_at"])
                    if "extracted_at" in i else datetime.now()
                ),
            )
            for i in iocs
            if isinstance(i, dict) and "type" in i and "value" in i
        ]

        validated = await pipeline.validate_batch(ioc_objects, os_type)

        by_verdict: dict = {"malicious": [], "suspicious": [], "benign": []}
        for v in validated:
            by_verdict[v.verdict].append({
                "type": v.ioc.ioc_type,
                "value": v.ioc.value,
                "confidence": v.final_confidence,
                "verdict": v.verdict,
                "reason": v.reason,
                "source": v.ioc.source_plugin,
                "context": v.ioc.context,
            })

        await ctx.info(
            f"Validation complete — malicious: {len(by_verdict['malicious'])}, "
            f"suspicious: {len(by_verdict['suspicious'])}, benign: {len(by_verdict['benign'])}"
        )

        return {
            "total": len(validated),
            "summary": {
                "malicious": len(by_verdict["malicious"]),
                "suspicious": len(by_verdict["suspicious"]),
                "benign": len(by_verdict["benign"]),
            },
            "malicious": by_verdict["malicious"],
            "suspicious": by_verdict["suspicious"],
            "benign": by_verdict["benign"],
            "next_action": "Call ioc_map_mitre to map findings to ATT&CK techniques",
        }

    @mcp.tool(
        name="ioc_map_mitre",
        description="""
Map validated IOCs to MITRE ATT&CK techniques and tactics using context from extraction.

## MAPPING LOGIC
Primary source: ioc.context["technique"] — set by ContextAwareExtractor and RegistryAnalyzer
               during ioc_extract when a suspicious pattern is matched.
Fallback inference (when technique not set by extractor):
  ip/ipv4     → T1071   Application Layer Protocol (C&C)
  domain      → T1071.001 Web Protocols
  md5/sha256  → T1105   Ingress Tool Transfer
  malfind src → T1055   Process Injection
  cmdline src → T1059   Command and Scripting Interpreter
  registry    → T1547.001 Registry Run Keys / Startup Folder

Only malicious and suspicious IOCs are mapped — benign IOCs are excluded.

## TECHNIQUE COVERAGE (17 techniques mapped)
Defense Evasion: T1055, T1055.001, T1036, T1218.010, T1218.005, T1218.011
Execution:       T1059, T1059.001, T1059.004, T1047
Persistence:     T1547.001, T1053.005, T1543.003, T1505.003
C&C:             T1071, T1071.001, T1105

## OUTPUT SCHEMA
{
  "total_techniques": 4,
  "tactics_involved": ["Defense Evasion", "Execution", "Persistence", "Command and Control"],
  "matrix": {
    "Execution":       [{"id": "T1059.001", "name": "PowerShell", "ioc_count": 2, ...}],
    "Defense Evasion": [{"id": "T1055",     "name": "Process Injection", "ioc_count": 3, ...}],
    ...all 14 ATT&CK tactics present, empty list if no technique mapped to that tactic...
  },
  "techniques": [
    {
      "id": "T1055",
      "name": "Process Injection",
      "tactic": "Defense Evasion",
      "description": "...",
      "ioc_count": 3,
      "recommendations": ["Analyze injected memory regions", "Dump suspicious process memory", ...]
    }
  ],
  "next_action": "Call ioc_generate_report to create final report"
}

## NEXT STEP
→ ioc_generate_report(case_id, validated_iocs, mitre_mapping, plugin_results)
""",
    )
    async def ioc_map_mitre(ctx: Context, validated_iocs: dict) -> dict:
        """
        Parameters
        ----------
        validated_iocs : dict
            Full output from ioc_validate.
            Must contain "malicious" and "suspicious" keys.
            Pass the entire ioc_validate result — do not extract sub-keys.
        """
        if not isinstance(validated_iocs, dict):
            raise ValueError(
                f"validated_iocs must be a dict from ioc_validate output, "
                f"got {type(validated_iocs).__name__}"
            )

        malicious_count = len(validated_iocs.get("malicious", []))
        suspicious_count = len(validated_iocs.get("suspicious", []))

        if malicious_count == 0 and suspicious_count == 0:
            await ctx.warning("No malicious or suspicious IOCs to map — returning empty MITRE result")
            return {
                "total_techniques": 0,
                "tactics_involved": [],
                "matrix": {},
                "techniques": [],
                "warning": "No actionable IOCs found. MITRE mapping skipped.",
            }

        await ctx.info(f"Mapping {malicious_count} malicious + {suspicious_count} suspicious IOCs to ATT&CK")

        iocs = _rebuild_validated_iocs(validated_iocs, ["malicious", "suspicious"])
        mapper = MITREMapper()

        try:
            mitre_report = mapper.map_iocs(iocs)
            matrix = mapper.generate_matrix(mitre_report)
        except Exception as e:
            await ctx.warning(f"MITREMapper error: {e}")
            return {"total_techniques": 0, "tactics_involved": [], "matrix": {}, "techniques": [], "error": str(e)}

        active_tactics = {k: v for k, v in matrix.items() if v}
        await ctx.info(f"Mapped to {mitre_report.total_techniques} techniques across {len(active_tactics)} tactics")

        return {
            "total_techniques": mitre_report.total_techniques,
            "tactics_involved": list(active_tactics.keys()),
            "matrix": matrix,
            "techniques": [
                {
                    "id": tid,
                    "name": data["technique"]["name"],
                    "tactic": data["technique"]["tactic"],
                    "description": data["technique"]["description"],
                    "ioc_count": len(data["iocs"]),
                    "recommendations": data["technique"]["recommendations"],
                }
                for tid, data in mitre_report.techniques.items()
            ],
            "next_action": "Call ioc_generate_report to create final report",
        }

    @mcp.tool(
        name="ioc_generate_report",
        description="""
Generate the complete forensics report — ALWAYS call this as the final step of every analysis.
Calling with 0 IOCs is valid and produces a "clean dump" report, which is equally important to document.

## REPORT STAGES (executed in order, each non-fatal if it fails)
Stage 1  Plugin output files  → Save raw rows from each plugin as .txt files
Stage 2  IOC reconstruction   → Rebuild ValidatedIOC objects from ioc_validate output
Stage 3  Timeline             → Chronological event sequence from IOC timestamps and plugin data
Stage 4  Attack chain         → Kill chain stages: initial access → execution → persistence → C2
Stage 5  Behavior analysis    → Classify malware family (ransomware, RAT, rootkit, etc.) + confidence
Stage 6  Visualizations       → ASCII/text representations of timeline and attack chain
Stage 7  Narrative            → Human-readable incident summary combining all above
Stage 8  DeepSeek upgrade     → Re-evaluate suspicious IOCs with full context (if configured)
Stage 9  Report files         → SUMMARY.txt, SUMMARY.md, report.json, iocs.json

## OUTPUT FILES (in /app/data/reports/CASE_{id}/)
SUMMARY.txt          → Human-readable executive summary
SUMMARY.md           → Markdown version of summary
report.json          → Full structured report with all fields
iocs.json            → Flat list of all IOCs with verdicts and context
timeline.txt         → Chronological event list
attack_chain.txt     → Kill chain stage breakdown
behavior_analysis.txt → Malware family classification details
narrative.txt        → Analyst-readable incident narrative
{plugin_name}.txt    → Raw plugin output for each plugin run (one file per plugin)
visualizations.txt   → ASCII charts and graphs

## THREAT SCORING
threat_score (0–100): malicious_iocs × 10 + suspicious_iocs × 3  (capped at 100)
CRITICAL ≥ 70  |  HIGH ≥ 40  |  MEDIUM ≥ 15  |  LOW < 15

## OUTPUT SCHEMA
{
  "case_id": "CASE_WIN_20260224_a1b2c3",
  "status": "completed",
  "threat_level": "HIGH",
  "threat_score": 55,
  "summary": { ...full summary dict... },
  "classification": {
    "family": "trojan_rat",
    "confidence": 0.82,
    "behavioral_summary": "..."
  },
  "timeline_events": 24,
  "attack_stages": 4,
  "report_paths": {
    "summary_txt": "/app/data/reports/.../SUMMARY.txt",
    "iocs_json":   "/app/data/reports/.../iocs.json",
    "report_json": "/app/data/reports/.../report.json",
    "summary_md":  "/app/data/reports/.../SUMMARY.md"
  },
  "top_recommendations": ["Block IP 185.x.x.x", ...],
  "techniques_detected": [{"id": "T1055", "name": "Process Injection"}, ...]
}
""",
    )
    async def ioc_generate_report(
        ctx: Context,
        case_id: str,
        validated_iocs: dict,
        mitre_mapping: dict,
        plugin_results: dict = {},
        format: str = "both",
    ) -> dict:
        """
        Parameters
        ----------
        case_id : str
            From smart_triage["case_id"] or automated_pipeline["case_id"].

        validated_iocs : dict
            Full ioc_validate output. Pass {} if validation was skipped.

        mitre_mapping : dict
            Full ioc_map_mitre output. Pass {} if MITRE mapping was skipped.

        plugin_results : dict
            Full batch_plugins output for saving per-plugin .txt files.
            Pass {} if not available — report will be generated without raw plugin files.

        format : str
            "json"     → report.json only
            "markdown" → SUMMARY.md only
            "both"     → all formats (default, recommended)
        """
        from src.core.timeline_builder import TimelineBuilder
        from src.core.attack_chain_builder import AttackChainBuilder
        from src.core.behavior_analyzer import BehaviorAnalyzer

        case = await get_case(case_id)
        if not case:
            raise ValueError(f"Case not found: {case_id}")

        await ctx.info(f"Generating report for case {case_id}")

        generator = ReportGenerator()
        generator.create_case_directory(case)

        safe_validated = validated_iocs if isinstance(validated_iocs, dict) else {}
        safe_mitre     = mitre_mapping  if isinstance(mitre_mapping,  dict) else {}

        raw_plugin_data: dict = {}
        if plugin_results:
            results_meta    = plugin_results.get("results", {})
            plugin_data_map = plugin_results.get("data", {})

            for plugin_name, meta in results_meta.items():
                if not isinstance(meta, dict):
                    continue
                actual_rows = plugin_data_map.get(plugin_name, [])
                raw_plugin_data[plugin_name] = {
                    **meta,
                    "data": actual_rows
                }
                try:
                    generator.save_plugin_output(
                        plugin_name=plugin_name,
                        data=actual_rows if isinstance(actual_rows, list) else [],
                        success=meta.get("success", False),
                        error=meta.get("error"),
                        execution_time=meta.get("execution_time", 0.0),
                    )
                except Exception as e:
                    await ctx.warning(f"save_plugin_output [{plugin_name}]: {e}")

        await ctx.info(f"Saved {len(raw_plugin_data)} plugin output files")

        iocs = _rebuild_validated_iocs(safe_validated, ["malicious", "suspicious", "benign"])
        await ctx.info(f"IOCs: {len(iocs)} total")

        # validation.py — thay thế đoạn từ dòng ~620 đến ~660

        timeline = None
        try:
            await ctx.info("Building event timeline...")
            plugin_data_for_timeline = {
                name: {"data": plugin_results.get("data", {}).get(name, [])}
                for name in raw_plugin_data
            }
            timeline = TimelineBuilder(case.os_type).build(plugin_data_for_timeline)
            generator.save_timeline(timeline)
            case.timeline = timeline
            await ctx.info(f"Timeline: {timeline.total_events} events")
        except Exception as e:
            await ctx.warning(f"TimelineBuilder failed (non-fatal): {e}")

        attack_chain = None
        try:
            await ctx.info("Building attack chain...")
            # Fix: truyền (timeline, iocs) đúng thứ tự, không dùng await
            if timeline is not None:
                attack_chain = AttackChainBuilder().build(timeline, iocs)
            else:
                # timeline None → tạo Timeline rỗng để AttackChainBuilder không crash
                from src.models.timeline import Timeline
                empty_timeline = Timeline(events=[], start_time=None, end_time=None, total_events=0, event_types={})
                attack_chain = AttackChainBuilder().build(empty_timeline, iocs)
            generator.save_attack_chain(attack_chain)
            case.attack_chain = attack_chain
            await ctx.info(f"Attack chain: {len(attack_chain.stages)} stages")
        except Exception as e:
            await ctx.warning(f"AttackChainBuilder failed (non-fatal): {e}")

        classification = None
        try:
            await ctx.info("Running behavior analysis...")
            # Fix: truyền (timeline, attack_chain, validated_iocs) đúng thứ tự
            tl  = timeline      or Timeline(events=[], start_time=None, end_time=None, total_events=0, event_types={})
            ac  = attack_chain  or AttackChainBuilder()
            result = BehaviorAnalyzer().analyze(tl, ac, iocs)
            # .analyze() trả dict {"classification": ..., ...} — lấy ra object
            classification = result["classification"] if isinstance(result, dict) else result
            generator.save_behavior_analysis(classification)
            case.malware_classification = classification
            family = (
                classification.primary_family.value
                if hasattr(classification.primary_family, "value")
                else str(classification.primary_family)
            )
            await ctx.info(f"Classification: {family} ({classification.confidence:.0%})")
        except Exception as e:
            await ctx.warning(f"BehaviorAnalyzer failed (non-fatal): {e}")


        if timeline and attack_chain:
            try:
                generator.save_visualizations(timeline, attack_chain, iocs)
                await ctx.info("Visualizations saved")
            except Exception as e:
                await ctx.warning(f"save_visualizations failed (non-fatal): {e}")

        if timeline and attack_chain and classification:
            try:
                generator.save_narrative(timeline, attack_chain, classification, iocs)
                await ctx.info("Narrative saved")
            except Exception as e:
                await ctx.warning(f"save_narrative failed (non-fatal): {e}")

        if settings.use_deepseek and settings.deepseek_api_key:
            suspicious_iocs = [i for i in iocs if i.verdict == "suspicious"]
            if suspicious_iocs:
                try:
                    from src.core.deepseek_validator import DeepSeekValidator
                    await ctx.info(f"DeepSeek re-evaluation: {len(suspicious_iocs)} suspicious IOCs")
                    ds = DeepSeekValidator(settings.deepseek_api_key)
                    ds_fn = getattr(ds, "validate_iocs_with_context", None)
                    if ds_fn and timeline and attack_chain and classification:
                        ds_results = await ds_fn(
                            suspicious_iocs,
                            timeline=timeline,
                            attack_chain=attack_chain,
                            classification=classification,
                        )
                    else:
                        ds_results = await ds.validate_iocs(suspicious_iocs, case.os_type)
                    ds_map = {r.ioc.value: r for r in ds_results}
                    iocs = [
                        ds_map.get(i.ioc.value, i) if i.verdict == "suspicious" else i
                        for i in iocs
                    ]
                    upgraded = sum(1 for r in ds_results if r.verdict == "malicious")
                    await ctx.info(f"DeepSeek: upgraded {upgraded}/{len(suspicious_iocs)} suspicious → malicious")
                except Exception as e:
                    await ctx.warning(f"DeepSeek phase failed (non-fatal): {e}")

        report = generator.generate(case, iocs, safe_mitre)
        paths = {}

        for label, fn, args in [
            ("summary_txt", generator.save_summary,   (case, iocs, safe_mitre, raw_plugin_data)),
            ("iocs_json",   generator.save_iocs_json, (iocs,)),
        ]:
            try:
                paths[label] = fn(*args)
                await ctx.info(f"{label}: {paths[label]}")
            except Exception as e:
                await ctx.warning(f"{label} failed: {e}")

        if format in ("json", "both"):
            try:
                paths["report_json"] = generator.save_json(report)
                await ctx.info(f"report.json: {paths['report_json']}")
            except Exception as e:
                await ctx.warning(f"save_json failed: {e}")

        if format in ("markdown", "both"):
            try:
                paths["summary_md"] = generator.save_markdown(report)
                await ctx.info(f"SUMMARY.md: {paths['summary_md']}")
            except Exception as e:
                await ctx.warning(f"save_markdown failed: {e}")

        await update_case_status(case_id, "completed")

        malicious_count  = sum(1 for i in iocs if i.verdict == "malicious")
        suspicious_count = sum(1 for i in iocs if i.verdict == "suspicious")

        await ctx.info(
            f"Report complete — {report.summary['threat_level']} ({report.summary['threat_score']}/100) | "
            f"IOCs: {len(iocs)} ({malicious_count} malicious, {suspicious_count} suspicious) | "
            f"Plugins: {len(raw_plugin_data)} | "
            f"Timeline: {timeline.total_events if timeline else 'N/A'} events | "
            f"Stages: {len(attack_chain.stages) if attack_chain else 'N/A'}"
        )
        
        _techniques = safe_mitre.get("techniques", [])
        if isinstance(_techniques, dict):
            _techniques = []

        return {
            "case_id": case_id,
            "status": "completed",
            "threat_level": report.summary["threat_level"],
            "threat_score": report.summary["threat_score"],
            "summary": report.summary,
            "classification": (
                {
                    "family": (
                        classification.primary_family.value
                        if hasattr(classification.primary_family, "value")
                        else str(classification.primary_family)
                    ),
                    "confidence": classification.confidence,
                    "behavioral_summary": classification.behavioral_summary,
                }
                if classification else None
            ),
            "timeline_events": timeline.total_events if timeline else 0,
            "attack_stages": len(attack_chain.stages) if attack_chain else 0,
            "report_paths": paths,
            "top_recommendations": report.recommendations[:5],
            "techniques_detected": [
                {"id": t["id"], "name": t["name"]}
                for t in _techniques[:10]
                if isinstance(t, dict) and "id" in t and "name" in t
            ],
        }


    @mcp.tool(
        name="validate_ip",
        description="""
Validate a single IPv4 address against VirusTotal and AbuseIPDB.

## WHEN TO USE
- Manual spot-check on a specific IP found outside of normal pipeline flow
- Verifying a C2 candidate IP before adding to a block list
- Quick lookup during live incident response

## CACHING
Result cached in Redis for 6 hours per IP address.
Repeated calls within 6h return cached result instantly (no API call).

## OUTPUT SCHEMA
{
  "ip": "185.220.101.45",
  "verdict": "malicious",       // malicious | suspicious | benign
  "confidence": 0.87,           // 0.0–1.0
  "reason": "VT: 48/94 malicious | AbuseIPDB: 95% confidence, 1847 reports"
}
""",
    )
    async def validate_ip(ctx: Context, ip: str) -> dict:
        """
        Parameters
        ----------
        ip : str
            IPv4 address to validate. Example: "185.220.101.45"
        """
        config = {
            "vt_api_key":       settings.vt_api_key,
            "abuse_api_key":    settings.abuseipdb_key,
            "use_deepseek":     getattr(settings, "use_deepseek", False),
            "deepseek_api_key": getattr(settings, "deepseek_api_key", None),
        }
        pipeline = await _get_pipeline(config)
        ioc = IOC(
            ioc_type="ip", value=ip, confidence=0.5,
            source_plugin="manual", context={}, extracted_at=datetime.now()
        )
        result = await pipeline.validate_ioc(ioc)
        return {"ip": ip, "verdict": result.verdict, "confidence": result.final_confidence, "reason": result.reason}

    @mcp.tool(
        name="validate_domain",
        description="""
Validate a single domain name against VirusTotal.

## WHEN TO USE
- Manual lookup of a suspicious domain from cmdline or network output
- Verifying a DGA (domain generation algorithm) candidate
- Quick check before adding to DNS block list

## NOTE
Domains in the system whitelist (*.microsoft.com, *.google.com, etc.)
return benign instantly without API call.

## CACHING
Result cached in Redis for 6 hours per domain.

## OUTPUT SCHEMA
{
  "domain": "evil-c2.xyz",
  "verdict": "malicious",
  "confidence": 0.78,
  "reason": "VT: 32/94 malicious"
}
""",
    )
    async def validate_domain(ctx: Context, domain: str) -> dict:
        """
        Parameters
        ----------
        domain : str
            Domain name without protocol. Example: "evil-c2.xyz"
        """
        config = {
            "vt_api_key":       settings.vt_api_key,
            "abuse_api_key":    settings.abuseipdb_key,
            "use_deepseek":     getattr(settings, "use_deepseek", False),
            "deepseek_api_key": getattr(settings, "deepseek_api_key", None),
        }
        pipeline = await _get_pipeline(config)
        ioc = IOC(
            ioc_type="domain", value=domain, confidence=0.5,
            source_plugin="manual", context={}, extracted_at=datetime.now()
        )
        result = await pipeline.validate_ioc(ioc)
        return {"domain": domain, "verdict": result.verdict, "confidence": result.final_confidence, "reason": result.reason}

    @mcp.tool(
        name="validate_hash",
        description="""
Validate a file hash (MD5 / SHA1 / SHA256) against VirusTotal.

## HASH TYPE AUTO-DETECTION
32 chars → MD5
40 chars → SHA1
64 chars → SHA256
Other    → treated as MD5 (may return no result)

## WHEN TO USE
- Verifying a hash extracted from malfind, dumpfiles, or filescan output
- Checking a dropped file hash from cmdline arguments
- Manual lookup of a known malware hash for comparison

## CACHING
Result cached in Redis for 6 hours per hash value.

## OUTPUT SCHEMA
{
  "hash": "d41d8cd98f00b204e9800998ecf8427e",
  "hash_type": "md5",
  "verdict": "malicious",
  "confidence": 0.92,
  "reason": "VT: 68/72 malicious"
}
""",
    )
    async def validate_hash(ctx: Context, hash_value: str) -> dict:
        """
        Parameters
        ----------
        hash_value : str
            MD5 (32), SHA1 (40), or SHA256 (64) hex string.
            Example: "d41d8cd98f00b204e9800998ecf8427e"
        """
        config = {
            "vt_api_key":       settings.vt_api_key,
            "abuse_api_key":    settings.abuseipdb_key,
            "use_deepseek":     getattr(settings, "use_deepseek", False),
            "deepseek_api_key": getattr(settings, "deepseek_api_key", None),
        }
        pipeline = await _get_pipeline(config)
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(hash_value), "md5")
        ioc = IOC(
            ioc_type=hash_type, value=hash_value, confidence=0.5,
            source_plugin="manual", context={}, extracted_at=datetime.now()
        )
        result = await pipeline.validate_ioc(ioc)
        return {
            "hash": hash_value,
            "hash_type": hash_type,
            "verdict": result.verdict,
            "confidence": result.final_confidence,
            "reason": result.reason,
        }

    @mcp.tool(
        name="get_mitre_technique",
        description="""
Retrieve full MITRE ATT&CK technique details by technique ID.

## WHEN TO USE
- Looking up recommendations for a specific technique found in ioc_map_mitre output
- Understanding what a technique means before acting on it
- Retrieving remediation steps for a confirmed IOC

## SUPPORTED TECHNIQUE IDs
T1055, T1055.001, T1059, T1059.001, T1059.004,
T1071, T1071.001, T1105, T1547.001, T1053.005,
T1543.003, T1505.003, T1036, T1047,
T1218.010, T1218.005, T1218.011

## OUTPUT SCHEMA
{
  "id": "T1055",
  "name": "Process Injection",
  "tactic": "Defense Evasion",
  "description": "Adversaries may inject code into processes to evade defenses",
  "recommendations": [
    "Analyze injected memory regions",
    "Dump suspicious process memory",
    "Check for known injection signatures"
  ]
}
Returns {"id": ..., "name": "Unknown", "tactic": "Unknown"} for unmapped IDs.
""",
    )
    async def get_mitre_technique(ctx: Context, technique_id: str) -> dict:
        """
        Parameters
        ----------
        technique_id : str
            MITRE ATT&CK technique ID. Examples: "T1055", "T1547.001"
        """
        return MITREMapper().get_technique_info(technique_id)
