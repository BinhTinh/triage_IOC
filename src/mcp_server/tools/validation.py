from fastmcp import FastMCP, Context

from src.core.ioc_extractor import ExtractionPipeline
from src.core.validator import ValidationPipeline
from src.config.settings import settings


def register_validation_tools(mcp: FastMCP):

    @mcp.tool(
        name="ioc_extract",
        description="""
Extract IOCs from run_plugins output, split into network-based and host-based categories.

## INPUT
Pass the full run_plugins output — contains "network_data" and "host_data" keys.

## EXTRACTION STRATEGY
Layer 1 — Regex scan:
  IPv4, domain, MD5/SHA256, file paths across all plugin output text.

Layer 2 — Context-aware rules:
  • netscan/netstat  → IP + port + process correlation → C2 candidates
  • cmdline/bash     → encoded PowerShell, certutil, mshta, bitsadmin
  • malfind          → RWX+PE header=0.95, RWX only=0.80, PE only=0.75
  • ldrmodules       → DLL absent from InLoad/InInit = hidden injection (T1055)
  • filescan/handles → execution from Temp/AppData/ProgramData (T1036)
  • registry.printkey → Run/RunOnce/Services/Winlogon values (T1547)
  • amcache          → executed file hashes

## CONFIDENCE SCORING
  ≥ 0.85 → high    (strong indicator, prioritize for validation)
  0.65–0.84 → medium
  < 0.65 → low

## OUTPUT SCHEMA
{
  "network_iocs": [
    {
      "type":          "ipv4",
      "value":         "185.220.101.5",
      "confidence":    0.88,
      "source_plugin": "windows.netscan.NetScan",
      "context":       {"process": "explorer.exe", "port": 4444, "technique": "T1571"}
    }
  ],
  "host_iocs": [
    {
      "type":          "injection",
      "value":         "PID 1944 (explorer.exe) @ 0x3CD0000",
      "confidence":    0.95,
      "source_plugin": "windows.malware.malfind.Malfind",
      "context":       {"technique": "T1055", "has_pe_header": true, "is_rwx": true}
    }
  ],
  "summary": {
    "total":          26,
    "network_count":  8,
    "host_count":     18,
    "high":           6,
    "medium":         12,
    "low":            8
  }
}

## NEXT STEP
→ ioc_validate(network_iocs=result["network_iocs"], host_iocs=result["host_iocs"], os_type=<os_type>)
""",
    )
    async def ioc_extract(
        ctx: Context,
        plugin_results: dict,
        os_type: str = "windows",
    ) -> dict:
        """
        Parameters
        ----------
        plugin_results : dict
            Full output from run_plugins. Must contain "network_data" and "host_data" keys.
        os_type : str
            "windows" or "linux".
        """
        await ctx.info("Extracting IOCs from plugin results")

        network_data = plugin_results.get("network_data", {})
        host_data    = plugin_results.get("host_data", {})

        if not network_data and not host_data:
            await ctx.warning(
                f"Both network_data and host_data are empty. "
                f"Keys received: {list(plugin_results.keys())}. "
                "Pass the full run_plugins output directly."
            )
            return {
                "network_iocs": [],
                "host_iocs":    [],
                "summary": {"total": 0, "network_count": 0, "host_count": 0,
                            "high": 0, "medium": 0, "low": 0},
                "warning": "No plugin data — pass full run_plugins output",
            }

        await ctx.info(
            f"Processing {len(network_data)} network plugins + {len(host_data)} host plugins"
        )

        pipeline = ExtractionPipeline(os_type)

        network_iocs = await pipeline.extract(network_data, category="network")
        host_iocs    = await pipeline.extract(host_data,    category="host")

        all_iocs = network_iocs + host_iocs
        high     = [i for i in all_iocs if i.confidence >= 0.85]
        medium   = [i for i in all_iocs if 0.65 <= i.confidence < 0.85]
        low      = [i for i in all_iocs if i.confidence < 0.65]

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
            return [
                ioc.to_dict()
                for ioc in sorted(iocs, key=lambda x: -x.confidence)
            ]

        return {
            "network_iocs": _serialize(network_iocs),
            "host_iocs":    _serialize(host_iocs),
            "summary": {
                "total":         len(all_iocs),
                "network_count": len(network_iocs),
                "host_count":    len(host_iocs),
                "high":          len(high),
                "medium":        len(medium),
                "low":           len(low),
            },
        }

    @mcp.tool(
        name="ioc_validate",
        description="""
Validate extracted IOCs through 3 layers: whitelist → DeepSeek reasoning → VT/AbuseIPDB.

## VALIDATION LAYERS

Layer 1 — Local whitelist (always runs, free):
  Filter known-clean system IPs, Microsoft domains, Windows system hashes.
  IOCs matching whitelist → verdict: benign, skipped from Layer 2+.

Layer 2 — DeepSeek reasoning (always runs for non-benign):
  Sends IOC context (type, value, source_plugin, process, technique) to DeepSeek.
  Analyzes behavioral patterns, chain of indicators, process context.
  Returns verdict + confidence + reasoning per IOC.

Layer 3 — VT + AbuseIPDB (only for IOCs with DeepSeek confidence ≥ 0.75):
  VirusTotal  → hash, IP, domain lookup
  AbuseIPDB   → IP reputation (abuse score)
  Saves API quota — only high-confidence suspicious IOCs are checked.

## VERDICT MAPPING
  malicious  → DeepSeek confidence ≥ 0.85 OR confirmed by VT/AbuseIPDB
  suspicious → DeepSeek confidence 0.50–0.84, no VT confirmation
  benign     → whitelist match OR DeepSeek confidence < 0.50

## OUTPUT SCHEMA
{
  "malicious":  [ {...ioc + verdict + reason...} ],
  "suspicious": [ {...} ],
  "benign":     [ {...} ],
  "summary": {
    "malicious":  3,
    "suspicious": 8,
    "benign":     15,
    "vt_checked": 4,
    "deepseek_reasoning": "Summary of behavioral patterns observed..."
  }
}
""",
    )
    async def ioc_validate(
        ctx: Context,
        network_iocs: list,
        host_iocs: list,
        os_type: str = "windows",
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
        all_iocs = network_iocs + host_iocs
        if not all_iocs:
            return {
                "malicious":  [],
                "suspicious": [],
                "benign":     [],
                "summary": {
                    "malicious": 0, "suspicious": 0, "benign": 0,
                    "vt_checked": 0, "deepseek_reasoning": "No IOCs to validate",
                },
            }

        await ctx.info(f"Validating {len(all_iocs)} IOCs "
                       f"({len(network_iocs)} network + {len(host_iocs)} host)...")

        from src.models.ioc import IOC
        ioc_objects: list[IOC] = []
        for entry in all_iocs:
            try:
                ioc_objects.append(IOC(
                    ioc_type=entry.get("type") or entry.get("ioc_type", "unknown"),
                    value=entry["value"],
                    confidence=entry.get("confidence", 0.5),
                    source_plugin=entry.get("source_plugin") or entry.get("source", "unknown"),
                    context=entry.get("context", {}),
                ))
            except Exception:
                continue

        validator = ValidationPipeline(config={
            "vt_api_key":    settings.vt_api_key,
            "abuse_api_key": settings.abuseipdb_key,
            "deepseek_api_key": settings.deepseek_api_key,
        })
        try:
            validated = await validator.validate_batch(ioc_objects, os_type=os_type)
        finally:
            await validator.close()

        malicious  = [v for v in validated if v.verdict == "malicious"]
        suspicious = [v for v in validated if v.verdict == "suspicious"]
        benign     = [v for v in validated if v.verdict == "benign"]
        vt_checked = sum(1 for v in validated if getattr(v, "vt_checked", False))

        await ctx.info(
            f"Results: {len(malicious)} malicious, "
            f"{len(suspicious)} suspicious, {len(benign)} benign | "
            f"VT checked: {vt_checked}"
        )

        def _fmt(validated_list):
            return [
                {
                    "type":             v.ioc.ioc_type,
                    "value":            v.ioc.value,
                    "verdict":          v.verdict,
                    "confidence":       v.final_confidence,
                    "reason":           v.reason or "",
                    "source_plugin":    v.ioc.source_plugin,
                    "context":          v.ioc.context,
                }
                for v in sorted(validated_list, key=lambda x: -x.final_confidence)
            ]

        return {
            "malicious":  _fmt(malicious),
            "suspicious": _fmt(suspicious),
            "benign":     _fmt(benign),
            "summary": {
                "malicious":          len(malicious),
                "suspicious":         len(suspicious),
                "benign":             len(benign),
                "vt_checked":         vt_checked,
                "deepseek_reasoning": getattr(validator, "last_reasoning", ""),
            },
        }
