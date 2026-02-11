import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastmcp import FastMCP, Context

from src.core.decision_engine import DecisionEngine, get_triage_plan
from src.core.volatility_executor import VolatilityExecutor
from src.core.ioc_extractor import ExtractionPipeline
from src.core.validator import ValidationPipeline
from src.core.mitre_mapper import MITREMapper
from src.core.report_generator import ReportGenerator
from src.core.symbol_resolver import SymbolResolver
from src.models.case import Case, CaseStatus
from src.models.ioc import IOC, ValidatedIOC
from src.utils.cache import CacheManager
from src.utils.security import validate_dump_path, validate_plugin_name, canonicalize_plugin_name
from src.config.settings import settings

mcp = FastMCP(
    name="volatility3-ioc-extraction",
    version="1.0.0",
    instructions="Automated IOC extraction from memory dumps using Volatility3"
)

cache = CacheManager()
executor = VolatilityExecutor()
decision_engine = DecisionEngine()
symbol_resolver = SymbolResolver()

cases_db: dict = {}


async def get_case(case_id: str) -> Optional[Case]:
    return cases_db.get(case_id)


async def save_case(case: Case) -> None:
    cases_db[case.id] = case


async def update_case_status(case_id: str, status: str) -> None:
    if case_id in cases_db:
        cases_db[case_id].status = CaseStatus(status)
        cases_db[case_id].updated_at = datetime.now()

async def _detect_os_helper(dump_path: str) -> dict:
    try:
        result = await executor.run_plugin(dump_path, "windows.info.Info", renderer="json")
        if result.success and result.data:
            return {
                "os_type": "windows",
                "version": str(result.data[0].get("NtMajorVersion", "unknown")),
                "build": str(result.data[0].get("NtBuildNumber", "unknown")),
                "arch": "x64" if result.data[0].get("Is64Bit", True) else "x86"
            }
    except:
        pass
    
    try:
        result = await executor.run_plugin(dump_path, "banners.Banners", renderer="json")
        if result.success and result.data:
            import re
            for banner in result.data:
                banner_text = banner.get("Banner", "")
                match = re.search(r"Linux version (\d+\.\d+\.\d+)", banner_text)
                if match:
                    return {"os_type": "linux", "version": match.group(1), "arch": "x64"}
    except:
        pass
    
    return {"os_type": "windows", "version": "unknown", "arch": "x64"}


async def _smart_triage_helper(dump_path: str, goal: str) -> dict:
    os_info = await _detect_os_helper(dump_path)
    plan = get_triage_plan(os_info["os_type"], goal)
    
    case = Case(
        dump_path=dump_path,
        dump_hash=await executor.get_dump_hash(dump_path),
        os_type=os_info["os_type"],
        os_version=os_info.get("version", "unknown"),
        os_arch=os_info.get("arch", "x64"),
        goal=goal
    )
    await save_case(case)
    
    return {
        "case_id": case.id,
        "os": os_info,
        "plan": {
            "goal": goal,
            "plugins": [p["name"] for p in plan.plugins],
            "estimated_minutes": plan.estimated_minutes
        }
    }

@mcp.tool()
async def detect_os(ctx: Context, dump_path: str) -> dict:
    validate_dump_path(dump_path)
    await ctx.info(f"Detecting OS for {dump_path}")
    return await _detect_os_helper(dump_path)


@mcp.tool()
async def smart_triage(ctx: Context, dump_path: str, goal: str = "malware_detection") -> dict:
    validate_dump_path(dump_path)
    await ctx.info(f"Starting smart triage for {dump_path}")
    result = await _smart_triage_helper(dump_path, goal)
    await ctx.info(f"Created case {result['case_id']}")
    return result


@mcp.tool()
async def run_plugin(
    ctx: Context,
    dump_path: str,
    plugin: str,
    args: Optional[dict] = None
) -> dict:
    validate_dump_path(dump_path)
    plugin = canonicalize_plugin_name(plugin)
    validate_plugin_name(plugin)

                         
    await ctx.info(f"Running plugin {plugin}")

    
    cache_key = cache.generate_key(dump_path, plugin, args)
    cached_result = await cache.get(cache_key)
    if cached_result:
        await ctx.info(f"Cache hit for {plugin}")
        return cached_result
    
    result = await executor.run_plugin(dump_path, plugin, args)
    
    if result.success:
        await cache.set(cache_key, result.to_dict())
    
    return result.to_dict()


@mcp.tool()
async def batch_plugins(
    ctx: Context,
    dump_path: str,
    plugins: List[str],
    max_concurrent: int = 3
) -> dict:
    validate_dump_path(dump_path)
    for plugin in plugins:
        validate_plugin_name(canonicalize_plugin_name(plugin))
    
    total = len(plugins)
    results = {}
    successful = 0
    failed = 0
    
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def run_with_semaphore(plugin: str) -> tuple:
        async with semaphore:
            await ctx.report_progress(
                current=len(results),
                total=total,
                message=f"Running {plugin}..."
            )
            result = await run_plugin(ctx, dump_path, canonicalize_plugin_name(plugin))
            return plugin, result
    
    tasks = [run_with_semaphore(p) for p in plugins]
    completed = await asyncio.gather(*tasks, return_exceptions=True)
    
    data = {}
    for item in completed:
        if isinstance(item, Exception):
            failed += 1
            continue
        plugin, result = item
        results[plugin] = {
            "success": result.get("success", False),
            "rows": len(result.get("data", [])) if result.get("data") else 0,
            "error": result.get("error")
        }
        if result.get("success"):
            successful += 1
            data[plugin] = result.get("data", [])
        else:
            failed += 1
    
    await ctx.report_progress(progress=total, total=total, message="Complete")
    
    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "results": results,
        "data": data
    }


@mcp.tool()
async def extract_iocs(
    ctx: Context,
    plugin_results: dict,
    os_type: str = "windows"
) -> dict:
    await ctx.info("Extracting IOCs from plugin results")
    
    pipeline = ExtractionPipeline(os_type)
    iocs = await pipeline.extract(plugin_results.get("data", {}))
    
    high_confidence = [i for i in iocs if i.confidence >= 0.7]
    medium_confidence = [i for i in iocs if 0.4 <= i.confidence < 0.7]
    low_confidence = [i for i in iocs if i.confidence < 0.4]
    
    by_type = {}
    for ioc in iocs:
        if ioc.ioc_type not in by_type:
            by_type[ioc.ioc_type] = []
        by_type[ioc.ioc_type].append(ioc.to_dict())
    
    await ctx.info(f"Extracted {len(iocs)} IOCs")
    
    return {
        "total": len(iocs),
        "by_confidence": {
            "high": len(high_confidence),
            "medium": len(medium_confidence),
            "low": len(low_confidence)
        },
        "by_type": {k: len(v) for k, v in by_type.items()},
        "iocs": [ioc.to_dict() for ioc in sorted(iocs, key=lambda x: -x.confidence)],
        "next_action": "Call validate_iocs to verify against threat intelligence"
    }


@mcp.tool()
async def validate_iocs(
    ctx: Context,
    iocs: List[dict],
    os_type: str = "windows"
) -> dict:
    await ctx.info(f"Validating {len(iocs)} IOCs")
    
    config = {
        "vt_api_key": settings.vt_api_key,
        "abuse_api_key": settings.abuseipdb_key
    }
    
    pipeline = ValidationPipeline(config)
    
    ioc_objects = [
        IOC(
            ioc_type=i["type"],
            value=i["value"],
            confidence=i.get("confidence", 0.5),
            source_plugin=i.get("source", "unknown"),
            context=i.get("context", {}),
            extracted_at=datetime.fromisoformat(i["extracted_at"]) if "extracted_at" in i else datetime.now()
        )
        for i in iocs
    ]
    
    validated = await pipeline.validate_batch(ioc_objects, os_type)
    
    by_verdict = {"malicious": [], "suspicious": [], "benign": []}
    for v in validated:
        by_verdict[v.verdict].append({
            "type": v.ioc.ioc_type,
            "value": v.ioc.value,
            "confidence": v.final_confidence,
            "verdict": v.verdict,
            "reason": v.reason,
            "context": v.ioc.context
        })
    
    await ctx.info(
        f"Results: {len(by_verdict['malicious'])} malicious, "
        f"{len(by_verdict['suspicious'])} suspicious, "
        f"{len(by_verdict['benign'])} benign"
    )
    
    return {
        "total": len(validated),
        "summary": {
            "malicious": len(by_verdict["malicious"]),
            "suspicious": len(by_verdict["suspicious"]),
            "benign": len(by_verdict["benign"])
        },
        "malicious": by_verdict["malicious"],
        "suspicious": by_verdict["suspicious"],
        "benign": by_verdict["benign"],
        "next_action": "Call map_mitre to map findings to ATT&CK techniques"
    }


@mcp.tool()
async def map_mitre(
    ctx: Context,
    validated_iocs: dict
) -> dict:
    await ctx.info("Mapping IOCs to MITRE ATT&CK")
    
    iocs = []
    for verdict in ["malicious", "suspicious"]:
        for ioc_data in validated_iocs.get(verdict, []):
            iocs.append(ValidatedIOC(
                ioc=IOC(
                    ioc_type=ioc_data["type"],
                    value=ioc_data["value"],
                    confidence=ioc_data.get("confidence", 0.5),
                    source_plugin=ioc_data.get("source", "unknown"),
                    context=ioc_data.get("context", {}),
                    extracted_at=datetime.now()
                ),
                final_confidence=ioc_data.get("confidence", 0.5),
                verdict=verdict,
                validation_results=[],
                reason=ioc_data.get("reason", "")
            ))
    
    mapper = MITREMapper()
    mitre_report = mapper.map_iocs(iocs)
    matrix = mapper.generate_matrix(mitre_report)
    
    active_tactics = {k: v for k, v in matrix.items() if v}
    
    await ctx.info(f"Mapped to {mitre_report.total_techniques} techniques")
    
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
                "recommendations": data["technique"]["recommendations"]
            }
            for tid, data in mitre_report.techniques.items()
        ],
        "next_action": "Call generate_report to create final report"
    }


@mcp.tool()
async def generate_report(
    ctx: Context,
    case_id: str,
    validated_iocs: dict,
    mitre_mapping: dict,
    format: str = "both"
) -> dict:
    case = await get_case(case_id)
    if not case:
        raise ValueError(f"Case not found: {case_id}")
    
    await ctx.info(f"Generating report for case {case_id}")
    
    iocs = []
    for verdict in ["malicious", "suspicious", "benign"]:
        for ioc_data in validated_iocs.get(verdict, []):
            iocs.append(ValidatedIOC(
                ioc=IOC(
                    ioc_type=ioc_data["type"],
                    value=ioc_data["value"],
                    confidence=ioc_data.get("confidence", 0.5),
                    source_plugin=ioc_data.get("source", "unknown"),
                    context=ioc_data.get("context", {}),
                    extracted_at=datetime.now()
                ),
                final_confidence=ioc_data.get("confidence", 0.5),
                verdict=verdict,
                validation_results=[],
                reason=ioc_data.get("reason", "")
            ))
    
    generator = ReportGenerator()
    generator.create_case_directory(case)
    report = generator.generate(case, iocs, mitre_mapping)
    
    paths = {}
    if format in ["json", "both"]:
        paths["json"] = generator.save_json(report)
        await ctx.info(f"JSON report saved: {paths['json']}")
    
    if format in ["markdown", "both"]:
        paths["markdown"] = generator.save_markdown(report)
        await ctx.info(f"Markdown report saved: {paths['markdown']}")
    
    await update_case_status(case_id, "completed")
    
    return {
        "case_id": case_id,
        "status": "completed",
        "threat_level": report.summary["threat_level"],
        "summary": report.summary,
        "report_paths": paths,
        "top_recommendations": report.recommendations[:5],
        "techniques_detected": [
            {"id": t["id"], "name": t["name"]}
            for t in mitre_mapping.get("techniques", [])[:10]
        ]
    }


@mcp.tool()
async def full_analysis(ctx: Context, dump_path: str, goal: str = "malware_detection") -> dict:
    validate_dump_path(dump_path)
    await ctx.info(f"Starting full analysis pipeline for {dump_path}")
    
    from src.core.analysis_pipeline import AnalysisPipeline
    
    pipeline = AnalysisPipeline(
        progress_callback=lambda curr, total, msg: asyncio.create_task(ctx.report_progress(curr, total, msg)),
        log_callback=lambda msg, level: asyncio.create_task(ctx.info(msg))
    )
    
    result = await pipeline.run_analysis(dump_path=dump_path, goal=goal)
    
    await ctx.info(f"Analysis complete: {result['threat_level']} threat level")
    
    return result

@mcp.tool()
async def get_symbols_status(
    ctx: Context,
    dump_path: str
) -> dict:
    validate_dump_path(dump_path)
    return await symbol_resolver.check_symbols(dump_path)


@mcp.resource("plugins://catalog")
async def get_plugin_catalog() -> dict:
    return decision_engine.get_plugin_catalog()


@mcp.resource("plugins://{plugin_name}/info")
async def get_plugin_info(plugin_name: str) -> dict:
    return decision_engine.get_plugin_info(plugin_name)


@mcp.resource("profiles://{goal}/{os_type}")
async def get_analysis_profile(goal: str, os_type: str) -> dict:
    plan = get_triage_plan(os_type, goal)
    return {
        "goal": goal,
        "os_type": os_type,
        "plugins": [p["name"] for p in plan.plugins],
        "estimated_minutes": plan.estimated_minutes,
        "description": plan.description
    }


@mcp.resource("cases://list")
async def list_cases() -> dict:
    return {
        "total": len(cases_db),
        "cases": [
            {
                "id": c.id,
                "status": c.status.value,
                "os_type": c.os_type,
                "goal": c.goal,
                "created_at": c.created_at.isoformat()
            }
            for c in cases_db.values()
        ]
    }


@mcp.resource("cases://{case_id}/summary")
async def get_case_summary(case_id: str) -> dict:
    case = await get_case(case_id)
    if not case:
        raise ValueError(f"Case not found: {case_id}")
    return case.to_dict()


@mcp.prompt()
async def malware_triage_prompt(dump_path: str, os_type: str = "windows") -> str:
    return f"""Analyze the memory dump at {dump_path} for malware indicators.

OS Type: {os_type}

Steps:
1. Run smart_triage to get analysis plan
2. Execute batch_plugins with recommended plugins
3. Extract IOCs from results
4. Validate IOCs against threat intelligence
5. Map findings to MITRE ATT&CK
6. Generate final report

Focus on:
- Process injection (T1055)
- Suspicious command lines
- Network connections to unknown IPs
- Persistence mechanisms
"""


@mcp.prompt()
async def incident_response_prompt(dump_path: str, incident_type: str = "malware") -> str:
    return f"""Perform incident response analysis on {dump_path}.

Incident Type: {incident_type}

Investigation Steps:
1. Identify compromised processes
2. Extract network IOCs (IPs, domains)
3. Find persistence mechanisms
4. Build attack timeline
5. Document all findings

Deliverables:
- List of malicious IOCs
- MITRE ATT&CK mapping
- Remediation recommendations
"""


def run_server(transport: str = "stdio", host: str = "0.0.0.0", port: int = 8000):
    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "http":
        mcp.run(transport="http", host=host, port=port)
    elif transport == "sse":
        mcp.run(transport="sse", host=host, port=port)
    else:
        raise ValueError(f"Unknown transport: {transport}")


if __name__ == "__main__":
    import sys
    
    transport = "stdio"
    host = "0.0.0.0"
    port = 8000
    
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--transport" and i < len(sys.argv):
            transport = sys.argv[i + 1]
        elif arg == "--host" and i < len(sys.argv):
            host = sys.argv[i + 1]
        elif arg == "--port" and i < len(sys.argv):
            port = int(sys.argv[i + 1])
    
    run_server(transport, host, port)