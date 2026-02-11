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


async def extract_iocs(ctx: Context, plugin_results: dict, os_type: str = "windows") -> dict:
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


async def validate_iocs(ctx: Context, iocs: List[dict], os_type: str = "windows") -> dict:
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


async def map_mitre(ctx: Context, validated_iocs: dict) -> dict:
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


def register_validation_tools(mcp: FastMCP):
    
    @mcp.tool()
    async def ioc_extract(ctx: Context, plugin_results: dict, os_type: str = "windows") -> dict:
        return await extract_iocs(ctx, plugin_results, os_type)
    
    @mcp.tool()
    async def ioc_validate(ctx: Context, iocs: List[dict], os_type: str = "windows") -> dict:
        return await validate_iocs(ctx, iocs, os_type)
    
    @mcp.tool()
    async def ioc_map_mitre(ctx: Context, validated_iocs: dict) -> dict:
        return await map_mitre(ctx, validated_iocs)
    
    @mcp.tool()
    async def ioc_generate_report(
        ctx: Context,
        case_id: str,
        validated_iocs: dict,
        mitre_mapping: dict,
        format: str = "both"
    ) -> dict:
        return await generate_report(ctx, case_id, validated_iocs, mitre_mapping, format)
    
    @mcp.tool()
    async def validate_ip(ctx: Context, ip: str) -> dict:
        config = {
            "vt_api_key": settings.vt_api_key,
            "abuse_api_key": settings.abuseipdb_key
        }
        
        pipeline = ValidationPipeline(config)
        
        ioc = IOC(
            ioc_type="ip",
            value=ip,
            confidence=0.5,
            source_plugin="manual",
            context={},
            extracted_at=datetime.now()
        )
        
        result = await pipeline.validate_ioc(ioc)
        
        return {
            "ip": ip,
            "verdict": result.verdict,
            "confidence": result.final_confidence,
            "reason": result.reason
        }
    
    @mcp.tool()
    async def validate_domain(ctx: Context, domain: str) -> dict:
        config = {
            "vt_api_key": settings.vt_api_key,
            "abuse_api_key": settings.abuseipdb_key
        }
        
        pipeline = ValidationPipeline(config)
        
        ioc = IOC(
            ioc_type="domain",
            value=domain,
            confidence=0.5,
            source_plugin="manual",
            context={},
            extracted_at=datetime.now()
        )
        
        result = await pipeline.validate_ioc(ioc)
        
        return {
            "domain": domain,
            "verdict": result.verdict,
            "confidence": result.final_confidence,
            "reason": result.reason
        }
    
    @mcp.tool()
    async def validate_hash(ctx: Context, hash_value: str) -> dict:
        config = {
            "vt_api_key": settings.vt_api_key,
            "abuse_api_key": settings.abuseipdb_key
        }
        
        pipeline = ValidationPipeline(config)
        
        hash_type = "md5"
        if len(hash_value) == 40:
            hash_type = "sha1"
        elif len(hash_value) == 64:
            hash_type = "sha256"
        
        ioc = IOC(
            ioc_type=hash_type,
            value=hash_value,
            confidence=0.5,
            source_plugin="manual",
            context={},
            extracted_at=datetime.now()
        )
        
        result = await pipeline.validate_ioc(ioc)
        
        return {
            "hash": hash_value,
            "hash_type": hash_type,
            "verdict": result.verdict,
            "confidence": result.final_confidence,
            "reason": result.reason
        }
    
    @mcp.tool()
    async def get_mitre_technique(ctx: Context, technique_id: str) -> dict:
        mapper = MITREMapper()
        return mapper.get_technique_info(technique_id)