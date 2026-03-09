import asyncio
import json
from src.mcp_server.tools.execution import get_stored_plugin_results
from src.core.ioc_extractor import ExtractionPipeline
from src.core.validator import ValidationPipeline
from src.config.settings import settings

async def main():
    rid = "rp_89bf3b5414494a01"
    payload = get_stored_plugin_results(rid)
    if not payload:
        print(json.dumps({"error": f"Unknown result_id: {rid}"}))
        return

    merged = {}
    merged.update(payload.get("network_data", {}))
    merged.update(payload.get("host_data", {}))

    extractor = ExtractionPipeline("windows")
    all_iocs = await extractor.extract(merged)
    network = [i for i in all_iocs if getattr(i, "category", "host") == "network"]
    host = [i for i in all_iocs if getattr(i, "category", "host") != "network"]

    validator = ValidationPipeline(config={
        "vt_api_key": settings.vt_api_key,
        "abuse_api_key": settings.abuseipdb_key,
        "deepseek_api_key": settings.deepseek_api_key,
        "use_deepseek": settings.use_deepseek,
    })
    try:
        validated = await validator.validate_batch(all_iocs, os_type="windows")
    finally:
        await validator.close()

    malicious = [v for v in validated if v.verdict == "malicious"]
    suspicious = [v for v in validated if v.verdict == "suspicious"]
    benign = [v for v in validated if v.verdict == "benign"]

    out = {
        "result_id": rid,
        "extraction_summary": {
            "total": len(all_iocs),
            "network_count": len(network),
            "host_count": len(host),
        },
        "validation_summary": {
            "malicious": len(malicious),
            "suspicious": len(suspicious),
            "benign": len(benign),
        },
        "top_malicious": [v.to_dict() for v in malicious[:5]],
        "top_suspicious": [v.to_dict() for v in suspicious[:5]],
        "top_benign": [v.to_dict() for v in benign[:5]],
    }
    print(json.dumps(out))

asyncio.run(main())
