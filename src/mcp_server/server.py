import sys
import os
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastmcp import FastMCP

from src.mcp_server.tools.triage import register_triage_tools
from src.mcp_server.tools.execution import register_execution_tools
from src.mcp_server.tools.validation import register_validation_tools
from src.mcp_server.prompts.templates import register_prompts
from src.mcp_server.resources.plugins import register_plugin_resources

_REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")


@asynccontextmanager
async def lifespan(app):
    redis_client = None
    try:
        redis_client = await aioredis.from_url(_REDIS_URL, decode_responses=False)
        await redis_client.ping()

        from src.mcp_server.tools.execution import executor
        executor._redis = redis_client

        print(f"✅ Redis connected: {_REDIS_URL}", file=sys.stderr)
    except Exception as e:
        print(f"⚠️  Redis unavailable ({e}) — running without cache", file=sys.stderr)

    yield

    if redis_client:
        await redis_client.aclose()


mcp = FastMCP(
    name="volatility3-ioc-extraction",
    version="2.0.0",
    lifespan=lifespan,
    instructions=(
        "# Volatility3 Windows IOC Extraction Server\n\n"

        "## 6-Phase Pipeline (always execute in order)\n"
        "1. `list_dumps()` — discover dump files in /app/data/dumps/\n"
        "2. `detect_os(dump_path)` — identify os_type; NEVER skip\n"
        "3. `run_plugins(dump_path, os_type, store_only=true)` → result_id\n"
        "4. `ioc_extract_from_store(result_id, os_type)` → ioc report_path\n"
        "5. `ioc_validate_from_report(report_path, os_type)` → validated report_path\n"
        "6. `forensic_report_from_validation(report_path)` → final forensic report\n\n"

        "## Key Output: by_process\n"
        "Phases 4 and 5 both return `by_process`: a list of process groups sorted "
        "by threat_score descending. Each group has: process, pid, threat_level "
        "(HIGH/MEDIUM/LOW), threat_score (0.0-1.0), techniques (MITRE list), "
        "ioc_count, and iocs[]. HIGH = threat_score >= 0.75. "
        "Always report the top dangerous processes to the user.\n\n"

        "## Path Rules\n"
        "Use POSIX Docker paths only — never Windows paths.\n"
        "Dumps: /app/data/dumps/ | Reports: /app/data/reports/\n\n"

        "## Validation\n"
        "Whitelist always runs. VT/AbuseIPDB only when API keys are configured. "
        "Verdicts: malicious (>=0.70), suspicious (0.40-0.69), benign (<0.40).\n\n"

        "## IOC Types Extracted\n"
        "injection (T1055), hollowing (T1055.012), hidden-process (T1564.001), "
        "service-persistence (T1543.003), C2-network (T1071), "
        "command (T1059), hashes/MD5/SHA1/SHA256 (T1204), "
        "filepath (T1036), registry-persistence (T1547).\n\n"

        "## Full Guide\n"
        "Call prompt `ioc_extraction_workflow` for the complete phase-by-phase guide "
        "with examples, error handling, and MITRE mapping table.\n"
        "Call prompt `ioc_reference` for the compact tool cheat sheet."
    ),
)

register_triage_tools(mcp)
register_execution_tools(mcp)
register_validation_tools(mcp)
register_prompts(mcp)
register_plugin_resources(mcp)


def run_server(transport: str = "stdio", host: str = "0.0.0.0", port: int = 8000):
    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "http":
        mcp.run(transport="http", host=host, port=port)
    elif transport == "sse":
        mcp.run(transport="sse", host=host, port=port)
    else:
        raise ValueError(f"Unsupported transport: {transport}")