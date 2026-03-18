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
        "Volatility3 IOC MCP server. "
        "Flow: list_dumps -> detect_os -> run_plugins(store_only=true) -> "
        "ioc_extract_from_store -> ioc_validate_from_report -> forensic_report_from_validation. "
        "Use Docker paths only (/app/data/dumps, /app/data/reports). "
        "Never skip detect_os."
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