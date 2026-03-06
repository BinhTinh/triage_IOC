import os
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastmcp import FastMCP

from src.mcp_server.tools.triage import register_triage_tools
from src.mcp_server.tools.execution import register_execution_tools
from src.mcp_server.tools.validation import register_validation_tools
from src.mcp_server.prompts.templates import register_prompts
from src.mcp_server.resources.plugins import register_plugin_resources
from src.mcp_server.resources.cases import register_case_resources

_REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")


@asynccontextmanager
async def lifespan(app):
    redis_client = None
    try:
        redis_client = await aioredis.from_url(_REDIS_URL, decode_responses=False)
        await redis_client.ping()

        from src.mcp_server.tools.execution import executor
        executor._redis = redis_client

        from src.core.validator import set_redis_client
        set_redis_client(redis_client)

        print(f"✅ Redis connected: {_REDIS_URL} (L1+L2 cache active)")
    except Exception as e:
        print(f"⚠️  Redis unavailable ({e}) — running without cache")

    yield

    if redis_client:
        await redis_client.aclose()
        print("Redis connection closed")


mcp = FastMCP(
    name="volatility3-ioc-extraction",
    version="2.0.0",
    lifespan=lifespan,
    instructions=(
        "MCP server for automated IOC extraction from memory dumps using Volatility3. "
        "Start every session with list_available_dumps → detect_os → smart_triage. "
        "Never skip detect_os — os_type is required by batch_plugins, compare_processes, and ioc_extract. "
        "For complete IOC extraction use the full plugin list from smart_triage — do not reduce it."
    ),
)

register_triage_tools(mcp)
register_execution_tools(mcp)
register_validation_tools(mcp)
register_prompts(mcp)
register_plugin_resources(mcp)
register_case_resources(mcp)


def run_server(transport: str = "stdio", host: str = "0.0.0.0", port: int = 8000):
    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "http":
        mcp.run(transport="http", host=host, port=port)
    elif transport == "sse":
        mcp.run(transport="sse", host=host, port=port)
    else:
        raise ValueError(f"Unsupported transport: {transport}")
