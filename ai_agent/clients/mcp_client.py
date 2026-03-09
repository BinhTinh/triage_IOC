import os
from fastmcp import Client


class MCPClient:
    def __init__(self):
        self._url = os.getenv("MCP_SERVER_URL", "http://localhost:8000/mcp")
        self._client = None
        self.available_tools: list[str] = []

    async def __aenter__(self):
        self._client = Client(self._url)
        await self._client.__aenter__()
        tools = await self._client.list_tools()
        self.available_tools = [t.name for t in tools]
        print(f"✓ MCP connected: {self.available_tools}")
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.__aexit__(*args)

    async def call_tool(self, name: str, arguments: dict = None):
        return await self._client.call_tool(name, arguments or {})
