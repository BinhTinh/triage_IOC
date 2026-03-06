import json
import httpx
from typing import Any, Dict, List, Optional
import os


class MCPClient:
    def __init__(self, base_url: str = None):
        self.base_url = (base_url or os.getenv("MCP_SERVER_URL", "http://localhost:8000")).rstrip("/")
        self.session_id: Optional[str] = None
        self.tools: Dict[str, Any] = {}
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"
        }
        self._req_id = 0

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _parse_sse(self, text: str) -> dict:
        last_data = None
        for line in text.strip().splitlines():
            line = line.strip()
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload and payload != "[DONE]":
                    last_data = payload
        if last_data:
            return json.loads(last_data)
        return json.loads(text)


    async def _post(self, payload: dict) -> dict:
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(
                f"{self.base_url}/mcp",
                headers=self._headers,
                json=payload
            )
            return self._parse_sse(resp.text)

    async def initialize(self) -> None:
        if self.session_id:
            return
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self.base_url}/mcp",
                headers=self._headers,
                json={
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "forensics-agent", "version": "1.0"}
                    },
                    "id": self._next_id()
                }
            )
            # Session ID nằm trong header
            self.session_id = resp.headers.get("mcp-session-id")
            if self.session_id:
                self._headers["mcp-session-id"] = self.session_id

        # Load tool list
        data = await self._post({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": self._next_id()
        })
        tools_list = data.get("result", {}).get("tools", [])
        self.tools = {t["name"]: t for t in tools_list}

    async def call_tool(self, name: str, **kwargs) -> Any:
        if not self.session_id:
            await self.initialize()
        if name not in self.tools:
            raise ValueError(f"Tool '{name}' not found. Available: {list(self.tools.keys())}")

        data = await self._post({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": name, "arguments": kwargs},
            "id": self._next_id()
        })

        result = data.get("result", {})

        # Trả về lỗi rõ ràng nếu tool error
        if result.get("isError"):
            content = result.get("content", [{}])
            error_msg = content[0].get("text", "Unknown error") if content else "Unknown error"
            raise RuntimeError(f"Tool '{name}' error: {error_msg}")

        # Ưu tiên structuredContent (dict), fallback về parse text
        structured = result.get("structuredContent")
        if structured:
            return structured

        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            try:
                return json.loads(content[0]["text"])
            except json.JSONDecodeError:
                return content[0]["text"]

        return result

    async def close(self) -> None:
        """Cleanup — không cần làm gì với HTTP stateless"""
        self.session_id = None

    def get_tool_names(self) -> List[str]:
        return list(self.tools.keys())

    def get_tool_description(self, name: str) -> str:
        return self.tools.get(name, {}).get("description", "")
