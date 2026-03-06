from openai import AsyncOpenAI
from typing import List, Dict, Any, Optional
import os


class DeepSeekClient:
    def __init__(self, api_key: str):
        self.chat_client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com"
        )
        self.reasoner_client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com"
        )
        self.total_tokens = 0
        self.total_requests = 0
        self._chat_model     = os.getenv("DEEPSEEK_MODEL",          "deepseek-chat")
        self._reasoner_model = os.getenv("DEEPSEEK_REASONER_MODEL", "deepseek-reasoner")

    async def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        temperature: float = 0.3,
        max_tokens: int = 8192,
    ) -> Any:
        params = {
            "model": self._chat_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            params["tools"] = tools
            params["tool_choice"] = "auto"

        response = await self.chat_client.chat.completions.create(**params)
        self.total_requests += 1
        if hasattr(response, "usage") and response.usage:
            self.total_tokens += response.usage.total_tokens
        return response.choices[0].message

    async def reason(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 16000,
    ) -> Dict[str, str]:
        params = {
            "model": self._reasoner_model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        response = await self.reasoner_client.chat.completions.create(**params)
        self.total_requests += 1
        if hasattr(response, "usage") and response.usage:
            self.total_tokens += response.usage.total_tokens

        msg = response.choices[0].message
        return {
            "content":           msg.content or "",
            "reasoning_content": getattr(msg, "reasoning_content", "") or "",
        }

    def get_stats(self) -> Dict[str, int]:
        return {
            "requests": self.total_requests,
            "tokens":   self.total_tokens,
        }
