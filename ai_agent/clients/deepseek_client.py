import os
from openai import AsyncOpenAI


class DeepSeekClient:
    def __init__(self):
        self.client = AsyncOpenAI(
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
        self.model = os.getenv("DEEPSEEK_MODEL", "deepseek-reasoner")

    async def reason(self, prompt: str) -> tuple[str, str]:
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        message = response.choices[0].message
        reasoning = getattr(message, "reasoning_content", "") or ""
        content = message.content or ""
        return reasoning, content

    async def chat(self, messages: list, temperature: float = 0.3) -> str:
        response = await self.client.chat.completions.create(
            model="deepseek-chat",
            messages=messages,
            temperature=temperature,
        )
        return response.choices[0].message.content or ""
