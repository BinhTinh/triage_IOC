import json
import redis.asyncio as redis
from typing import Any, Optional

class RedisCache:
    def __init__(self, url: str = "redis://localhost:6379"):
        self.url = url
        self.client: Optional[redis.Redis] = None
    
    async def connect(self):
        self.client = await redis.from_url(self.url, decode_responses=True)
    
    async def close(self):
        if self.client:
            await self.client.close()
    
    async def get(self, key: str) -> Optional[Any]:
        if not self.client:
            return None
        
        data = await self.client.get(key)
        return json.loads(data) if data else None
    
    async def set(self, key: str, value: Any, ttl: int = 3600):
        if not self.client:
            return
        
        await self.client.set(key, json.dumps(value), ex=ttl)
    
    async def delete(self, key: str):
        if self.client:
            await self.client.delete(key)
    
    async def exists(self, key: str) -> bool:
        if not self.client:
            return False
        return await self.client.exists(key) > 0