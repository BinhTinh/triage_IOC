import hashlib
import json
from typing import Optional, Any

from src.config.settings import settings

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class CacheManager:
    def __init__(self):
        self.redis = None
        self._local_cache = {}
        self.ttl = settings.cache_ttl
    
    async def _get_redis(self):
        if not REDIS_AVAILABLE:
            return None
        
        if self.redis is None and settings.redis_url:
            try:
                self.redis = aioredis.from_url(settings.redis_url)
            except Exception:
                self.redis = None
        
        return self.redis
    
    def generate_key(self, dump_path: str, plugin: str, args: Optional[dict] = None) -> str:
        args_str = json.dumps(args or {}, sort_keys=True)
        key_data = f"{dump_path}:{plugin}:{args_str}"
        key_hash = hashlib.md5(key_data.encode()).hexdigest()[:16]
        return f"vol3:result:{key_hash}"
    
    async def get(self, key: str) -> Optional[dict]:
        redis = await self._get_redis()
        
        if redis:
            try:
                data = await redis.get(key)
                if data:
                    return json.loads(data)
            except Exception:
                pass
        
        return self._local_cache.get(key)
    
    async def set(self, key: str, value: dict, ttl: Optional[int] = None) -> bool:
        ttl = ttl or self.ttl
        redis = await self._get_redis()
        
        if redis:
            try:
                await redis.setex(key, ttl, json.dumps(value, default=str))
                return True
            except Exception:
                pass
        
        self._local_cache[key] = value
        return True
    
    async def delete(self, key: str) -> bool:
        redis = await self._get_redis()
        
        if redis:
            try:
                await redis.delete(key)
            except Exception:
                pass
        
        if key in self._local_cache:
            del self._local_cache[key]
        
        return True
    
    async def clear(self) -> bool:
        redis = await self._get_redis()
        
        if redis:
            try:
                keys = await redis.keys("vol3:*")
                if keys:
                    await redis.delete(*keys)
            except Exception:
                pass
        
        self._local_cache.clear()
        return True