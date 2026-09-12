import redis.asyncio as aioredis
from config import REDIS_URL

_redis_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    """Return the shared async Redis connection pool (lazy-initialized)."""
    global _redis_pool
    if _redis_pool is None:
        # Blocking pool: under bursts, requests wait for a free connection instead of failing
        # with "Too many connections" (observed as HTTP 500 at >=100 concurrent clients).
        pool = aioredis.BlockingConnectionPool.from_url(
            REDIS_URL, decode_responses=True, max_connections=100, timeout=5,
        )
        _redis_pool = aioredis.Redis(connection_pool=pool)
    return _redis_pool


async def close_redis() -> None:
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.aclose()
        _redis_pool = None
