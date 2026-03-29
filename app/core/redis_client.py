from functools import lru_cache

from app.config import get_settings
from redis import Redis


@lru_cache
def get_redis() -> Redis:
    settings = get_settings()
    return Redis.from_url(settings.redis_url, decode_responses=True)
