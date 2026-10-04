import time
import uuid
from typing import cast

from redis import Redis


def sliding_window_allow(
    redis_client: Redis,
    *,
    key: str,
    limit: int,
    window_seconds: int = 60,
) -> tuple[bool, int]:
    """
    Sliding window rate limit using Redis sorted set (scores = request timestamps).
    Returns (allowed, retry_after_seconds). retry_after is 0 if allowed.
    """
    now = time.time()
    # Admission and counting must be atomic across concurrent HTTP workers.
    result = cast(list[int], redis_client.eval(
        """
        redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1] - ARGV[2])
        if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
            local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
            local retry = math.max(1, math.floor(ARGV[2] - (ARGV[1] - oldest[2])) + 1)
            return {0, retry}
        end
        redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
        redis.call('EXPIRE', KEYS[1], ARGV[2] + 5)
        return {1, 0}
        """,
        1, key, str(now), str(window_seconds), str(limit), uuid.uuid4().hex,
    ))
    return bool(result[0]), int(result[1])
