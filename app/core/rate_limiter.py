import time
import uuid
from typing import Any, cast

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
    window_start = now - window_seconds
    pipe = redis_client.pipeline()
    pipe.zremrangebyscore(key, 0, window_start)
    pipe.zcard(key)
    exec_result = cast(list[Any], pipe.execute())
    _, count = exec_result[0], int(exec_result[1])

    if count >= limit:
        oldest_scores = cast(list[tuple[Any, Any]], redis_client.zrange(key, 0, 0, withscores=True))
        if oldest_scores:
            oldest = float(oldest_scores[0][1])
            retry_after = max(1, int(window_seconds - (now - oldest)) + 1)
        else:
            retry_after = window_seconds
        return False, retry_after

    member = f"{now}:{uuid.uuid4().hex}"
    pipe = redis_client.pipeline()
    pipe.zadd(key, {member: now})
    pipe.expire(key, window_seconds + 5)
    pipe.execute()
    return True, 0
