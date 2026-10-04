from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from app.core.rate_limiter import sliding_window_allow


def test_concurrent_requests_cannot_exceed_rate_limit(redis_client, monkeypatch):
    barrier = Barrier(2)
    original_pipeline = redis_client.pipeline

    def coordinated_pipeline(*args, **kwargs):
        pipeline = original_pipeline(*args, **kwargs)
        original_execute = pipeline.execute

        def execute(*args, **kwargs):
            results = original_execute(*args, **kwargs)
            # Expose a split read/write race at the real Redis boundary.
            if len(results) == 2 and isinstance(results[1], int):
                barrier.wait(timeout=5)
            return results

        pipeline.execute = execute
        return pipeline

    monkeypatch.setattr(redis_client, "pipeline", coordinated_pipeline)

    def attempt(_):
        return sliding_window_allow(redis_client, key="rl:concurrency:test", limit=1)[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, range(2)))
    assert outcomes.count(True) == 1
    assert redis_client.zcard("rl:concurrency:test") == 1
