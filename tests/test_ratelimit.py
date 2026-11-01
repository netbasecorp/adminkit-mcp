from __future__ import annotations

import asyncio

import pytest

from adminkit_mcp.ratelimit import RateLimiter


async def test_rate_limiter_allows_burst_up_to_capacity() -> None:
    limiter = RateLimiter(rate=1000.0, burst=3.0)
    start = asyncio.get_event_loop().time()
    for _ in range(3):
        await limiter.acquire()
    elapsed = asyncio.get_event_loop().time() - start
    assert elapsed < 0.05  # all 3 should be effectively instant


async def test_rate_limiter_throttles_beyond_burst() -> None:
    limiter = RateLimiter(rate=20.0, burst=1.0)
    await limiter.acquire()  # consumes the single burst token
    start = asyncio.get_event_loop().time()
    await limiter.acquire()
    elapsed = asyncio.get_event_loop().time() - start
    assert elapsed >= 0.03  # had to wait roughly 1/20s


def test_rate_limiter_rejects_non_positive_rate() -> None:
    with pytest.raises(ValueError):
        RateLimiter(rate=0)
