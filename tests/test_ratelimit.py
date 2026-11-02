from __future__ import annotations

import asyncio

import pytest

from adminkit_mcp.ratelimit import PerClientRateLimiter, RateLimiter


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


def test_try_acquire_never_waits_and_fails_past_burst() -> None:
    limiter = RateLimiter(rate=1.0, burst=1.0)
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False  # the single token is already spent


def test_per_client_rate_limiter_isolates_keys() -> None:
    limiter = PerClientRateLimiter(rate=1.0, burst=1.0)
    assert limiter.allow("1.2.3.4") is True
    assert limiter.allow("1.2.3.4") is False  # this key's single token is spent
    assert limiter.allow("5.6.7.8") is True  # a different key has its own, untouched bucket


def test_per_client_rate_limiter_evicts_once_past_max_keys() -> None:
    limiter = PerClientRateLimiter(rate=1.0, burst=1.0, max_keys=2)
    assert limiter.allow("a") is True
    assert limiter.allow("b") is True
    assert limiter.allow("a") is False  # "a"'s bucket is still fresh, one token already spent

    # A third distinct key pushes the bucket dict past max_keys, triggering the crude
    # clear-everything eviction -- "a" gets a brand new, full bucket afterwards.
    assert limiter.allow("c") is True
    assert limiter.allow("a") is True
