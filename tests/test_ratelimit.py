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


def test_per_client_rate_limiter_evicts_least_recently_used_key() -> None:
    limiter = PerClientRateLimiter(rate=1.0, burst=1.0, max_keys=2)
    assert limiter.allow("a") is True
    assert limiter.allow("b") is True
    assert limiter.allow("a") is False  # "a"'s single token is spent; "a" is now most recent

    # A third distinct key evicts only the least-recently-used bucket ("b"), never "a".
    assert limiter.allow("c") is True
    assert len(limiter) == 2
    assert "b" not in limiter
    assert limiter.allow("a") is False  # "a" kept its spent bucket: no free reset


def test_per_client_rate_limiter_rejects_non_positive_max_keys() -> None:
    with pytest.raises(ValueError):
        PerClientRateLimiter(rate=1.0, max_keys=0)


def test_per_client_limiter_eviction_does_not_reset_throttled_key() -> None:
    max_keys = 10_000
    rate = 1.0 / 3600  # no measurable refill during the test
    limiter = PerClientRateLimiter(rate=rate, burst=1.0, max_keys=max_keys)

    # 1) The attacker keeps hammering while flooding the map with max_keys other keys: every
    #    refused request marks "A" as recently used, so it is never evicted and stays throttled.
    assert limiter.allow("A") is True
    assert limiter.allow("A") is False
    for i in range(max_keys):
        limiter.allow(f"flood-{i}")
        assert len(limiter) <= max_keys
        if i % 100 == 0:
            assert limiter.allow("A") is False
    assert "A" in limiter
    assert limiter.allow("A") is False

    # 2) If "A" goes quiet, it is evicted only once it is the least-recently-used key, and the
    #    flood evicts strictly oldest-first.
    quiet = PerClientRateLimiter(rate=rate, burst=1.0, max_keys=max_keys)
    assert quiet.allow("A") is True
    assert quiet.allow("A") is False
    for i in range(max_keys - 1):
        quiet.allow(f"old-{i}")
    assert len(quiet) == max_keys and "A" in quiet
    quiet.allow("new-0")  # the map is full: the LRU key ("A") goes first
    assert "A" not in quiet and "old-0" in quiet
    quiet.allow("new-1")
    assert "old-0" not in quiet and "old-1" in quiet  # then the next oldest, and so on
    assert len(quiet) == max_keys
