"""A tiny token bucket, used both to rate-limit every outbound call this server makes
(`acquire`, waits its turn) and to rate-limit inbound hosted-HTTP requests per client IP
(`try_acquire`, never waits — a public endpoint must answer 429 immediately, not queue
strangers' requests)."""

from __future__ import annotations

import asyncio
import math
import time


class RateLimiter:
    """Limits callers to `rate` acquisitions per second, with a burst of `burst` tokens."""

    def __init__(self, rate: float, burst: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._rate = rate
        self._capacity = burst if burst is not None else max(1.0, rate)
        self._tokens = self._capacity
        self._updated_at = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated_at
        self._updated_at = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_for = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait_for)

    def try_acquire(self) -> bool:
        """Non-blocking: takes a token and returns True if one is available right now,
        otherwise returns False immediately without consuming one or waiting. Safe to call
        without the asyncio lock: single-threaded cooperative code never context-switches
        between `_refill()` and the token check below."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def seconds_until_available(self) -> float:
        """Seconds until one token is available (0.0 if one is available now). Read-only:
        consumes nothing."""
        self._refill()
        if self._tokens >= 1.0:
            return 0.0
        return (1.0 - self._tokens) / self._rate


class PerClientRateLimiter:
    """One independent `RateLimiter` token bucket per key (typically a client IP), so a
    public hosted endpoint throttles each caller separately instead of sharing one global
    budget a single noisy client could exhaust for everyone else.

    `max_keys` bounds memory on a long-running hosted process: once the bucket dict would
    grow past it, it is cleared outright (a crude but safe eviction — a client that loses
    its accumulated tokens this way simply gets a fresh, full bucket, never a 429 it didn't
    earn)."""

    def __init__(self, rate: float, burst: float | None = None, *, max_keys: int = 10_000) -> None:
        self._rate = rate
        self._burst = burst
        self._max_keys = max_keys
        self._buckets: dict[str, RateLimiter] = {}

    def allow(self, key: str) -> bool:
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self._max_keys:
                self._buckets.clear()
            bucket = RateLimiter(self._rate, self._burst)
            self._buckets[key] = bucket
        return bucket.try_acquire()

    def retry_after(self, key: str) -> int:
        """Whole seconds (>= 1) until `key` may send another request, for an HTTP `Retry-After`
        header on the 429 `allow` just answered. Rounded up so a client that waits exactly this
        long is not refused again; an unknown key (bucket evicted meanwhile) gets the minimum 1."""
        bucket = self._buckets.get(key)
        wait = bucket.seconds_until_available() if bucket is not None else 0.0
        return max(1, math.ceil(wait))
