"""A tiny async token bucket, used to rate-limit every outbound call this server makes."""

from __future__ import annotations

import asyncio
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

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated_at
                self._updated_at = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_for = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait_for)
