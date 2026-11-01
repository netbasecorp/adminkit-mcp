"""Thin HTTP client over the live AdminKit Check API, with a resilience fallback to the
live site Pages Functions for when a route is unreachable (spec section 6.1, job brief).
The API key, when set, is attached as a header and never logged or echoed back in any
tool output.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any, Self

import httpx

from adminkit_mcp.config import Settings
from adminkit_mcp.ratelimit import RateLimiter

API_KEY_HEADER = "X-API-Key"
USER_AGENT = "adminkit-mcp/0.1.0"


class ApiUnavailable(Exception):
    """Raised when the Check API returns 404/501 for a route: not shipped yet (e.g. `dnsbl`),
    or a live route that is temporarily unreachable."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        super().__init__(f"AdminKit API returned {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class AdminKitClient:
    """Owns the two httpx clients (API, fallback site) and a shared rate limiter.

    Tests inject their own `httpx.AsyncClient` instances (built with a `MockTransport`)
    instead of calling `from_settings`, so no real network call is ever reachable.
    """

    def __init__(
        self,
        api_client: httpx.AsyncClient,
        site_client: httpx.AsyncClient,
        *,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._api_client = api_client
        self._site_client = site_client
        self._rate_limiter = rate_limiter or RateLimiter(rate=5.0, burst=5.0)

    @classmethod
    def from_settings(cls, settings: Settings) -> Self:
        headers = {"User-Agent": USER_AGENT}
        if settings.api_key:
            headers[API_KEY_HEADER] = settings.api_key
        api_client = httpx.AsyncClient(
            base_url=settings.api_base, headers=headers, timeout=settings.timeout_seconds
        )
        site_client = httpx.AsyncClient(
            base_url=settings.site_base,
            headers={"User-Agent": USER_AGENT},
            timeout=settings.timeout_seconds,
        )
        rate_limiter = RateLimiter(
            rate=settings.rate_limit_per_second, burst=settings.rate_limit_per_second
        )
        return cls(api_client, site_client, rate_limiter=rate_limiter)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._api_client.aclose()
        await self._site_client.aclose()

    async def call_api(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Call `/v1/...` on the Check API. Raises `ApiUnavailable` on 404/501."""
        await self._rate_limiter.acquire()
        response = await self._api_client.request(method, path, **kwargs)
        if response.status_code in (404, 501):
            raise ApiUnavailable(response.status_code, response.text[:200])
        response.raise_for_status()
        return response

    async def call_site(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        """Call the fallback live site function (`https://adminkit.net/api/...`)."""
        await self._rate_limiter.acquire()
        response = await self._site_client.get(path, params=params)
        response.raise_for_status()
        return response
