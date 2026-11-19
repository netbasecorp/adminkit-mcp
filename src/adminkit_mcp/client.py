"""Thin HTTP client over the live AdminKit Check API, with a resilience fallback to the
live site Pages Functions for when a route is unreachable (spec section 6.1, job brief).
The API key, when set, is attached as a header and never logged or echoed back in any
tool output.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from types import TracebackType
from typing import Any, Self

import httpx

from adminkit_mcp import __version__
from adminkit_mcp.config import Settings
from adminkit_mcp.ratelimit import RateLimiter

API_KEY_HEADER = "X-API-Key"
USER_AGENT = f"adminkit-mcp/{__version__}"


class ApiUnavailable(Exception):
    """Raised when the Check API returns 404/501 for a route: not shipped yet (e.g. `dnsbl`),
    or a live route that is temporarily unreachable."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        super().__init__(f"AdminKit API returned {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class ApiRateLimited(httpx.HTTPStatusError):
    """Raised on HTTP 429 from the Check API or the fallback site. Subclasses
    `httpx.HTTPStatusError`, so existing `except httpx.HTTPStatusError` handlers keep working.

    `retry_after_seconds` is the wait the server announced (see `retry_after_seconds()` for the
    precedence), or None when it did not say. The client never sleeps or retries on its own;
    the caller decides whether to wait.
    """

    def __init__(self, response: httpx.Response) -> None:
        self.retry_after_seconds = retry_after_seconds(response)
        self.detail = problem_detail(response)
        super().__init__(
            rate_limited_message(self.retry_after_seconds), request=response.request, response=response
        )

    @property
    def message(self) -> str:
        return rate_limited_message(self.retry_after_seconds)


def rate_limited_message(seconds: int | None) -> str:
    """The text every tool uses for a 429: says it was rate limited and, when known, the wait."""
    if seconds is None:
        return "Rate limited by the AdminKit API (HTTP 429); no retry time was given, retry later."
    return f"Rate limited by the AdminKit API (HTTP 429); retry in {seconds} s."


def retry_after_seconds(response: httpx.Response, *, now: datetime | None = None) -> int | None:
    """The wait a 429 response announces, in whole seconds, or None when it says nothing usable.

    Precedence: `Retry-After` header (delta-seconds or an HTTP-date) -> problem body
    `retry_after_seconds` -> `RateLimit-Reset` header (delta-seconds) -> None. Never invents a
    wait: an unparsable value falls through to the next source.
    """
    header = _retry_after_header(response.headers.get("Retry-After"), now=now)
    if header is not None:
        return header
    body = _body_retry_after(response)
    if body is not None:
        return body
    return _delta_seconds(response.headers.get("RateLimit-Reset"))


def _delta_seconds(raw: str | None) -> int | None:
    if raw is None:
        return None
    value = raw.strip()
    return int(value) if value.isascii() and value.isdigit() else None


def _retry_after_header(raw: str | None, *, now: datetime | None) -> int | None:
    if raw is None:
        return None
    delta = _delta_seconds(raw)
    if delta is not None:
        return delta
    try:
        when = parsedate_to_datetime(raw.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    remaining = (when - (now or datetime.now(UTC))).total_seconds()
    return max(0, math.ceil(remaining))


def _body_retry_after(response: httpx.Response) -> int | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    value = payload.get("retry_after_seconds")
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return math.ceil(value)


def problem_detail(response: httpx.Response) -> str | None:
    """The RFC 9457 problem `detail` (or `title`) of an error response, if it has one."""
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail") or payload.get("title")
    return str(detail) if detail else None


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
        rate_limiter = RateLimiter(rate=settings.rate_limit_per_second, burst=settings.rate_limit_per_second)
        return cls(api_client, site_client, rate_limiter=rate_limiter)

    @property
    def has_api_key(self) -> bool:
        """Whether an `X-API-Key` is attached to API calls (never exposes the key itself), so
        keyed tools can refuse up front instead of sending an anonymous request."""
        return bool(self._api_client.headers.get(API_KEY_HEADER))

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
        """Call `/v1/...` on the Check API. Raises `ApiUnavailable` on 404/501 and
        `ApiRateLimited` on 429 (never retried automatically)."""
        await self._rate_limiter.acquire()
        response = await self._api_client.request(method, path, **kwargs)
        if response.status_code in (404, 501):
            raise ApiUnavailable(response.status_code, response.text[:200])
        if response.status_code == 429:
            raise ApiRateLimited(response)
        response.raise_for_status()
        return response

    async def call_site(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        """Call the fallback live site function (`https://adminkit.net/api/...`)."""
        await self._rate_limiter.acquire()
        response = await self._site_client.get(path, params=params)
        if response.status_code == 429:
            raise ApiRateLimited(response)
        response.raise_for_status()
        return response
