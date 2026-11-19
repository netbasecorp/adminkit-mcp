"""API 429 -> "rate limited, retry in N s" tool results, and the hosted endpoint's own
`Retry-After` on its 429. All HTTP is mocked (`httpx.MockTransport` / `httpx.ASGITransport`);
no socket is opened and nothing is retried or slept on."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from starlette.types import Receive, Scope, Send

from adminkit_mcp.client import AdminKitClient, ApiRateLimited, retry_after_seconds
from adminkit_mcp.hosted import ClientRateLimitMiddleware
from adminkit_mcp.ratelimit import PerClientRateLimiter
from adminkit_mcp.server import build_server
from adminkit_mcp.tools.explain_report import explain_report
from adminkit_mcp.tools.list_assets import list_assets
from adminkit_mcp.tools.subnet_calc import subnet_calc
from fakes.fake_api import (
    all_not_implemented_api,
    check_result_payload,
    json_handler,
    make_client,
    make_recording_client,
    problem_payload,
)

FAKE_KEY = "ak_test_FAKE_PLACEHOLDER"
API_BASE = "https://api.adminkit.net"
SITE_BASE = "https://adminkit.net"


def _problem_429(
    *, retry_after_seconds: int | None = None, detail: str = "Rate limit exceeded."
) -> dict[str, Any]:
    body = problem_payload(status=429, title="Too Many Requests", detail=detail)
    if retry_after_seconds is not None:
        body["retry_after_seconds"] = retry_after_seconds
    return body


def _handler_429(body: dict[str, Any] | None, headers: dict[str, str] | None = None) -> Any:
    def handler(_request: httpx.Request) -> httpx.Response:
        if body is None:
            return httpx.Response(429, headers=headers)
        return httpx.Response(429, json=body, headers=headers)

    return handler


def _response(body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("GET", f"{API_BASE}/v1/check/x")
    if body is None:
        return httpx.Response(429, headers=headers, request=request)
    return httpx.Response(429, json=body, headers=headers, request=request)


# --- precedence: Retry-After header -> body retry_after_seconds -> RateLimit-Reset -> none ---


def test_retry_after_header_delta_seconds_wins_over_body_and_reset() -> None:
    resp = _response(_problem_429(retry_after_seconds=30), {"Retry-After": "7", "RateLimit-Reset": "50"})
    assert retry_after_seconds(resp) == 7


def test_retry_after_header_http_date_is_accepted() -> None:
    now = datetime(2026, 11, 19, 10, 0, 0, tzinfo=UTC)
    resp = _response(_problem_429(retry_after_seconds=30), {"Retry-After": "Thu, 19 Nov 2026 10:00:12 GMT"})
    assert retry_after_seconds(resp, now=now) == 12


def test_retry_after_http_date_in_the_past_is_zero_not_negative() -> None:
    now = datetime(2026, 11, 19, 10, 0, 0, tzinfo=UTC)
    resp = _response(None, {"Retry-After": "Thu, 19 Nov 2026 09:59:00 GMT"})
    assert retry_after_seconds(resp, now=now) == 0


def test_unparsable_retry_after_falls_through_to_body() -> None:
    resp = _response(_problem_429(retry_after_seconds=30), {"Retry-After": "soon", "RateLimit-Reset": "50"})
    assert retry_after_seconds(resp) == 30


def test_body_wins_over_ratelimit_reset() -> None:
    resp = _response(_problem_429(retry_after_seconds=30), {"RateLimit-Reset": "50"})
    assert retry_after_seconds(resp) == 30


def test_ratelimit_reset_used_when_nothing_else() -> None:
    resp = _response(_problem_429(), {"RateLimit-Reset": "50"})
    assert retry_after_seconds(resp) == 50


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        (None, None),
        (_problem_429(), None),
        ({"retry_after_seconds": "12"}, None),
        ({"retry_after_seconds": True}, None),
        ({"retry_after_seconds": -3}, {"RateLimit-Reset": "-1"}),
    ],
)
def test_no_usable_wait_is_none_never_invented(
    body: dict[str, Any] | None, headers: dict[str, str] | None
) -> None:
    assert retry_after_seconds(_response(body, headers)) is None


# --- tool results ---


async def _check_domain_with(handler: Any) -> dict[str, Any]:
    """Calls `check_domain` through FastMCP, i.e. the tool result an MCP client actually gets."""
    api = make_client({("POST", "/v1/check/whois"): handler}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    mcp = build_server(client)
    try:
        content, structured = await mcp.call_tool("check_domain", {"domain": "example.com"})
    finally:
        await client.aclose()
    assert isinstance(structured, dict)
    assert structured["tool"] == "check_domain"
    assert structured["result"]["message"] in str(content)  # the text block says the same
    return structured


async def test_api_429_with_header_tool_text_says_retry_in_n_s() -> None:
    out = await _check_domain_with(_handler_429(_problem_429(retry_after_seconds=9), {"Retry-After": "9"}))
    assert out["status"] == "error"
    assert out["result"]["rate_limited"] is True
    assert out["result"]["retry_after_seconds"] == 9
    assert "rate limited" in out["result"]["message"].lower()
    assert "retry in 9 s" in out["result"]["message"]
    assert "9 s" in out["fix_hint"]


async def test_api_429_body_only_tool_text_uses_body_wait() -> None:
    out = await _check_domain_with(_handler_429(_problem_429(retry_after_seconds=4)))
    assert out["result"]["retry_after_seconds"] == 4
    assert "retry in 4 s" in out["result"]["message"]


async def test_api_429_with_nothing_says_rate_limited_without_a_wait() -> None:
    out = await _check_domain_with(_handler_429(None))
    assert out["status"] == "error"
    assert out["result"]["rate_limited"] is True
    assert out["result"]["retry_after_seconds"] is None
    assert "rate limited" in out["result"]["message"].lower()
    assert "retry in" not in out["result"]["message"]


async def test_api_429_is_not_retried_automatically() -> None:
    calls: list[str] = []
    api = make_recording_client(
        calls,
        {("GET", "/v1/tools/subnet"): _handler_429(_problem_429(), {"Retry-After": "1"})},
        base_url=API_BASE,
    )
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await subnet_calc(client, "192.0.2.0/24")
    finally:
        await client.aclose()
    assert calls == ["GET /v1/tools/subnet"]
    assert result.status == "error"
    assert result.result["message"] == "Rate limited by the AdminKit API (HTTP 429); retry in 1 s."
    assert result.result["detail"] == "Rate limit exceeded."


async def test_api_429_raises_rate_limited_which_is_still_an_http_status_error() -> None:
    api = make_client({("GET", "/v1/x"): _handler_429(None, {"Retry-After": "3"})}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        with pytest.raises(httpx.HTTPStatusError) as info:
            await client.call_api("GET", "/v1/x")
    finally:
        await client.aclose()
    assert isinstance(info.value, ApiRateLimited)
    assert info.value.retry_after_seconds == 3
    assert info.value.response.status_code == 429


async def test_unhandled_429_through_fastmcp_returns_rate_limited_envelope_not_generic_error() -> None:
    api = make_client(
        {("GET", "/v1/check/my-ip"): _handler_429(_problem_429(retry_after_seconds=5), {"Retry-After": "5"})},
        base_url=API_BASE,
    )
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    mcp = build_server(client)
    try:
        content = await mcp.call_tool("check_ip", {})
    finally:
        await client.aclose()
    text = str(content)
    assert "Rate limited by the AdminKit API (HTTP 429); retry in 5 s." in text
    assert "check_ip" in text


async def test_assets_429_keeps_detail_and_appends_wait() -> None:
    api = make_client(
        {("GET", "/v1/assets"): _handler_429(_problem_429(detail="rate-limited"), {"Retry-After": "11"})},
        base_url=API_BASE,
    )
    api.headers["X-API-Key"] = FAKE_KEY
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        out = (await list_assets(client)).to_dict()
    finally:
        await client.aclose()
    assert out["result"]["message"] == "rate-limited Retry in 11 s."
    assert "11 s" in out["fix_hint"]


async def test_explain_429_reports_wait() -> None:
    report = check_result_payload(check="spf", target="example.com")
    api = make_client(
        {
            ("GET", "/v1/report/rpt_01H8"): json_handler(200, report),
            ("POST", "/v1/ai/explain"): _handler_429(_problem_429(retry_after_seconds=60, detail="AI cap.")),
        },
        base_url=API_BASE,
    )
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await explain_report(client, "rpt_01H8")
    finally:
        await client.aclose()
    assert result.result["message"] == "AI cap. Retry in 60 s."
    assert result.result["retry_after_seconds"] == 60


# --- hosted endpoint's own 429 ---


async def _ok_app(scope: Scope, receive: Receive, send: Send) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


@pytest.mark.parametrize(("per_minute", "max_wait"), [(60.0, 1), (30.0, 2), (6.0, 10)])
async def test_hosted_429_has_retry_after_from_limiter(per_minute: float, max_wait: int) -> None:
    app = ClientRateLimitMiddleware(_ok_app, PerClientRateLimiter(rate=per_minute / 60.0, burst=1.0))
    transport = httpx.ASGITransport(app=app, client=("203.0.113.5", 1))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765") as http:
        first = await http.post("/mcp")
        second = await http.post("/mcp")
    assert first.status_code == 200
    assert second.status_code == 429
    retry_after = second.headers["Retry-After"]
    assert retry_after.isdigit()
    assert 1 <= int(retry_after) <= max_wait
    assert second.json()["retry_after_seconds"] == int(retry_after)
    assert second.json()["error"] == "rate_limited"


def test_per_client_retry_after_is_at_least_one_second() -> None:
    limiter = PerClientRateLimiter(rate=1000.0, burst=1.0)
    assert limiter.retry_after("never-seen") == 1
    limiter.allow("a")
    assert limiter.retry_after("a") == 1
