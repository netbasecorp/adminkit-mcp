from __future__ import annotations

from typing import Any

import httpx
import pytest

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.ip_in_cidr import MAX_CIDR_LENGTH, MAX_IP_LENGTH, ip_in_cidr
from fakes.fake_api import (
    all_not_implemented_api,
    ip_in_cidr_payload,
    json_handler,
    make_client,
    make_recording_client,
    problem_payload,
)

API_BASE = "https://api.adminkit.net"
SITE_BASE = "https://adminkit.net"


async def test_ip_in_cidr_tool() -> None:
    api = make_client(
        {("GET", "/v1/tools/ip-in-cidr"): json_handler(200, ip_in_cidr_payload())}, base_url=API_BASE
    )
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await ip_in_cidr(client, "192.0.2.10", "192.0.2.0/24")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result == {
        "ip": "192.0.2.10",
        "cidr": "192.0.2.0/24",
        "contains": True,
        "network": "192.0.2.0/24",
    }
    assert result.evidence == ip_in_cidr_payload()
    assert result.report_url == "https://adminkit.net/tools/ip-in-cidr/?utm_source=mcp"


async def test_ip_in_cidr_tool_not_contained_is_ok_not_error() -> None:
    payload = ip_in_cidr_payload(ip="198.51.100.1", contains=False)
    api = make_client({("GET", "/v1/tools/ip-in-cidr"): json_handler(200, payload)}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await ip_in_cidr(client, "198.51.100.1", "192.0.2.0/24")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["contains"] is False


async def test_ip_in_cidr_tool_calls_correct_path_with_params() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["ip"] = request.url.params["ip"]
        seen["cidr"] = request.url.params["cidr"]
        return httpx.Response(200, json=ip_in_cidr_payload())

    api = make_client({("GET", "/v1/tools/ip-in-cidr"): handler}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        await ip_in_cidr(client, "2001:db8::1", "2001:db8::/32")
    finally:
        await client.aclose()
    assert seen == {"path": "/v1/tools/ip-in-cidr", "ip": "2001:db8::1", "cidr": "2001:db8::/32"}


async def test_ip_in_cidr_tool_api_422_is_explicit_error() -> None:
    problem = problem_payload(detail="'not-a-cidr' is not a valid CIDR network.")
    api = make_client({("GET", "/v1/tools/ip-in-cidr"): json_handler(422, problem)}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await ip_in_cidr(client, "192.0.2.10", "not-a-cidr")
    finally:
        await client.aclose()
    assert result.status == "error"
    assert result.result == {"message": "'not-a-cidr' is not a valid CIDR network."}
    assert result.report_url == "https://adminkit.net/tools/ip-in-cidr/?utm_source=mcp"


async def test_ip_in_cidr_tool_api_429_is_rate_limited_envelope_without_retry() -> None:
    calls: list[str] = []
    api = make_recording_client(
        calls,
        {
            ("GET", "/v1/tools/ip-in-cidr"): lambda _r: httpx.Response(
                429,
                json=problem_payload(status=429, detail="Rate limit exceeded."),
                headers={"Retry-After": "6"},
            )
        },
        base_url=API_BASE,
    )
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await ip_in_cidr(client, "192.0.2.10", "192.0.2.0/24")
    finally:
        await client.aclose()
    assert calls == ["GET /v1/tools/ip-in-cidr"]
    assert result.status == "error"
    assert result.result["rate_limited"] is True
    assert result.result["retry_after_seconds"] == 6
    assert "retry in 6 s" in result.result["message"]
    assert result.fix_hint is not None and "6 s" in result.fix_hint


@pytest.mark.parametrize(
    ("ip", "cidr", "message"),
    [
        ("", "192.0.2.0/24", "ip must not be empty."),
        ("   ", "192.0.2.0/24", "ip must not be empty."),
        ("192.0.2.10", "", "cidr must not be empty."),
        ("1" * (MAX_IP_LENGTH + 1), "192.0.2.0/24", f"ip must be at most {MAX_IP_LENGTH} characters."),
        ("192.0.2.10", "1" * (MAX_CIDR_LENGTH + 1), f"cidr must be at most {MAX_CIDR_LENGTH} characters."),
    ],
)
async def test_ip_in_cidr_tool_rejects_bad_input_without_a_request(ip: str, cidr: str, message: str) -> None:
    calls: list[str] = []
    routes: dict[Any, Any] = {}
    api = make_recording_client(calls, routes, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await ip_in_cidr(client, ip, cidr)
    finally:
        await client.aclose()
    assert calls == []
    assert result.status == "error"
    assert result.result == {"message": message}
