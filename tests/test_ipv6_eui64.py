from __future__ import annotations

from typing import Any

import httpx
import pytest

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.ipv6_eui64 import MAX_MAC_LENGTH, MAX_PREFIX_LENGTH, ipv6_eui64
from fakes.fake_api import (
    all_not_implemented_api,
    ipv6_eui64_payload,
    json_handler,
    make_client,
    make_recording_client,
    problem_payload,
)

API_BASE = "https://api.adminkit.net"
SITE_BASE = "https://adminkit.net"


async def test_ipv6_eui64_tool() -> None:
    api = make_client(
        {("GET", "/v1/tools/ipv6-eui64"): json_handler(200, ipv6_eui64_payload())}, base_url=API_BASE
    )
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await ipv6_eui64(client, "2001:db8::/64", "00:1A:2B:3C:4D:5E")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["interface_id"] == "021a:2bff:fe3c:4d5e"
    assert result.result["address"] == "2001:db8::21a:2bff:fe3c:4d5e"
    assert result.result["exploded"] == "2001:0db8:0000:0000:021a:2bff:fe3c:4d5e"
    assert result.evidence == ipv6_eui64_payload()
    assert result.report_url == "https://adminkit.net/tools/ipv6-info/?utm_source=mcp"


async def test_ipv6_eui64_tool_calls_correct_path_with_params() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["prefix"] = request.url.params["prefix"]
        seen["mac"] = request.url.params["mac"]
        return httpx.Response(200, json=ipv6_eui64_payload())

    api = make_client({("GET", "/v1/tools/ipv6-eui64"): handler}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        await ipv6_eui64(client, "2001:db8:1::/48", "00-1A-2B-3C-4D-5E")
    finally:
        await client.aclose()
    assert seen == {"path": "/v1/tools/ipv6-eui64", "prefix": "2001:db8:1::/48", "mac": "00-1A-2B-3C-4D-5E"}


async def test_ipv6_eui64_tool_prefix_too_long_is_explicit_error() -> None:
    problem = problem_payload(
        detail="prefix length /96 leaves less than 64 bits of interface space; "
        "a 64-bit EUI-64 identifier needs a prefix of /64 or shorter."
    )
    api = make_client({("GET", "/v1/tools/ipv6-eui64"): json_handler(422, problem)}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await ipv6_eui64(client, "2001:db8::/96", "00:1A:2B:3C:4D:5E")
    finally:
        await client.aclose()
    assert result.status == "error"
    assert "/64 or shorter" in result.result["message"]
    assert result.report_url == "https://adminkit.net/tools/ipv6-info/?utm_source=mcp"


async def test_ipv6_eui64_tool_api_429_is_rate_limited_envelope_without_retry() -> None:
    calls: list[str] = []
    api = make_recording_client(
        calls,
        {("GET", "/v1/tools/ipv6-eui64"): lambda _r: httpx.Response(429)},
        base_url=API_BASE,
    )
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await ipv6_eui64(client, "2001:db8::/64", "00:1A:2B:3C:4D:5E")
    finally:
        await client.aclose()
    assert calls == ["GET /v1/tools/ipv6-eui64"]
    assert result.status == "error"
    assert result.result["rate_limited"] is True
    assert result.result["retry_after_seconds"] is None
    assert "retry in" not in result.result["message"]


@pytest.mark.parametrize(
    ("prefix", "mac", "message"),
    [
        ("", "00:1A:2B:3C:4D:5E", "prefix must not be empty."),
        ("2001:db8::/64", " ", "mac must not be empty."),
        (
            "a" * (MAX_PREFIX_LENGTH + 1),
            "00:1A:2B:3C:4D:5E",
            f"prefix must be at most {MAX_PREFIX_LENGTH} characters.",
        ),
        ("2001:db8::/64", "0" * (MAX_MAC_LENGTH + 1), f"mac must be at most {MAX_MAC_LENGTH} characters."),
    ],
)
async def test_ipv6_eui64_tool_rejects_bad_input_without_a_request(
    prefix: str, mac: str, message: str
) -> None:
    calls: list[str] = []
    routes: dict[Any, Any] = {}
    api = make_recording_client(calls, routes, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await ipv6_eui64(client, prefix, mac)
    finally:
        await client.aclose()
    assert calls == []
    assert result.status == "error"
    assert result.result == {"message": message}
