from __future__ import annotations

import httpx

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.ipv6_info import ipv6_info
from fakes.fake_api import (
    all_not_implemented_api,
    ipv6_info_payload,
    json_handler,
    make_client,
    problem_payload,
)


async def test_ipv6_info_tool() -> None:
    payload = ipv6_info_payload(ip="2001:db8::1")
    api = make_client(
        {("GET", "/v1/tools/ipv6-info"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await ipv6_info(client, "2001:db8::1")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["network_64"] == "2001:db8::/64"
    assert result.result["embedded_ipv4"] is None
    assert result.report_url == "https://adminkit.net/tools/"


async def test_ipv6_info_tool_surfaces_embedded_ipv4() -> None:
    payload = ipv6_info_payload(
        ip="::ffff:203.0.113.9", embedded_ipv4="203.0.113.9", embedded_ipv4_kind="ipv4-mapped"
    )
    api = make_client(
        {("GET", "/v1/tools/ipv6-info"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await ipv6_info(client, "::ffff:203.0.113.9")
    finally:
        await client.aclose()
    assert result.result["embedded_ipv4"] == "203.0.113.9"
    assert result.result["embedded_ipv4_kind"] == "ipv4-mapped"


async def test_ipv6_info_tool_calls_correct_path_with_ip_param() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["ip"] = request.url.params["ip"]
        return httpx.Response(200, json=ipv6_info_payload())

    api = make_client({("GET", "/v1/tools/ipv6-info"): handler}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        await ipv6_info(client, "2001:db8::1")
    finally:
        await client.aclose()
    assert seen["path"] == "/v1/tools/ipv6-info"
    assert seen["ip"] == "2001:db8::1"


async def test_ipv6_info_tool_ipv4_input_is_honest_error() -> None:
    problem = problem_payload(detail="'203.0.113.9' is an IPv4 address; use /v1/tools/ip-info instead.")
    api = make_client(
        {("GET", "/v1/tools/ipv6-info"): json_handler(422, problem)},
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await ipv6_info(client, "203.0.113.9")
    finally:
        await client.aclose()
    assert result.status == "error"
    assert "ip-info" in result.result["message"]
