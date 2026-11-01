from __future__ import annotations

import httpx

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.ip_info import ip_info
from fakes.fake_api import (
    all_not_implemented_api,
    ip_info_payload,
    json_handler,
    make_client,
    problem_payload,
)


async def test_ip_info_tool() -> None:
    payload = ip_info_payload(ip="203.0.113.9")
    api = make_client(
        {("GET", "/v1/tools/ip-info"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await ip_info(client, "203.0.113.9")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["ip"] == "203.0.113.9"
    assert result.result["reverse_dns"] == "9.113.0.203.in-addr.arpa"
    assert result.report_url == "https://adminkit.net/tools/"


async def test_ip_info_tool_calls_correct_path_with_ip_param() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["ip"] = request.url.params["ip"]
        return httpx.Response(200, json=ip_info_payload())

    api = make_client({("GET", "/v1/tools/ip-info"): handler}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        await ip_info(client, "198.51.100.7")
    finally:
        await client.aclose()
    assert seen["path"] == "/v1/tools/ip-info"
    assert seen["ip"] == "198.51.100.7"


async def test_ip_info_tool_invalid_ip_is_honest_error() -> None:
    api = make_client(
        {
            ("GET", "/v1/tools/ip-info"): json_handler(
                422, problem_payload(detail="'not-an-ip' is not a valid IP address.")
            )
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await ip_info(client, "not-an-ip")
    finally:
        await client.aclose()
    assert result.status == "error"
    assert "not a valid IP address" in result.result["message"]
