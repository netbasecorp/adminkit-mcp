from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.check_ip import check_ip
from fakes.fake_api import (
    all_not_implemented_api,
    check_result_payload,
    ip_payload,
    json_handler,
    make_client,
)


async def test_check_ip_uses_live_api_when_available() -> None:
    payload = check_result_payload(check="my-ip", target="self", status="ok")
    api = make_client(
        {("GET", "/v1/check/my-ip"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_ip(client)
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["check"] == "my-ip"


async def test_check_ip_falls_back_to_site_on_501() -> None:
    api = all_not_implemented_api()
    site = make_client({("GET", "/api/ip"): json_handler(200, ip_payload())}, base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_ip(client)
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["ip"] == "203.0.113.5"
    assert result.report_url == "https://adminkit.net/tools/my-ip/"


async def test_check_ip_falls_back_to_site_on_404() -> None:
    api = make_client({}, base_url="https://api.adminkit.net")  # unmatched routes -> 404
    site = make_client({("GET", "/api/ip"): json_handler(200, ip_payload())}, base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_ip(client)
    finally:
        await client.aclose()
    assert result.status == "ok"


async def test_check_ip_cgnat_hint_surfaces_as_fix_hint() -> None:
    api = all_not_implemented_api()
    site = make_client(
        {("GET", "/api/ip"): json_handler(200, ip_payload(cgnat_hint=True))}, base_url="https://adminkit.net"
    )
    client = AdminKitClient(api, site)
    try:
        result = await check_ip(client)
    finally:
        await client.aclose()
    assert result.result["cgnat_hint"] is True
    assert result.fix_hint is not None and "shared" in result.fix_hint.lower()


async def test_check_ip_with_explicit_ip_is_not_available() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_ip(client, "198.51.100.7")
    finally:
        await client.aclose()
    assert result.status == "not_available"
    assert "198.51.100.7" not in result.result["message"]  # never echoes an unsupported lookup as if done

