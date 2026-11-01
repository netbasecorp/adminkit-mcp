from __future__ import annotations

import httpx

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.mac_vendor import mac_vendor
from fakes.fake_api import (
    all_not_implemented_api,
    json_handler,
    mac_vendor_payload,
    make_client,
    problem_payload,
)


async def test_mac_vendor_tool() -> None:
    payload = mac_vendor_payload(mac="AA:BB:CC:DD:EE:FF", found=True, organization="Example Networks Inc.")
    api = make_client(
        {("GET", "/v1/tools/mac-vendor"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await mac_vendor(client, "AA:BB:CC:DD:EE:FF")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["found"] is True
    assert result.result["organization"] == "Example Networks Inc."
    assert result.report_url == "https://adminkit.net/tools/mac-lookup/"


async def test_mac_vendor_tool_unknown_oui_is_honest_not_found() -> None:
    payload = mac_vendor_payload(mac="FF:FF:FF:01:02:03", found=False)
    api = make_client(
        {("GET", "/v1/tools/mac-vendor"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await mac_vendor(client, "FF:FF:FF:01:02:03")
    finally:
        await client.aclose()
    assert result.status == "ok"  # the lookup itself succeeded; it's the answer that is "not found"
    assert result.result["found"] is False
    assert result.result["organization"] is None
    assert result.result["matched_prefix"] is None


async def test_mac_vendor_tool_calls_correct_path_with_mac_param() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["mac"] = request.url.params["mac"]
        return httpx.Response(200, json=mac_vendor_payload())

    api = make_client({("GET", "/v1/tools/mac-vendor"): handler}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        await mac_vendor(client, "AA:BB:CC")
    finally:
        await client.aclose()
    assert seen["path"] == "/v1/tools/mac-vendor"
    assert seen["mac"] == "AA:BB:CC"


async def test_mac_vendor_tool_invalid_mac_is_honest_error() -> None:
    api = make_client(
        {
            ("GET", "/v1/tools/mac-vendor"): json_handler(
                422, problem_payload(detail="'nope' is not a valid MAC-48 address or OUI prefix.")
            )
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await mac_vendor(client, "nope")
    finally:
        await client.aclose()
    assert result.status == "error"
    assert "not a valid MAC-48" in result.result["message"]
