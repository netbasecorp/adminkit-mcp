from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.check_owned_ports import check_owned_ports
from fakes.fake_api import all_not_implemented_api, check_result_payload, json_handler, make_client


async def test_check_owned_ports_not_available_yet() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_owned_ports(client, "verified-asset.example.com")
    finally:
        await client.aclose()
    assert result.status == "not_available"
    assert result.report_url == "https://adminkit.net/tools/port-check/"


async def test_check_owned_ports_uses_live_api_when_available() -> None:
    api = make_client(
        {
            ("POST", "/v1/check/ports"): json_handler(
                200,
                check_result_payload(
                    check="ports",
                    target="verified-asset.example.com",
                    status="warn",
                    findings=[{"fix_hint": "Close Telnet (23) on this host."}],
                ),
            )
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_owned_ports(client, "verified-asset.example.com")
    finally:
        await client.aclose()
    assert result.status == "warn"
    assert result.fix_hint == "Close Telnet (23) on this host."
