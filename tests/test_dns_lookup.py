from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.dns_lookup import dns_lookup
from fakes.fake_api import (
    all_not_implemented_api,
    check_result_payload,
    dns_payload,
    json_handler,
    make_client,
)


async def test_dns_lookup_uses_live_api_when_available() -> None:
    payload = check_result_payload(check="dns.lookup", target="example.com")
    api = make_client({("POST", "/v1/check/dns"): json_handler(200, payload)}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await dns_lookup(client, "example.com", "A")
    finally:
        await client.aclose()
    assert result.status == "ok"


async def test_dns_lookup_falls_back_to_site() -> None:
    api = all_not_implemented_api()
    answers = [{"name": "example.com", "type": "A", "ttl": 300, "data": "93.184.216.34"}]
    site = make_client(
        {("GET", "/api/dns"): json_handler(200, dns_payload(name="example.com", type_="A", answers=answers))},
        base_url="https://adminkit.net",
    )
    client = AdminKitClient(api, site)
    try:
        result = await dns_lookup(client, "example.com", "A")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["answers"] == answers


async def test_dns_lookup_rejects_disallowed_type() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await dns_lookup(client, "example.com", "ANY")
    finally:
        await client.aclose()
    assert result.status == "error"
    assert "type must be one of" in result.result["message"]


async def test_dns_lookup_normalizes_type_case() -> None:
    api = all_not_implemented_api()
    site = make_client(
        {("GET", "/api/dns"): json_handler(200, dns_payload(name="example.com", type_="MX"))},
        base_url="https://adminkit.net",
    )
    client = AdminKitClient(api, site)
    try:
        result = await dns_lookup(client, "example.com", "mx")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["type"] == "MX"


async def test_dns_lookup_site_error_status_maps_to_error() -> None:
    api = all_not_implemented_api()
    site = make_client(
        {
            ("GET", "/api/dns"): json_handler(
                200, dns_payload(name="bad..name", type_="A", status="invalid-name")
            )
        },
        base_url="https://adminkit.net",
    )
    client = AdminKitClient(api, site)
    try:
        result = await dns_lookup(client, "bad..name", "A")
    finally:
        await client.aclose()
    assert result.status == "error"
