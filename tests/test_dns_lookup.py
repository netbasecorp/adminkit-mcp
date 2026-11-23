from __future__ import annotations

import json

import httpx

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.server import build_server
from adminkit_mcp.tools.dns_lookup import ALLOWED_TYPES, dns_lookup
from fakes.fake_api import (
    all_not_implemented_api,
    check_result_payload,
    dns_payload,
    json_handler,
    make_client,
)


async def test_dns_lookup_uses_live_api_when_available() -> None:
    payload = check_result_payload(check="dns.lookup", target="example.com")
    api = make_client(
        {("POST", "/v1/check/dns"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
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


async def test_dns_lookup_accepts_srv_sshfp_tlsa_and_sends_types_option() -> None:
    import json

    import httpx

    seen: list[dict[str, object]] = []
    payload = check_result_payload(check="dns.lookup", target="_443._tcp.example.com")

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=payload)

    api = make_client({("POST", "/v1/check/dns"): record}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        results = [
            await dns_lookup(client, "_443._tcp.example.com", rtype) for rtype in ("srv", "SSHFP", "TLSA")
        ]
    finally:
        await client.aclose()
    assert [r.status for r in results] == ["ok", "ok", "ok"]
    assert [body["options"] for body in seen] == [
        {"types": ["SRV"]},
        {"types": ["SSHFP"]},
        {"types": ["TLSA"]},
    ]


async def test_dns_lookup_site_fallback_for_tlsa() -> None:
    api = all_not_implemented_api()
    answers = [{"name": "_443._tcp.example.com", "type": "TLSA", "ttl": 300, "data": "3 1 1 ab12"}]
    site = make_client(
        {
            ("GET", "/api/dns"): json_handler(
                200, dns_payload(name="_443._tcp.example.com", type_="TLSA", answers=answers)
            )
        },
        base_url="https://adminkit.net",
    )
    client = AdminKitClient(api, site)
    try:
        result = await dns_lookup(client, "_443._tcp.example.com", "TLSA")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["type"] == "TLSA"
    assert result.result["answers"] == answers


async def test_dns_lookup_still_rejects_any_and_axfr() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        results = [await dns_lookup(client, "example.com", rtype) for rtype in ("ANY", "axfr", "IXFR")]
    finally:
        await client.aclose()
    assert all(r.status == "error" for r in results)
    assert all("type must be one of" in r.result["message"] for r in results)


async def test_dns_lookup_tool_description_lists_all_12_types() -> None:
    client = AdminKitClient(
        all_not_implemented_api(), all_not_implemented_api(base_url="https://adminkit.net")
    )
    try:
        tools = {tool.name: tool for tool in await build_server(client).list_tools()}
    finally:
        await client.aclose()
    description = tools["dns_lookup"].description or ""
    listed = description.split("`type` is one of ", 1)[1].split(".", 1)[0]
    assert {t.strip() for t in listed.replace("\n", " ").split(",")} == ALLOWED_TYPES
    assert len(ALLOWED_TYPES) == 12


async def test_dns_lookup_tool_tlsa_on_underscore_owner_name_round_trips() -> None:
    seen: list[dict[str, object]] = []
    payload = check_result_payload(check="dns.lookup", target="_443._tcp.example.com")

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=payload)

    api = make_client({("POST", "/v1/check/dns"): record}, base_url="https://api.adminkit.net")
    client = AdminKitClient(api, all_not_implemented_api(base_url="https://adminkit.net"))
    try:
        _, structured = await build_server(client).call_tool(
            "dns_lookup", {"name": "_443._tcp.example.com", "type": "TLSA"}
        )
    finally:
        await client.aclose()
    assert isinstance(structured, dict)
    assert structured["status"] == "ok"
    assert seen == [{"target": "_443._tcp.example.com", "options": {"types": ["TLSA"]}}]
