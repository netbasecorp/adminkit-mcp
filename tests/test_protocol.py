"""In-process MCP protocol test: the server lists all 8 spec section 18.8 tools plus the 5
offline utility tools with valid JSON schemas, and a tool call round-trips through the real
FastMCP machinery."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.server import build_server
from fakes.fake_api import (
    all_not_implemented_api,
    check_result_payload,
    json_handler,
    make_client,
    subnet_payload,
)

ORIGINAL_8_TOOLS = {
    "check_ip",
    "dns_lookup",
    "check_mail_auth",
    "check_domain",
    "check_owned_ports",
    "explain_report",
    "get_radar",
    "check_mcp_endpoint",
}

OFFLINE_UTILITY_TOOLS = {
    "subnet_calc",
    "ip_info",
    "ipv6_info",
    "mac_vendor",
    "user_agent",
}

EXPECTED_TOOLS = ORIGINAL_8_TOOLS | OFFLINE_UTILITY_TOOLS


async def _build_test_server() -> tuple[AdminKitClient, FastMCP]:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    return client, build_server(client)


async def test_server_lists_exactly_the_13_tools() -> None:
    client, mcp = await _build_test_server()
    try:
        tools = await mcp.list_tools()
    finally:
        await client.aclose()
    assert {t.name for t in tools} == EXPECTED_TOOLS


async def test_original_8_tools_still_registered_alongside_offline_utilities() -> None:
    """Regression guard: adding the 5 offline utility tools must not drop or rename any
    of the original spec section 18.8 tools."""
    client, mcp = await _build_test_server()
    try:
        names = {t.name for t in await mcp.list_tools()}
    finally:
        await client.aclose()
    assert names >= ORIGINAL_8_TOOLS
    assert names >= OFFLINE_UTILITY_TOOLS


async def test_every_tool_has_a_valid_object_schema_with_descriptions() -> None:
    client, mcp = await _build_test_server()
    try:
        tools = await mcp.list_tools()
    finally:
        await client.aclose()
    for tool in tools:
        assert tool.description, f"{tool.name} is missing a description"
        schema = tool.inputSchema
        assert schema.get("type") == "object"
        assert "properties" in schema


async def test_check_ip_tool_call_round_trips_through_fastmcp() -> None:
    api = make_client(
        {("GET", "/v1/check/my-ip"): json_handler(200, check_result_payload(check="my-ip", target="self"))},
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    mcp = build_server(client)
    try:
        content = await mcp.call_tool("check_ip", {})
    finally:
        await client.aclose()
    assert content  # at least one content block returned


async def test_subnet_calc_tool_call_round_trips_through_fastmcp() -> None:
    api = make_client(
        {("GET", "/v1/tools/subnet"): json_handler(200, subnet_payload())}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    mcp = build_server(client)
    try:
        content = await mcp.call_tool("subnet_calc", {"cidr": "192.0.2.0/24"})
    finally:
        await client.aclose()
    assert content  # at least one content block returned


async def test_unknown_tool_name_raises() -> None:
    client, mcp = await _build_test_server()
    try:
        raised = False
        try:
            await mcp.call_tool("not_a_real_tool", {})
        except Exception:  # noqa: BLE001 -- any ToolError subtype from the SDK is acceptable here
            raised = True
        assert raised
    finally:
        await client.aclose()
