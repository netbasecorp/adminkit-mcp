"""In-process MCP protocol test: the server lists all 8 spec section 18.8 tools plus the 5
offline utility tools and the read-only `list_assets`/`get_asset` account tools with valid JSON schemas,
and a tool call round-trips through the real FastMCP machinery."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

import adminkit_mcp
from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.server import build_server
from fakes.fake_api import (
    all_not_implemented_api,
    check_result_payload,
    ip_in_cidr_payload,
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
    "ip_in_cidr",
    "ipv6_info",
    "ipv6_eui64",
    "mac_vendor",
    "user_agent",
    "spf_validate",
}

ACCOUNT_TOOLS = {"list_assets", "get_asset"}

EXPECTED_TOOLS = ORIGINAL_8_TOOLS | OFFLINE_UTILITY_TOOLS | ACCOUNT_TOOLS


async def _build_test_server() -> tuple[AdminKitClient, FastMCP]:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    return client, build_server(client)


async def test_server_lists_exactly_the_18_tools() -> None:
    client, mcp = await _build_test_server()
    try:
        tools = await mcp.list_tools()
    finally:
        await client.aclose()
    assert {t.name for t in tools} == EXPECTED_TOOLS


async def test_initialize_reports_adminkit_name_and_package_version() -> None:
    """serverInfo.version must be adminkit-mcp's own version, not the installed `mcp` SDK's
    (the SDK's fallback when the server sets none). /developers/mcp/ documents it."""
    client, mcp = await _build_test_server()
    try:
        async with create_connected_server_and_client_session(mcp._mcp_server) as session:
            result = await session.initialize()
    finally:
        await client.aclose()
    assert result.serverInfo.name == "adminkit"
    assert result.serverInfo.version == adminkit_mcp.__version__


async def test_original_8_tools_still_registered_alongside_offline_utilities() -> None:
    """Regression guard: adding the 8 offline utility tools must not drop or rename any
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
        {("GET", "/v1/tools/subnet"): json_handler(200, subnet_payload())},
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    mcp = build_server(client)
    try:
        content = await mcp.call_tool("subnet_calc", {"cidr": "192.0.2.0/24"})
    finally:
        await client.aclose()
    assert content  # at least one content block returned


async def test_ip_in_cidr_tool_call_round_trips_through_fastmcp() -> None:
    api = make_client(
        {("GET", "/v1/tools/ip-in-cidr"): json_handler(200, ip_in_cidr_payload())},
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    mcp = build_server(client)
    try:
        content, structured = await mcp.call_tool("ip_in_cidr", {"ip": "192.0.2.10", "cidr": "192.0.2.0/24"})
    finally:
        await client.aclose()
    assert content
    assert isinstance(structured, dict)
    assert structured["tool"] == "ip_in_cidr"
    assert structured["status"] == "ok"
    assert structured["result"]["contains"] is True
    assert structured["report_url"] == "https://adminkit.net/tools/ip-in-cidr/?utm_source=mcp"


async def test_new_offline_tools_expose_their_arguments_as_required_strings() -> None:
    client, mcp = await _build_test_server()
    try:
        tools = {t.name: t for t in await mcp.list_tools()}
    finally:
        await client.aclose()
    for name, args in {
        "ip_in_cidr": ["ip", "cidr"],
        "ipv6_eui64": ["prefix", "mac"],
        "spf_validate": ["record"],
    }.items():
        schema = tools[name].inputSchema
        assert sorted(schema["required"]) == sorted(args), name
        for arg in args:
            assert schema["properties"][arg]["type"] == "string", (name, arg)


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
