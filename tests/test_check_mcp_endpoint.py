"""Tests for the `check_mcp_endpoint` probe: streamable HTTP, legacy SSE, auth discovery,
dangerous tool names, private-target refusal, and that `tools/call` is never sent."""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.check_mcp_endpoint import check_mcp_endpoint
from fakes.fake_api import all_not_implemented_api
from fakes.fake_mcp_server import FakeMcpConfig


async def _fake_client() -> AdminKitClient:
    return AdminKitClient(all_not_implemented_api(), all_not_implemented_api(base_url="https://adminkit.net"))


async def test_check_mcp_endpoint_flags_anonymous_access(fake_mcp_server) -> None:  # type: ignore[no-untyped-def]
    config = FakeMcpConfig(require_auth=False, tool_names=("search", "list_files"))
    base_url = fake_mcp_server(config)
    client = await _fake_client()
    try:
        result = await check_mcp_endpoint(client, base_url + "/mcp", allow_private=True)
    finally:
        await client.aclose()
    assert result.status == "fail"
    finding_ids = {f["id"] for f in result.result["findings"]}
    assert "mcp.no_auth_required" in finding_ids
    assert "mcp.tools_exposed_anonymously" in finding_ids
    assert "tools/call" not in config.received_methods


async def test_check_mcp_endpoint_flags_dangerous_tool_name(fake_mcp_server) -> None:  # type: ignore[no-untyped-def]
    config = FakeMcpConfig(require_auth=False, tool_names=("search", "exec_shell"))
    base_url = fake_mcp_server(config)
    client = await _fake_client()
    try:
        result = await check_mcp_endpoint(client, base_url + "/mcp", allow_private=True)
    finally:
        await client.aclose()
    finding_ids = {f["id"] for f in result.result["findings"]}
    assert "mcp.dangerous_tool_exposed" in finding_ids
    dangerous = next(f for f in result.result["findings"] if f["id"] == "mcp.dangerous_tool_exposed")
    assert dangerous["severity"] == "critical"
    assert "tools/call" not in config.received_methods


async def test_check_mcp_endpoint_auth_required_is_clean(fake_mcp_server) -> None:  # type: ignore[no-untyped-def]
    config = FakeMcpConfig(require_auth=True, tool_names=("search",))
    base_url = fake_mcp_server(config)
    client = await _fake_client()
    try:
        result = await check_mcp_endpoint(client, base_url + "/mcp", allow_private=True)
    finally:
        await client.aclose()
    finding_ids = {f["id"] for f in result.result["findings"]}
    assert "mcp.no_auth_required" not in finding_ids
    assert "mcp.tools_exposed_anonymously" not in finding_ids
    assert result.result["evidence"]["auth_required"] is True
    assert result.result["evidence"]["www_authenticate"]
    assert "tools/call" not in config.received_methods


async def test_check_mcp_endpoint_legacy_sse_transport(fake_mcp_server) -> None:  # type: ignore[no-untyped-def]
    config = FakeMcpConfig(
        require_auth=False,
        tool_names=("search", "delete_file"),
        support_streamable_http=False,
        support_legacy_sse=True,
    )
    base_url = fake_mcp_server(config)
    client = await _fake_client()
    try:
        result = await check_mcp_endpoint(client, base_url + "/mcp", allow_private=True)
    finally:
        await client.aclose()
    assert result.result["evidence"]["transport"] == "legacy-sse"
    finding_ids = {f["id"] for f in result.result["findings"]}
    assert "mcp.no_auth_required" in finding_ids
    assert "tools/call" not in config.received_methods


async def test_check_mcp_endpoint_discovers_oauth_metadata(fake_mcp_server) -> None:  # type: ignore[no-untyped-def]
    config = FakeMcpConfig(require_auth=True, oauth_protected_resource={"authorization_servers": []})
    base_url = fake_mcp_server(config)
    config.oauth_protected_resource = {"authorization_servers": [base_url]}
    config.oauth_authorization_server = {"issuer": base_url, "token_endpoint": base_url + "/token"}
    client = await _fake_client()
    try:
        result = await check_mcp_endpoint(client, base_url + "/mcp", allow_private=True)
    finally:
        await client.aclose()
    oauth_meta = result.result["evidence"]["oauth_metadata"]
    assert oauth_meta["protected_resource"]["authorization_servers"] == [base_url]
    assert oauth_meta["authorization_server"]["issuer"] == base_url


async def test_check_mcp_endpoint_refuses_private_target_by_default(fake_mcp_server) -> None:  # type: ignore[no-untyped-def]
    config = FakeMcpConfig(require_auth=False, tool_names=("search",))
    base_url = fake_mcp_server(config)
    client = await _fake_client()
    try:
        result = await check_mcp_endpoint(client, base_url + "/mcp", allow_private=False)
    finally:
        await client.aclose()
    assert result.status == "skipped"
    assert config.received_methods == []  # never even connected


async def test_check_mcp_endpoint_prefers_live_api_when_available() -> None:
    from fakes.fake_api import check_result_payload, json_handler, make_client

    api = make_client(
        {
            ("POST", "/v1/check/mcp-endpoint"): json_handler(
                200, check_result_payload(check="machine.mcp", target="https://mcp.example.com", status="ok")
            )
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_mcp_endpoint(client, "https://mcp.example.com")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["check"] == "machine.mcp"
