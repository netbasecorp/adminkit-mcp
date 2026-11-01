from __future__ import annotations

import httpx

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.user_agent import user_agent
from fakes.fake_api import (
    all_not_implemented_api,
    json_handler,
    make_client,
    problem_payload,
    user_agent_payload,
)

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0"


async def test_user_agent_tool() -> None:
    payload = user_agent_payload(ua=CHROME_UA, browser_family="Chrome")
    api = make_client(
        {("GET", "/v1/tools/user-agent"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await user_agent(client, CHROME_UA)
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["browser_family"] == "Chrome"
    assert result.result["os_family"] == "Windows"
    assert result.report_url == "https://adminkit.net/tools/user-agent/"


async def test_user_agent_tool_unmatched_ua_is_honest_null() -> None:
    payload = user_agent_payload(ua="SomeUnknownClient/1.0", browser_family=None)
    api = make_client(
        {("GET", "/v1/tools/user-agent"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await user_agent(client, "SomeUnknownClient/1.0")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["browser_family"] is None
    assert result.result["os_family"] is None
    assert result.result["is_bot"] is False


async def test_user_agent_tool_calls_correct_path_with_ua_param() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["ua"] = request.url.params["ua"]
        return httpx.Response(200, json=user_agent_payload())

    api = make_client({("GET", "/v1/tools/user-agent"): handler}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        await user_agent(client, CHROME_UA)
    finally:
        await client.aclose()
    assert seen["path"] == "/v1/tools/user-agent"
    assert seen["ua"] == CHROME_UA


async def test_user_agent_tool_rejects_oversized_input() -> None:
    api = make_client(
        {
            ("GET", "/v1/tools/user-agent"): json_handler(
                422, problem_payload(detail="ua must be at most 512 characters.")
            )
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await user_agent(client, "x" * 1000)
    finally:
        await client.aclose()
    assert result.status == "error"
    assert "at most" in result.result["message"]
