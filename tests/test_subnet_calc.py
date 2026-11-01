from __future__ import annotations

import httpx

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.subnet_calc import subnet_calc
from fakes.fake_api import all_not_implemented_api, json_handler, make_client, problem_payload, subnet_payload


async def test_subnet_calc_tool() -> None:
    payload = subnet_payload(cidr="192.0.2.0/24")
    api = make_client(
        {("GET", "/v1/tools/subnet"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await subnet_calc(client, "192.0.2.0/24")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["network"] == "192.0.2.0"
    assert result.result["usable_hosts"] == "254"
    assert result.report_url == "https://adminkit.net/tools/subnet-calculator/"


async def test_subnet_calc_tool_calls_correct_path_with_cidr_param() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["cidr"] = request.url.params["cidr"]
        return httpx.Response(200, json=subnet_payload())

    api = make_client({("GET", "/v1/tools/subnet"): handler}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        await subnet_calc(client, "10.0.0.0/8")
    finally:
        await client.aclose()
    assert seen["path"] == "/v1/tools/subnet"
    assert seen["cidr"] == "10.0.0.0/8"


async def test_subnet_calc_tool_invalid_cidr_is_honest_error() -> None:
    problem = problem_payload(detail="'not-a-cidr' is not a valid CIDR network.")
    api = make_client(
        {("GET", "/v1/tools/subnet"): json_handler(422, problem)},
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await subnet_calc(client, "not-a-cidr")
    finally:
        await client.aclose()
    assert result.status == "error"
    assert "not a valid CIDR" in result.result["message"]
