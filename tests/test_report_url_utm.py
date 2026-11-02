"""Plan row A16 ("Link back"): every tool's `report_url` must point at the matching,
real adminkit.net page and carry `utm_source=mcp`, whether that URL is the tool's own
public page or a shareable report link the Check API issued for this specific call.

These tests work against the existing fakes only (see `conftest.py`'s socket guard and
`fakes/fake_api.py`) -- no real host is ever contacted.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse, with_mcp_utm
from adminkit_mcp.tools.check_domain import WHOIS_PAGE, check_domain
from adminkit_mcp.tools.check_ip import MY_IP_PAGE, check_ip
from adminkit_mcp.tools.check_mail_auth import MAIL_AUTH_PAGE, check_mail_auth
from adminkit_mcp.tools.check_mcp_endpoint import MCP_CHECK_PAGE, check_mcp_endpoint
from adminkit_mcp.tools.check_owned_ports import PORT_CHECK_PAGE, check_owned_ports
from adminkit_mcp.tools.dns_lookup import DNS_LOOKUP_PAGE, dns_lookup
from adminkit_mcp.tools.explain_report import explain_report
from adminkit_mcp.tools.get_radar import RADAR_PAGE, get_radar
from adminkit_mcp.tools.ip_info import IP_INFO_PAGE, ip_info
from adminkit_mcp.tools.ipv6_info import IPV6_INFO_PAGE, ipv6_info
from adminkit_mcp.tools.mac_vendor import MAC_VENDOR_PAGE, mac_vendor
from adminkit_mcp.tools.subnet_calc import SUBNET_CALC_PAGE, subnet_calc
from adminkit_mcp.tools.user_agent import USER_AGENT_PAGE, user_agent
from fakes.fake_api import (
    all_not_implemented_api,
    check_result_payload,
    ip_info_payload,
    ip_payload,
    ipv6_info_payload,
    json_handler,
    mac_vendor_payload,
    make_client,
    subnet_payload,
    user_agent_payload,
)


def _utm_source(url: str) -> list[str]:
    return parse_qs(urlsplit(url).query).get("utm_source", [])


def test_with_mcp_utm_appends_param() -> None:
    assert with_mcp_utm("https://adminkit.net/tools/whois/") == (
        "https://adminkit.net/tools/whois/?utm_source=mcp"
    )


def test_with_mcp_utm_is_idempotent() -> None:
    already_tagged = "https://adminkit.net/tools/whois/?utm_source=mcp"
    assert with_mcp_utm(already_tagged) == already_tagged


def test_with_mcp_utm_preserves_existing_query_params() -> None:
    assert with_mcp_utm("https://adminkit.net/r/abc?foo=bar") == (
        "https://adminkit.net/r/abc?foo=bar&utm_source=mcp"
    )


def test_with_mcp_utm_passes_through_none() -> None:
    assert with_mcp_utm(None) is None


def test_tool_response_tags_report_url_on_construction() -> None:
    response = ToolResponse(tool="x", status="ok", report_url="https://adminkit.net/tools/whois/")
    assert response.report_url == "https://adminkit.net/tools/whois/?utm_source=mcp"


def test_tool_response_leaves_missing_report_url_as_none() -> None:
    response = ToolResponse(tool="x", status="ok")
    assert response.report_url is None


async def _fake_client(
    api: httpx.AsyncClient | None = None, site: httpx.AsyncClient | None = None
) -> AdminKitClient:
    return AdminKitClient(
        api or all_not_implemented_api(),
        site or all_not_implemented_api(base_url="https://adminkit.net"),
    )


async def test_check_ip_offline_utility_fallback_has_utm() -> None:
    site = make_client({("GET", "/api/ip"): json_handler(200, ip_payload())}, base_url="https://adminkit.net")
    client = await _fake_client(site=site)
    try:
        result = await check_ip(client)
    finally:
        await client.aclose()
    assert result.report_url == MY_IP_PAGE + "?utm_source=mcp"
    assert _utm_source(result.report_url) == ["mcp"]


async def test_check_ip_live_api_falls_back_to_own_page_when_api_issues_no_report_url() -> None:
    api = make_client(
        {("GET", "/v1/check/my-ip"): json_handler(200, check_result_payload(check="my-ip", target="self"))},
        base_url="https://api.adminkit.net",
    )
    client = await _fake_client(api=api)
    try:
        result = await check_ip(client)
    finally:
        await client.aclose()
    assert result.report_url == MY_IP_PAGE + "?utm_source=mcp"


async def test_check_ip_live_api_keeps_api_issued_report_url_and_tags_it() -> None:
    api = make_client(
        {
            ("GET", "/v1/check/my-ip"): json_handler(
                200,
                check_result_payload(
                    check="my-ip",
                    target="self",
                    report_url="https://adminkit.net/r/rpt_abc123",
                ),
            )
        },
        base_url="https://api.adminkit.net",
    )
    client = await _fake_client(api=api)
    try:
        result = await check_ip(client)
    finally:
        await client.aclose()
    assert result.report_url == "https://adminkit.net/r/rpt_abc123?utm_source=mcp"


async def test_dns_lookup_live_api_falls_back_to_own_page() -> None:
    payload = check_result_payload(check="dns.lookup", target="example.com")
    api = make_client(
        {("POST", "/v1/check/dns"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    client = await _fake_client(api=api)
    try:
        result = await dns_lookup(client, "example.com", "A")
    finally:
        await client.aclose()
    assert result.report_url == DNS_LOOKUP_PAGE + "?utm_source=mcp"


async def test_check_mail_auth_live_api_falls_back_to_own_page() -> None:
    payload = check_result_payload(check="mail.auth", target="example.com")
    api = make_client(
        {("POST", "/v1/check/mail"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    client = await _fake_client(api=api)
    try:
        result = await check_mail_auth(client, "example.com")
    finally:
        await client.aclose()
    assert result.report_url == MAIL_AUTH_PAGE + "?utm_source=mcp"


async def test_check_mcp_endpoint_live_api_falls_back_to_own_page() -> None:
    api = make_client(
        {
            ("POST", "/v1/check/mcp-endpoint"): json_handler(
                200, check_result_payload(check="machine.mcp", target="https://mcp.example.com")
            )
        },
        base_url="https://api.adminkit.net",
    )
    client = await _fake_client(api=api)
    try:
        result = await check_mcp_endpoint(client, "https://mcp.example.com")
    finally:
        await client.aclose()
    assert result.report_url == MCP_CHECK_PAGE + "?utm_source=mcp"


async def test_check_owned_ports_live_api_falls_back_to_own_page() -> None:
    payload = check_result_payload(check="ports", target="verified.example.com")
    api = make_client(
        {("POST", "/v1/check/ports"): json_handler(200, payload)}, base_url="https://api.adminkit.net"
    )
    client = await _fake_client(api=api)
    try:
        result = await check_owned_ports(client, "verified.example.com")
    finally:
        await client.aclose()
    assert result.report_url == PORT_CHECK_PAGE + "?utm_source=mcp"


async def test_check_domain_report_url_has_utm() -> None:
    client = await _fake_client()
    try:
        result = await check_domain(client, "example.com")
    finally:
        await client.aclose()
    assert result.report_url == WHOIS_PAGE + "?utm_source=mcp"


async def test_get_radar_report_url_has_utm() -> None:
    client = await _fake_client()
    try:
        result = await get_radar(client, "mcp")
    finally:
        await client.aclose()
    assert result.report_url == RADAR_PAGE + "?utm_source=mcp"


async def test_subnet_calc_report_url_has_utm() -> None:
    api = make_client(
        {("GET", "/v1/tools/subnet"): json_handler(200, subnet_payload())},
        base_url="https://api.adminkit.net",
    )
    client = await _fake_client(api=api)
    try:
        result = await subnet_calc(client, "192.0.2.0/24")
    finally:
        await client.aclose()
    assert result.report_url == SUBNET_CALC_PAGE + "?utm_source=mcp"


async def test_ip_info_report_url_has_utm() -> None:
    api = make_client(
        {("GET", "/v1/tools/ip-info"): json_handler(200, ip_info_payload())},
        base_url="https://api.adminkit.net",
    )
    client = await _fake_client(api=api)
    try:
        result = await ip_info(client, "203.0.113.9")
    finally:
        await client.aclose()
    assert result.report_url == IP_INFO_PAGE + "?utm_source=mcp"


async def test_ipv6_info_report_url_has_utm() -> None:
    api = make_client(
        {("GET", "/v1/tools/ipv6-info"): json_handler(200, ipv6_info_payload())},
        base_url="https://api.adminkit.net",
    )
    client = await _fake_client(api=api)
    try:
        result = await ipv6_info(client, "2001:db8::1")
    finally:
        await client.aclose()
    assert result.report_url == IPV6_INFO_PAGE + "?utm_source=mcp"


async def test_mac_vendor_report_url_has_utm() -> None:
    api = make_client(
        {("GET", "/v1/tools/mac-vendor"): json_handler(200, mac_vendor_payload())},
        base_url="https://api.adminkit.net",
    )
    client = await _fake_client(api=api)
    try:
        result = await mac_vendor(client, "AA:BB:CC:DD:EE:FF")
    finally:
        await client.aclose()
    assert result.report_url == MAC_VENDOR_PAGE + "?utm_source=mcp"


async def test_user_agent_report_url_has_utm() -> None:
    api = make_client(
        {("GET", "/v1/tools/user-agent"): json_handler(200, user_agent_payload())},
        base_url="https://api.adminkit.net",
    )
    client = await _fake_client(api=api)
    try:
        result = await user_agent(client, "Mozilla/5.0")
    finally:
        await client.aclose()
    assert result.report_url == USER_AGENT_PAGE + "?utm_source=mcp"


async def test_explain_report_unknown_token_has_no_backlink() -> None:
    """No real report exists for an unknown/expired share token, so there is nothing
    honest to link to -- `report_url` must stay None rather than guessing a page."""
    not_found = {"type": "about:blank", "title": "Not Found", "status": 404}
    api = make_client(
        {("GET", "/v1/report/rpt_missing"): json_handler(404, not_found)}, base_url="https://api.adminkit.net"
    )
    client = await _fake_client(api=api)
    try:
        result = await explain_report(client, "rpt_missing")
    finally:
        await client.aclose()
    assert result.report_url is None


async def test_explain_report_tags_the_api_issued_report_link() -> None:
    report = check_result_payload(
        check="spf", target="example.com", report_url="https://api.adminkit.net/v1/report/rpt_01H8"
    )
    api = make_client(
        {
            ("GET", "/v1/report/rpt_01H8"): json_handler(200, report),
            ("POST", "/v1/ai/explain"): json_handler(
                200,
                {
                    "check": "spf",
                    "target": "example.com",
                    "model": "claude-fake-5",
                    "explanation": "ok",
                    "cited_evidence_ids": [],
                },
            ),
        },
        base_url="https://api.adminkit.net",
    )
    client = await _fake_client(api=api)
    try:
        result = await explain_report(client, "rpt_01H8")
    finally:
        await client.aclose()
    assert result.report_url == "https://api.adminkit.net/v1/report/rpt_01H8?utm_source=mcp"
