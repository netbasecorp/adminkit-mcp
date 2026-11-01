"""`ipv6_info` tool (spec section 18.1 offline utility, section 18.7 "IPv6 exposes devices").

Thin wrapper over the live, no-auth `/v1/tools/ipv6-info` endpoint: decodes an IPv6 address
into its /64 network, reverse-pointer form, and any embedded IPv4 (IPv4-mapped, 6to4,
Teredo) — all derived locally, nothing is queried or probed. IPv4 input is rejected by the
API itself; use `ip_info` for IPv4.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._common import call_tools_api

TOOL = "ipv6_info"
IPV6_INFO_PAGE = "https://adminkit.net/tools/"


async def ipv6_info(client: AdminKitClient, ip: str) -> ToolResponse:
    outcome = await call_tools_api(client, TOOL, "ipv6-info", params={"ip": ip}, report_url=IPV6_INFO_PAGE)
    if isinstance(outcome, ToolResponse):
        return outcome
    payload = outcome
    return ToolResponse(
        tool=TOOL,
        status="ok",
        result={
            "ip": payload.get("ip"),
            "version": payload.get("version"),
            "is_private": payload.get("is_private"),
            "is_global": payload.get("is_global"),
            "is_link_local": payload.get("is_link_local"),
            "is_multicast": payload.get("is_multicast"),
            "is_loopback": payload.get("is_loopback"),
            "is_reserved": payload.get("is_reserved"),
            "compressed": payload.get("compressed"),
            "exploded": payload.get("exploded"),
            "reverse_pointer": payload.get("reverse_pointer"),
            "network_64": payload.get("network_64"),
            "embedded_ipv4": payload.get("embedded_ipv4"),
            "embedded_ipv4_kind": payload.get("embedded_ipv4_kind"),
            "teredo_server": payload.get("teredo_server"),
        },
        evidence=payload,
        report_url=IPV6_INFO_PAGE,
    )
