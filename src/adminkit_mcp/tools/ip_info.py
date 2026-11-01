"""`ip_info` tool (spec section 18.1 offline utility): IPv4/IPv6 address math.

Thin wrapper over the live, no-auth `/v1/tools/ip-info` endpoint. `reverse_dns` is the
address's reverse-lookup name computed locally (`ipaddress.reverse_pointer`); it is never
actually queried against DNS. Unlike `check_ip`, this accepts any address, not only the
caller's own — it is pure arithmetic, not reconnaissance against a host.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._common import call_tools_api

TOOL = "ip_info"
IP_INFO_PAGE = "https://adminkit.net/tools/"


async def ip_info(client: AdminKitClient, ip: str) -> ToolResponse:
    outcome = await call_tools_api(client, TOOL, "ip-info", params={"ip": ip}, report_url=IP_INFO_PAGE)
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
            "is_loopback": payload.get("is_loopback"),
            "is_link_local": payload.get("is_link_local"),
            "is_multicast": payload.get("is_multicast"),
            "is_reserved": payload.get("is_reserved"),
            "reverse_dns": payload.get("reverse_dns"),
            "integer": payload.get("integer"),
            "compressed": payload.get("compressed"),
            "exploded": payload.get("exploded"),
        },
        evidence=payload,
        report_url=IP_INFO_PAGE,
    )
