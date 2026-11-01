"""`subnet_calc` tool (spec section 18.1 offline utility): IPv4/IPv6 subnet math.

Thin wrapper over the live, no-auth `/v1/tools/subnet` endpoint — pure `ipaddress` math on
the platform side (`platform/adminkit/tools/service.py`), no third-party host is ever
contacted. Distinct from the original 8 `/v1/check/*` tools: this one never fails or falls
back, it only reports a 422 from the API as an honest validation error.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._common import call_tools_api

TOOL = "subnet_calc"
SUBNET_CALC_PAGE = "https://adminkit.net/tools/subnet-calculator/"


async def subnet_calc(client: AdminKitClient, cidr: str) -> ToolResponse:
    outcome = await call_tools_api(client, TOOL, "subnet", params={"cidr": cidr}, report_url=SUBNET_CALC_PAGE)
    if isinstance(outcome, ToolResponse):
        return outcome
    payload = outcome
    return ToolResponse(
        tool=TOOL,
        status="ok",
        result={
            "cidr": payload.get("cidr"),
            "version": payload.get("version"),
            "network": payload.get("network"),
            "prefix_length": payload.get("prefix_length"),
            "netmask": payload.get("netmask"),
            "broadcast": payload.get("broadcast"),
            "wildcard": payload.get("wildcard"),
            "total_addresses": payload.get("total_addresses"),
            "usable_hosts": payload.get("usable_hosts"),
            "first_usable": payload.get("first_usable"),
            "last_usable": payload.get("last_usable"),
            "is_private": payload.get("is_private"),
            "is_global": payload.get("is_global"),
            "is_loopback": payload.get("is_loopback"),
            "is_multicast": payload.get("is_multicast"),
        },
        evidence=payload,
        report_url=SUBNET_CALC_PAGE,
    )
