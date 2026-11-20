"""`ip_in_cidr` tool (spec section 18.1 offline utility): is an address inside a CIDR range?

Thin wrapper over the live, no-auth `/v1/tools/ip-in-cidr` endpoint — pure `ipaddress`
membership math on the platform side, no third-party host is ever contacted. An IPv4
address tested against an IPv6 CIDR (or vice versa) is an honest `contains: false`, not an
error; malformed input is a 422 from the API, reported as an error.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._common import call_tools_api, invalid_input, validate_text_input

TOOL = "ip_in_cidr"
IP_IN_CIDR_PAGE = "https://adminkit.net/tools/ip-in-cidr/"
MAX_IP_LENGTH = 64
MAX_CIDR_LENGTH = 64


async def ip_in_cidr(client: AdminKitClient, ip: str, cidr: str) -> ToolResponse:
    problem = validate_text_input("ip", ip, max_length=MAX_IP_LENGTH) or validate_text_input(
        "cidr", cidr, max_length=MAX_CIDR_LENGTH
    )
    if problem is not None:
        return invalid_input(TOOL, problem, report_url=IP_IN_CIDR_PAGE)
    outcome = await call_tools_api(
        client, TOOL, "ip-in-cidr", params={"ip": ip, "cidr": cidr}, report_url=IP_IN_CIDR_PAGE
    )
    if isinstance(outcome, ToolResponse):
        return outcome
    payload = outcome
    return ToolResponse(
        tool=TOOL,
        status="ok",
        result={
            "ip": payload.get("ip"),
            "cidr": payload.get("cidr"),
            "contains": payload.get("contains"),
            "network": payload.get("network"),
        },
        evidence=payload,
        report_url=IP_IN_CIDR_PAGE,
    )
