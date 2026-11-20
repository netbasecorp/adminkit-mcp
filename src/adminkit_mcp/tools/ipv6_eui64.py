"""`ipv6_eui64` tool (spec section 18.1 offline utility, section 18.7 "IPv6 exposes devices").

Thin wrapper over the live, no-auth `/v1/tools/ipv6-eui64` endpoint: derives the modified
EUI-64 interface identifier from a MAC-48 address (RFC 4291 appendix A, U/L bit flipped) and
combines it with an IPv6 prefix of /64 or shorter — all computed locally, nothing is queried
or probed. A prefix longer than /64 or an IPv4 prefix is a 422 from the API, reported as an
error.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._common import call_tools_api, invalid_input, validate_text_input

TOOL = "ipv6_eui64"
# The site's IPv6 tool page also derives the modified EUI-64 interface id from a MAC.
IPV6_EUI64_PAGE = "https://adminkit.net/tools/ipv6-info/"
MAX_PREFIX_LENGTH = 64
MAX_MAC_LENGTH = 32


async def ipv6_eui64(client: AdminKitClient, prefix: str, mac: str) -> ToolResponse:
    problem = validate_text_input("prefix", prefix, max_length=MAX_PREFIX_LENGTH) or validate_text_input(
        "mac", mac, max_length=MAX_MAC_LENGTH
    )
    if problem is not None:
        return invalid_input(TOOL, problem, report_url=IPV6_EUI64_PAGE)
    outcome = await call_tools_api(
        client, TOOL, "ipv6-eui64", params={"prefix": prefix, "mac": mac}, report_url=IPV6_EUI64_PAGE
    )
    if isinstance(outcome, ToolResponse):
        return outcome
    payload = outcome
    return ToolResponse(
        tool=TOOL,
        status="ok",
        result={
            "prefix": payload.get("prefix"),
            "mac": payload.get("mac"),
            "interface_id": payload.get("interface_id"),
            "address": payload.get("address"),
            "compressed": payload.get("compressed"),
            "exploded": payload.get("exploded"),
        },
        evidence=payload,
        report_url=IPV6_EUI64_PAGE,
    )
