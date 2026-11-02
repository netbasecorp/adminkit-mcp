"""`check_ip` tool (spec section 18.8): the caller's own public IP, ASN, and a CGNAT hint.

AdminKit only ever reports on the IP address that is actually making the request (spec
section 18.2: scanning someone else's IP is out of scope without verified ownership), so
the optional `ip` argument is accepted for forward compatibility with a future
verified-asset lookup, but is not usable yet.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse, not_available_yet
from adminkit_mcp.tools._common import map_check_result

TOOL = "check_ip"
MY_IP_PAGE = "https://adminkit.net/tools/my-ip/"


async def check_ip(client: AdminKitClient, ip: str | None = None) -> ToolResponse:
    if ip is not None:
        return not_available_yet(
            TOOL,
            report_url=MY_IP_PAGE,
            detail=(
                "Looking up a specific third-party IP is not offered: AdminKit only reports on the IP "
                "address making the request, to avoid becoming a reconnaissance tool against other "
                "people's networks (spec section 8 rule 1). Call check_ip() with no argument to check "
                "the caller's own IP."
            ),
        )

    try:
        resp = await client.call_api("GET", "/v1/check/my-ip")
    except ApiUnavailable:
        return await _from_site(client)
    return map_check_result(TOOL, resp.json(), fallback_report_url=MY_IP_PAGE)


async def _from_site(client: AdminKitClient) -> ToolResponse:
    resp = await client.call_site("/api/ip")
    payload = resp.json()
    findings = []
    if payload.get("cgnatHint"):
        findings.append(
            {
                "fix_hint": (
                    "This IP looks shared (CGNAT or mobile carrier) — port/exposure checks against it may "
                    "reflect a neighbour, not your own device."
                )
            }
        )
    return ToolResponse(
        tool=TOOL,
        status="ok" if payload.get("ip") else "error",
        result={
            "ip": payload.get("ip"),
            "is_ipv6": payload.get("isIPv6"),
            "asn": payload.get("asn"),
            "as_organization": payload.get("asOrganization"),
            "country": payload.get("country"),
            "cgnat_hint": payload.get("cgnatHint"),
            "cgnat_reason": payload.get("cgnatReason"),
        },
        evidence=payload,
        fix_hint=findings[0]["fix_hint"] if findings else None,
        report_url=MY_IP_PAGE,
    )
