"""`check_owned_ports` tool (spec section 18.8, section 8 rule 1): port exposure check.

Active port probing is only safe once AdminKit has verified the caller owns `target`
(DNS TXT / file / OAuth, spec section 8 rule 1) — this tool is a thin client over the
live Check API's ownership-gated endpoint (`/v1/check/ports`), never a local scan. The
ownership gate is enforced server-side (`adminkit.check.service._ports`); an unverified
target still gets a result, just scanned against an empty allow-list rather than refused
outright. If the Check API cannot be reached, this returns a "could not be reached"
result rather than fabricating one.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._common import map_check_result

TOOL = "check_owned_ports"
PORT_CHECK_PAGE = "https://adminkit.net/tools/port-check/"


async def check_owned_ports(client: AdminKitClient, target: str) -> ToolResponse:
    try:
        resp = await client.call_api("POST", "/v1/check/ports", json={"target": target, "options": {}})
    except ApiUnavailable:
        return ToolResponse(
            tool=TOOL,
            status="not_available",
            result={"message": "Owned-port checking could not be reached on the Check API right now."},
            fix_hint="This check is temporarily unavailable; retry shortly or see the public port "
            "check tool page.",
            report_url=PORT_CHECK_PAGE,
        )
    return map_check_result(TOOL, resp.json())
