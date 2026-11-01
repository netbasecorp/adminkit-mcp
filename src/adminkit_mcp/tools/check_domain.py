"""`check_domain` tool (spec section 18.8): an aggregate domain health overview.

Runs whois, TLS, and HTTP-header checks against the live Check API (`/v1/check/whois`,
`/v1/check/tls`, `/v1/check/http-headers`) in parallel and combines them into one result.
There is no site-function fallback for this tool (only `ip`, `dns`, `mailauth` have one),
so a sub-check that cannot be reached is dropped from the aggregate rather than
fabricated; if none of the three can be reached this returns a structured "could not be
reached" result instead of a partial one.
"""

from __future__ import annotations

import asyncio
from typing import Any

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse, ToolStatus
from adminkit_mcp.tools._common import map_check_result

TOOL = "check_domain"
WHOIS_PAGE = "https://adminkit.net/tools/whois/"
_SUB_CHECKS = ("whois", "tls", "http-headers")


async def check_domain(client: AdminKitClient, domain: str) -> ToolResponse:
    results = await asyncio.gather(*(_run_sub_check(client, domain, kind) for kind in _SUB_CHECKS))
    pairs = zip(_SUB_CHECKS, results, strict=True)
    available = {kind: result for kind, result in pairs if result is not None}

    if not available:
        return ToolResponse(
            tool=TOOL,
            status="not_available",
            result={
                "message": "Domain overview (whois/tls/http-headers) could not be reached on the "
                "Check API right now."
            },
            fix_hint="This check is temporarily unavailable; retry shortly or see the public whois "
            "tool page.",
            report_url=WHOIS_PAGE,
        )

    statuses = [r["status"] for r in available.values()]
    overall: ToolStatus = "fail" if "fail" in statuses else "warn" if "warn" in statuses else "ok"
    return ToolResponse(
        tool=TOOL,
        status=overall,
        result={"domain": domain, "checks": available},
        evidence={kind: r.get("evidence", {}) for kind, r in available.items()},
        report_url=WHOIS_PAGE,
    )


async def _run_sub_check(client: AdminKitClient, domain: str, kind: str) -> dict[str, Any] | None:
    try:
        resp = await client.call_api("POST", f"/v1/check/{kind}", json={"target": domain, "options": {}})
    except ApiUnavailable:
        return None
    return map_check_result(f"{TOOL}.{kind}", resp.json()).to_dict()
