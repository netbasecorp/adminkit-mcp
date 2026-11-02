"""`dns_lookup` tool (spec section 18.8): A/AAAA/MX/TXT/NS/CAA/PTR/SOA/CNAME lookup."""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._common import map_check_result

TOOL = "dns_lookup"
DNS_LOOKUP_PAGE = "https://adminkit.net/tools/dns-lookup/"

ALLOWED_TYPES = frozenset({"A", "AAAA", "MX", "TXT", "NS", "CAA", "PTR", "SOA", "CNAME"})


async def dns_lookup(client: AdminKitClient, name: str, type: str = "A") -> ToolResponse:
    record_type = type.strip().upper()
    if record_type not in ALLOWED_TYPES:
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": f"type must be one of: {', '.join(sorted(ALLOWED_TYPES))}"},
            report_url=DNS_LOOKUP_PAGE,
        )

    try:
        resp = await client.call_api(
            "POST", "/v1/check/dns", json={"target": name, "options": {"type": record_type}}
        )
    except ApiUnavailable:
        return await _from_site(client, name, record_type)
    return map_check_result(TOOL, resp.json(), fallback_report_url=DNS_LOOKUP_PAGE)


async def _from_site(client: AdminKitClient, name: str, record_type: str) -> ToolResponse:
    resp = await client.call_site("/api/dns", params={"name": name, "type": record_type})
    payload = resp.json()
    status = payload.get("status")
    answers = payload.get("answers", [])
    return ToolResponse(
        tool=TOOL,
        status="ok" if status == "ok" else "error",
        result={"name": payload.get("name"), "type": payload.get("type"), "answers": answers},
        evidence=payload,
        fix_hint=payload.get("message") if status != "ok" else None,
        report_url=DNS_LOOKUP_PAGE,
    )
