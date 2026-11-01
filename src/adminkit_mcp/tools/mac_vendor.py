"""`mac_vendor` tool (spec section 18.1 offline utility): MAC/OUI vendor lookup.

Thin wrapper over the live, no-auth `/v1/tools/mac-vendor` endpoint: matches against a
bundled IEEE registry snapshot (`platform/adminkit/tools/data/oui.csv`), no network lookup.
`found: false` for an unmatched prefix is returned as-is, never guessed at.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._common import call_tools_api

TOOL = "mac_vendor"
MAC_VENDOR_PAGE = "https://adminkit.net/tools/mac-lookup/"


async def mac_vendor(client: AdminKitClient, mac: str) -> ToolResponse:
    outcome = await call_tools_api(
        client, TOOL, "mac-vendor", params={"mac": mac}, report_url=MAC_VENDOR_PAGE
    )
    if isinstance(outcome, ToolResponse):
        return outcome
    payload = outcome
    return ToolResponse(
        tool=TOOL,
        status="ok",
        result={
            "mac": payload.get("mac"),
            "is_oui_only": payload.get("is_oui_only"),
            "found": payload.get("found"),
            "organization": payload.get("organization"),
            "matched_prefix": payload.get("matched_prefix"),
            "assignment": payload.get("assignment"),
            "locally_administered": payload.get("locally_administered"),
            "multicast": payload.get("multicast"),
        },
        evidence=payload,
        report_url=MAC_VENDOR_PAGE,
    )
