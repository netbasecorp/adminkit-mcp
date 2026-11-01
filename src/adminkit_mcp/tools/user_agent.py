"""`user_agent` tool (spec section 18.1 offline utility): User-Agent string parsing.

Thin wrapper over the live, no-auth `/v1/tools/user-agent` endpoint: matches against a
bundled uap-core-derived rule set (`platform/adminkit/tools/data/ua_regexes.json`), no
network lookup. Unmatched fields come back `null`, never guessed at.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._common import call_tools_api

TOOL = "user_agent"
USER_AGENT_PAGE = "https://adminkit.net/tools/user-agent/"


async def user_agent(client: AdminKitClient, ua: str) -> ToolResponse:
    outcome = await call_tools_api(client, TOOL, "user-agent", params={"ua": ua}, report_url=USER_AGENT_PAGE)
    if isinstance(outcome, ToolResponse):
        return outcome
    payload = outcome
    return ToolResponse(
        tool=TOOL,
        status="ok",
        result={
            "ua": payload.get("ua"),
            "browser_family": payload.get("browser_family"),
            "browser_version": payload.get("browser_version"),
            "os_family": payload.get("os_family"),
            "os_version": payload.get("os_version"),
            "device_family": payload.get("device_family"),
            "device_brand": payload.get("device_brand"),
            "device_model": payload.get("device_model"),
            "is_bot": payload.get("is_bot"),
        },
        evidence=payload,
        report_url=USER_AGENT_PAGE,
    )
