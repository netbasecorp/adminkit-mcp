"""`check_mcp_endpoint` tool (spec section 18.8): MCP server exposure probe.

Prefers `/v1/check/mcp-endpoint` on the live Check API; otherwise runs the local,
own-implementation probe in `adminkit_mcp.probe.mcp_probe`. `tools/call` is never sent by
either path.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.probe.mcp_probe import probe_mcp_endpoint
from adminkit_mcp.tools._common import map_check_result

TOOL = "check_mcp_endpoint"
MCP_CHECK_PAGE = "https://adminkit.net/tools/mcp-check/"


async def check_mcp_endpoint(client: AdminKitClient, url: str, allow_private: bool = False) -> ToolResponse:
    try:
        resp = await client.call_api("POST", "/v1/check/mcp-endpoint", json={"target": url, "options": {}})
        return map_check_result(TOOL, resp.json())
    except ApiUnavailable:
        pass

    # Never reuse `client`'s httpx clients here: they carry the AdminKit API key header,
    # which must not be sent to an arbitrary third-party URL being probed.
    result = await probe_mcp_endpoint(url, allow_private=allow_private)
    top_finding = result.findings[0] if result.findings else None
    return ToolResponse(
        tool=TOOL,
        status=result.status,
        result=result.to_dict(),
        evidence=result.evidence,
        fix_hint=top_finding.fix_hint if top_finding else None,
        report_url=MCP_CHECK_PAGE,
    )
