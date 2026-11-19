"""`list_assets` tool: read-only list of the caller's own AdminKit assets with their
stored monitored status (L0 monitoring), so an agent can answer "which of my assets are
failing?".

One real call: `GET /v1/assets` (`AssetListResponse` in `platform/openapi.stub.yaml`), which
needs an authenticated `X-API-Key`. Without a configured key this tool returns an "API key
required" result and sends no request at all (the hosted HTTP endpoint never forwards a key,
so there it always answers that way). Nothing is created, verified, checked, or deleted.

Per-asset fields and error mapping are shared with `get_asset` (`tools/_assets.py`); the
asset's `verification_token` is never returned. Each asset carries `value_valid` (`false` = a
legacy row whose stored value does not parse: remove and add it again; absent in an older API =
`true`); any such asset makes the result `warn` and is counted in the summary.
"""

from __future__ import annotations

import httpx

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._assets import (
    ASSETS_PAGE,
    INVALID_VALUE_HINT,
    has_invalid_value,
    is_failing,
    key_required,
    map_asset,
    map_error,
    unreachable,
)

TOOL = "list_assets"


async def list_assets(client: AdminKitClient) -> ToolResponse:
    if not client.has_api_key:
        return key_required(TOOL, "Listing your assets")
    try:
        resp = await client.call_api("GET", "/v1/assets")
    except ApiUnavailable:
        return unreachable(TOOL)
    except httpx.HTTPStatusError as exc:
        return map_error(TOOL, exc.response, action="listing assets")

    try:
        payload = resp.json()
    except ValueError:
        payload = None
    raw_assets = payload.get("assets") if isinstance(payload, dict) else None
    if not isinstance(raw_assets, list):
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": "The assets API returned an unexpected response body."},
            report_url=ASSETS_PAGE,
        )

    assets = [map_asset(item) for item in raw_assets if isinstance(item, dict)]
    failing = [a["id"] for a in assets if is_failing(a)]
    not_checked = [a["id"] for a in assets if a["status"] is None]
    invalid = [a["id"] for a in assets if has_invalid_value(a)]
    summary = (
        f"{len(assets)} asset(s): {len(failing)} failing, "
        f"{len(assets) - len(failing) - len(not_checked)} passing, {len(not_checked)} not checked yet."
    )
    if invalid:
        ids = ", ".join(map(str, invalid))
        summary += f" {len(invalid)} with an invalid stored value (remove and add again): {ids}."
    hints = []
    if failing:
        hints.append("Open the failing asset in your AdminKit account to see its latest check results.")
    if invalid:
        hints.append(INVALID_VALUE_HINT)
    return ToolResponse(
        tool=TOOL,
        status="warn" if failing or invalid else "ok",
        result={
            "summary": summary,
            "count": len(assets),
            "failing": failing,
            "not_checked": not_checked,
            "assets": assets,
        },
        fix_hint=" ".join(hints) or None,
        report_url=ASSETS_PAGE,
    )
