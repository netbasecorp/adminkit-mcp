"""`get_asset` tool: read-only view of ONE of the caller's own AdminKit assets and its stored
monitored status, so an agent can answer "is my asset X passing?" without listing everything.

One real call: `GET /v1/assets/{asset_id}` (`AssetResponse` in `platform/openapi.stub.yaml`),
which needs an authenticated `X-API-Key`. Without a configured key this tool returns an "API key
required" result and sends no request (the hosted HTTP endpoint never forwards a key, so there it
always answers that way). `asset_id` is validated locally and percent-encoded into the path; a bad
id is refused without any request. The API answers 404 for an unknown id and for another
organization's id alike, and so does this tool. Nothing is created, verified, checked, or deleted.

Returns the same per-asset fields as `list_assets` (`tools/_assets.py`), never the asset's
`verification_token`.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools._assets import (
    ASSETS_PAGE,
    is_failing,
    key_required,
    map_asset,
    map_error,
    unreachable,
)

TOOL = "get_asset"
MAX_ASSET_ID_LENGTH = 128
_FORBIDDEN_CHARS = frozenset("/?#%\\")


def validate_asset_id(asset_id: str) -> str | None:
    """Returns why `asset_id` is unacceptable, or None if it may be sent. Asset ids are
    `ast_`-prefixed ULIDs; this only rejects ids that could not be one safely in a URL path."""
    if not asset_id:
        return "asset_id must not be empty."
    if len(asset_id) > MAX_ASSET_ID_LENGTH:
        return f"asset_id must be at most {MAX_ASSET_ID_LENGTH} characters."
    if ".." in asset_id:
        return "asset_id must not contain '..'."
    for ch in asset_id:
        if ch in _FORBIDDEN_CHARS:
            return f"asset_id must not contain {ch!r}."
        if ch.isspace() or not ch.isprintable():
            return "asset_id must not contain whitespace or control characters."
    return None


async def get_asset(client: AdminKitClient, asset_id: str) -> ToolResponse:
    problem = validate_asset_id(asset_id)
    if problem is not None:
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": f"Invalid asset_id: {problem} No request was sent."},
            fix_hint="Use an asset id from list_assets (they look like ast_01H...).",
            report_url=ASSETS_PAGE,
        )
    if not client.has_api_key:
        return key_required(TOOL, "Reading your asset")
    try:
        resp = await client.call_api("GET", f"/v1/assets/{quote(asset_id, safe='')}")
    except ApiUnavailable as exc:
        if exc.status_code == 404:
            return ToolResponse(
                tool=TOOL,
                status="error",
                result={"message": "Asset not found in your organization."},
                fix_hint="Run list_assets to see the ids of the assets your API key can read.",
                report_url=ASSETS_PAGE,
            )
        return unreachable(TOOL)
    except httpx.HTTPStatusError as exc:
        return map_error(TOOL, exc.response, action="reading this asset")

    try:
        payload = resp.json()
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": "The assets API returned an unexpected response body."},
            report_url=ASSETS_PAGE,
        )

    asset = map_asset(payload)
    failing = is_failing(asset)
    if asset["status"] is None:
        summary = f"Asset {asset['value']} ({asset['kind']}) has not been checked yet."
    elif failing:
        summary = f"Asset {asset['value']} ({asset['kind']}) is failing: {asset['status']['reason']}"
    else:
        summary = f"Asset {asset['value']} ({asset['kind']}) is passing."
    return ToolResponse(
        tool=TOOL,
        status="warn" if failing else "ok",
        result={"summary": summary, "asset": asset},
        fix_hint="Open this asset in your AdminKit account to see its latest check results."
        if failing
        else None,
        report_url=ASSETS_PAGE,
    )
