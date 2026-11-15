"""`list_assets` tool: read-only list of the caller's own AdminKit assets with their
stored monitored status (L0 monitoring), so an agent can answer "which of my assets are
failing?".

One real call: `GET /v1/assets` (`AssetListResponse` in `platform/openapi.stub.yaml`), which
needs an authenticated `X-API-Key`. Without a configured key this tool returns an "API key
required" result and sends no request at all (the hosted HTTP endpoint never forwards a key,
so there it always answers that way). Nothing is created, verified, checked, or deleted.

Per asset only `id`, `kind`, `value`, `verified`, `last_checked_at`, and `status`
(`{passing, reason, checked_at}`, or `None` = "not checked yet") are returned -- never the
asset's `verification_token`. An older API without `last_checked_at`/`status`, or a
malformed `status` object, maps to `None` rather than a guess or a crash.
"""

from __future__ import annotations

from typing import Any

import httpx

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse

TOOL = "list_assets"
ASSETS_PAGE = "https://adminkit.net/account/assets/"
KEY_REQUIRED_MESSAGE = (
    "Listing your assets requires an authenticated AdminKit API key (X-API-Key). "
    "Set ADMINKIT_API_KEY for this MCP server; no request was sent."
)


async def list_assets(client: AdminKitClient) -> ToolResponse:
    if not client.has_api_key:
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": KEY_REQUIRED_MESSAGE},
            fix_hint="Create an API key in your AdminKit account and set ADMINKIT_API_KEY.",
            report_url=ASSETS_PAGE,
        )
    try:
        resp = await client.call_api("GET", "/v1/assets")
    except ApiUnavailable:
        return ToolResponse(
            tool=TOOL,
            status="not_available",
            result={"message": "The assets API could not be reached right now."},
            fix_hint="Retry shortly, or see your assets in the AdminKit account page.",
            report_url=ASSETS_PAGE,
        )
    except httpx.HTTPStatusError as exc:
        return _map_error(exc.response)

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

    assets = [_map_asset(item) for item in raw_assets if isinstance(item, dict)]
    failing = [a["id"] for a in assets if a["status"] is not None and a["status"]["passing"] is False]
    not_checked = [a["id"] for a in assets if a["status"] is None]
    return ToolResponse(
        tool=TOOL,
        status="warn" if failing else "ok",
        result={
            "summary": f"{len(assets)} asset(s): {len(failing)} failing, "
            f"{len(assets) - len(failing) - len(not_checked)} passing, {len(not_checked)} not checked yet.",
            "count": len(assets),
            "failing": failing,
            "not_checked": not_checked,
            "assets": assets,
        },
        fix_hint="Open the failing asset in your AdminKit account to see its latest check results."
        if failing
        else None,
        report_url=ASSETS_PAGE,
    )


def _map_asset(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "kind": item.get("kind"),
        "value": item.get("value"),
        "verified": item.get("verified") is True,
        "last_checked_at": _str_or_none(item.get("last_checked_at")),
        "status": _map_status(item.get("status")),
    }


def _map_status(raw: Any) -> dict[str, Any] | None:
    """`AssetStatusResponse` -> dict, or None when absent or malformed (`passing` must be a
    bool and `checked_at` a string, both required by the contract)."""
    if not isinstance(raw, dict):
        return None
    passing = raw.get("passing")
    checked_at = raw.get("checked_at")
    if not isinstance(passing, bool) or not isinstance(checked_at, str):
        return None
    reason = raw.get("reason")
    return {"passing": passing, "reason": reason if isinstance(reason, str) else "", "checked_at": checked_at}


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _map_error(response: httpx.Response) -> ToolResponse:
    detail = _problem_detail(response)
    if response.status_code in (401, 403):
        message = "The AdminKit API rejected the configured API key (X-API-Key) for listing assets."
        fix_hint: str | None = "Check that ADMINKIT_API_KEY is a valid, unrevoked key for your account."
    elif response.status_code == 429:
        message = detail or "Rate limit reached for the assets API; retry later."
        fix_hint = "Wait a moment and retry."
    else:
        message = detail or f"Listing assets failed (HTTP {response.status_code})."
        fix_hint = None
    return ToolResponse(
        tool=TOOL, status="error", result={"message": message}, fix_hint=fix_hint, report_url=ASSETS_PAGE
    )


def _problem_detail(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail") or payload.get("title")
    return str(detail) if detail else None
