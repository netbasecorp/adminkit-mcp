"""Shared helpers for the read-only account asset tools (`list_assets`, `get_asset`): the
"API key required" refusal, the per-asset field mapping (`AssetResponse` in
`platform/openapi.stub.yaml`), and the HTTP error mapping.

Per asset only `id`, `kind`, `value`, `verified`, `value_valid`, `last_checked_at`, and
`status` (`{passing, reason, checked_at}`, or `None` = "not checked yet") are returned -- never
the asset's `verification_token`. An older API without `last_checked_at`/`status`, or a
malformed `status` object, maps to `None` rather than a guess or a crash.

`value_valid` is `False` only when the API says so: the stored value does not parse for its kind
(a legacy row), so it cannot be verified or checked and must be removed and added again. An older
API without the field maps to `True` (the contract default), as does any non-boolean value.
"""

from __future__ import annotations

from typing import Any

import httpx

from adminkit_mcp.envelope import ToolResponse

ASSETS_PAGE = "https://adminkit.net/account/assets/"


def key_required(tool: str, action: str) -> ToolResponse:
    """`action` is the sentence subject, e.g. "Listing your assets"."""
    return ToolResponse(
        tool=tool,
        status="error",
        result={
            "message": f"{action} requires an authenticated AdminKit API key (X-API-Key). "
            "Set ADMINKIT_API_KEY for this MCP server; no request was sent."
        },
        fix_hint="Create an API key in your AdminKit account and set ADMINKIT_API_KEY.",
        report_url=ASSETS_PAGE,
    )


def unreachable(tool: str) -> ToolResponse:
    return ToolResponse(
        tool=tool,
        status="not_available",
        result={"message": "The assets API could not be reached right now."},
        fix_hint="Retry shortly, or see your assets in the AdminKit account page.",
        report_url=ASSETS_PAGE,
    )


def map_asset(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "kind": item.get("kind"),
        "value": item.get("value"),
        "verified": item.get("verified") is True,
        "value_valid": item.get("value_valid") is not False,
        "last_checked_at": _str_or_none(item.get("last_checked_at")),
        "status": _map_status(item.get("status")),
    }


def is_failing(asset: dict[str, Any]) -> bool:
    return asset["status"] is not None and asset["status"]["passing"] is False


def has_invalid_value(asset: dict[str, Any]) -> bool:
    return asset["value_valid"] is False


INVALID_VALUE_HINT = (
    "Remove each asset with value_valid=false in your AdminKit account and add it again: its stored "
    "value does not parse for its kind, so it cannot be verified or checked."
)


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


def map_error(tool: str, response: httpx.Response, *, action: str) -> ToolResponse:
    """Maps a 4xx/5xx (other than 404/501, which the client raises as `ApiUnavailable`).
    `action` is lowercase for use mid-sentence, e.g. "listing assets"."""
    detail = _problem_detail(response)
    if response.status_code in (401, 403):
        message = f"The AdminKit API rejected the configured API key (X-API-Key) for {action}."
        fix_hint: str | None = "Check that ADMINKIT_API_KEY is a valid, unrevoked key for your account."
    elif response.status_code == 429:
        message = detail or "Rate limit reached for the assets API; retry later."
        fix_hint = "Wait a moment and retry."
    else:
        message = detail or f"{action[:1].upper()}{action[1:]} failed (HTTP {response.status_code})."
        fix_hint = None
    return ToolResponse(
        tool=tool, status="error", result={"message": message}, fix_hint=fix_hint, report_url=ASSETS_PAGE
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
