"""Shared helpers for the tool modules: calling the Check API and mapping its
`CheckResultResponse` shape (see `platform/openapi.stub.yaml`) into a `ToolResponse`."""

from __future__ import annotations

from typing import Any

import httpx

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse, not_available_yet


def map_check_result(tool: str, payload: dict[str, Any]) -> ToolResponse:
    """Maps a `CheckResultResponse` JSON body (platform/openapi.stub.yaml) to a ToolResponse."""
    status = payload.get("status", "error")
    findings = payload.get("findings", [])
    fix_hint = findings[0].get("fix_hint") if findings and isinstance(findings[0], dict) else None
    return ToolResponse(
        tool=tool,
        status=status,
        result={
            "check": payload.get("check"),
            "target": payload.get("target"),
            "summary": payload.get("summary", ""),
            "findings": findings,
            "score": payload.get("score"),
        },
        evidence=payload.get("evidence", {}),
        fix_hint=fix_hint,
        report_url=payload.get("report_url"),
    )


async def run_check(
    client: AdminKitClient, tool: str, kind: str, target: str, *, options: dict[str, Any] | None = None
) -> ToolResponse | None:
    """POSTs `/v1/check/{kind}`. Returns None on 404/501 so the caller can fall back."""
    try:
        resp = await client.call_api(
            "POST", f"/v1/check/{kind}", json={"target": target, "options": options or {}}
        )
    except ApiUnavailable:
        return None
    return map_check_result(tool, resp.json())


def not_available(tool: str, *, page: str, what: str) -> ToolResponse:
    return not_available_yet(
        tool,
        report_url=f"https://adminkit.net{page}",
        detail=f"{what} is not live on the public Check API yet. See the public tool page for current "
        "status.",
    )


async def call_tools_api(
    client: AdminKitClient, tool: str, path: str, *, params: dict[str, Any], report_url: str
) -> dict[str, Any] | ToolResponse:
    """GETs `/v1/tools/{path}` (spec section 18.1 offline utilities: subnet/ip/mac/UA math).

    These routes are always live and never fall back to a site function, but they do
    reject malformed input with a 422 problem document (`platform/adminkit/tools/service.py`).
    Returns the parsed JSON body on success, or an "error"/"not_available" `ToolResponse` —
    callers must check `isinstance(result, ToolResponse)` before treating it as a payload.
    """
    try:
        resp = await client.call_api("GET", f"/v1/tools/{path}", params=params)
    except ApiUnavailable as exc:
        return not_available_yet(
            tool,
            report_url=report_url,
            detail=f"/v1/tools/{path} is not reachable on the public API right now ({exc.detail}).",
        )
    except httpx.HTTPStatusError as exc:
        return ToolResponse(
            tool=tool,
            status="error",
            result={"message": _problem_detail(exc.response)},
            report_url=report_url,
        )
    payload: dict[str, Any] = resp.json()
    return payload


def _problem_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"Invalid input (HTTP {response.status_code})."
    detail = payload.get("detail") or payload.get("title")
    return str(detail) if detail else f"Invalid input (HTTP {response.status_code})."
