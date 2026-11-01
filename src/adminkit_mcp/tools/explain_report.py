"""`explain_report` tool (spec section 18.8): plain-language AI explanation of a saved,
shared check report.

Two real calls, in order, both live on main:
1. `GET /v1/report/{token}` (M5 share-link; public, rate-limited --
   `platform/adminkit/report/router.py`) fetches the saved `CheckResultResponse` for a report
   token minted by passing `options.share` to a check.
2. `POST /v1/ai/explain` (M11; requires an authenticated `X-API-Key` --
   `platform/adminkit/ai/router.py`, `TenantDep`) asks the real Claude-based explainer to
   narrate that result, with every claim cited back to a real finding/evidence id.

`AdminKitClient` only ever attaches the `X-API-Key` a caller already configured (spec section
13.1: AI never auto-applies anything, and this tool never forges or strips auth to make the
call "work" anonymously). Every failure mode below is mapped to an honest `ToolResponse`; this
tool never fabricates or partially returns an explanation.
"""

from __future__ import annotations

from typing import Any

import httpx

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse, not_available_yet

TOOL = "explain_report"
DEFAULT_PAGE = "https://adminkit.net/"


async def explain_report(client: AdminKitClient, report_token: str) -> ToolResponse:
    try:
        report_resp = await client.call_api("GET", f"/v1/report/{report_token}")
    except ApiUnavailable:
        return ToolResponse(
            tool=TOOL,
            status="not_available",
            result={
                "message": f"No saved report for token {report_token!r} "
                "(unknown or expired share link)."
            },
            fix_hint="Share links expire after 30 days; re-run the check with sharing enabled "
            "to get a new one.",
        )
    except httpx.HTTPStatusError as exc:
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": _problem_detail(exc.response)},
        )

    check_result = report_resp.json()
    report_url = check_result.get("report_url")

    try:
        explain_resp = await client.call_api("POST", "/v1/ai/explain", json={"check_result": check_result})
    except ApiUnavailable:
        return not_available_yet(
            TOOL,
            report_url=report_url or DEFAULT_PAGE,
            detail="AI explanation is not reachable on the public API right now.",
        )
    except httpx.HTTPStatusError as exc:
        return _map_explain_error(exc.response, report_url)

    payload = explain_resp.json()
    return ToolResponse(
        tool=TOOL,
        status="ok",
        result={
            "check": payload.get("check"),
            "target": payload.get("target"),
            "model": payload.get("model"),
            "explanation": payload.get("explanation"),
            "cited_evidence_ids": payload.get("cited_evidence_ids", []),
        },
        evidence={"check_result": check_result},
        report_url=report_url,
    )


def _map_explain_error(response: httpx.Response, report_url: str | None) -> ToolResponse:
    detail = _problem_detail(response)

    if response.status_code == 503:
        return ToolResponse(
            tool=TOOL,
            status="not_available",
            result={
                "message": detail
                or "AI explanations are not enabled on this deployment yet (no AI key configured)."
            },
            fix_hint="AI explanations need an AI provider key configured on this AdminKit "
            "deployment; see the public page for current status.",
            report_url=report_url or DEFAULT_PAGE,
        )
    if response.status_code in (401, 403):
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": "Explaining a report requires an authenticated AdminKit API key (X-API-Key)."},
            report_url=report_url,
        )
    if response.status_code == 429:
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": detail or "AI daily cap or rate limit reached; retry later."},
            report_url=report_url,
        )
    if response.status_code == 502:
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": detail or "The AI explanation failed citation validation and was rejected."},
            report_url=report_url,
        )
    return ToolResponse(
        tool=TOOL,
        status="error",
        result={"message": detail or f"AI explanation request failed (HTTP {response.status_code})."},
        report_url=report_url,
    )


def _problem_detail(response: httpx.Response) -> str | None:
    try:
        payload: dict[str, Any] = response.json()
    except ValueError:
        return None
    detail = payload.get("detail") or payload.get("title")
    return str(detail) if detail else None
