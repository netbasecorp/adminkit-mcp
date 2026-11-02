"""Shared, citation-friendly response envelope every tool returns (spec section 18.8).

Every tool returns the same four fields so an agent can cite a result consistently:
`result` (the structured answer), `evidence` (raw data backing it), `fix_hint` (a short,
actionable next step, or None when there is nothing to fix), and `report_url` (a link to a
shareable AdminKit page, or None when the API has not issued one yet).

Every non-None `report_url` is tagged with `utm_source=mcp` (M5 plan row A16) so a click
back from an agent's result is attributable as MCP referral traffic, whether the link is
the tool's own public page or a report link the Check API issued for this call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ToolStatus = Literal["ok", "warn", "fail", "error", "skipped", "not_available"]

UTM_SOURCE = "mcp"


def with_mcp_utm(url: str | None) -> str | None:
    """Appends `utm_source=mcp` to a backlink's query string. Idempotent (a URL that
    already carries `utm_source` is returned unchanged) and a no-op for `None`/empty."""
    if not url:
        return url
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    if any(key == "utm_source" for key, _ in query):
        return url
    query.append(("utm_source", UTM_SOURCE))
    return urlunsplit(parts._replace(query=urlencode(query)))


@dataclass
class ToolResponse:
    tool: str
    status: ToolStatus
    result: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    fix_hint: str | None = None
    report_url: str | None = None

    def __post_init__(self) -> None:
        self.report_url = with_mcp_utm(self.report_url)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "result": self.result,
            "evidence": self.evidence,
            "fix_hint": self.fix_hint,
            "report_url": self.report_url,
        }


def not_available_yet(tool: str, *, report_url: str, detail: str) -> ToolResponse:
    """Standard "the real API hasn't shipped this yet" response. Never fabricates data."""
    return ToolResponse(
        tool=tool,
        status="not_available",
        result={"message": detail},
        evidence={},
        fix_hint="This endpoint is not live yet; see the public page for what is available today.",
        report_url=report_url,
    )
