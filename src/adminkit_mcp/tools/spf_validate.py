"""`spf_validate` tool (spec section 18.1 offline utility): static SPF record syntax check.

Thin wrapper over the live, no-auth `/v1/tools/spf-validate` endpoint: parses the given SPF
TXT record string only. No DNS lookup is performed and include:/redirect= chains are not
followed, so `lookup_term_count` covers this record alone — use `check_mail_auth` for a
domain's live, fully resolved SPF. The envelope status follows the API's `verdict`:
`valid` -> ok, `valid_with_warnings` -> warn, `invalid` -> fail.
"""

from __future__ import annotations

from typing import Any

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse, ToolStatus
from adminkit_mcp.tools._common import call_tools_api, invalid_input, validate_text_input

TOOL = "spf_validate"
SPF_VALIDATE_PAGE = "https://adminkit.net/tools/spf-validate/"
# Same cap as the API (`_SPF_MAX_LENGTH` in platform/adminkit/tools/service.py).
MAX_RECORD_LENGTH = 4096

_VERDICT_STATUS: dict[str, ToolStatus] = {
    "valid": "ok",
    "valid_with_warnings": "warn",
    "invalid": "fail",
}


def _first_fix_hint(findings: Any) -> str | None:
    """The message of the worst finding (error before warning), or None if there is none."""
    if not isinstance(findings, list):
        return None
    for severity in ("error", "warning"):
        for finding in findings:
            if isinstance(finding, dict) and finding.get("severity") == severity:
                message = finding.get("message")
                return str(message) if message else None
    return None


async def spf_validate(client: AdminKitClient, record: str) -> ToolResponse:
    problem = validate_text_input("record", record, max_length=MAX_RECORD_LENGTH)
    if problem is not None:
        return invalid_input(TOOL, problem, report_url=SPF_VALIDATE_PAGE)
    outcome = await call_tools_api(
        client, TOOL, "spf-validate", params={"record": record}, report_url=SPF_VALIDATE_PAGE
    )
    if isinstance(outcome, ToolResponse):
        return outcome
    payload = outcome
    findings = payload.get("findings", [])
    return ToolResponse(
        tool=TOOL,
        status=_VERDICT_STATUS.get(str(payload.get("verdict")), "error"),
        result={
            "record": payload.get("record"),
            "verdict": payload.get("verdict"),
            "has_version": payload.get("has_version"),
            "lookup_term_count": payload.get("lookup_term_count"),
            "lookup_term_limit": payload.get("lookup_term_limit"),
            "findings": findings,
        },
        evidence=payload,
        fix_hint=_first_fix_hint(findings),
        report_url=SPF_VALIDATE_PAGE,
    )
