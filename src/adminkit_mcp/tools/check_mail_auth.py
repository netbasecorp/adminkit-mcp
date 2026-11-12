"""`check_mail_auth` tool (spec section 18.8): SPF + DMARC posture for a domain.

DKIM is intentionally left out of the automatic summary: `/api/mailauth?kind=dkim`
requires a selector, which is not knowable without a hint (common ones are listed in the
AdminKit DKIM tool page) or the DNS admin telling you. `explain_report`/the DKIM tool page
cover it once a selector is known.
"""

from __future__ import annotations

from typing import Any

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse, ToolStatus
from adminkit_mcp.tools._common import map_check_result

TOOL = "check_mail_auth"
MAIL_AUTH_PAGE = "https://adminkit.net/tools/spf-check/"
_DMARC_POLICIES = frozenset({"none", "quarantine", "reject"})


def _dmarc_policy(dmarc: dict[str, Any]) -> str | None:
    """Policy in effect from an /api/mailauth DMARC result.

    Uses the ``policy`` field (RFC 9989 §4.10.1: a missing ``p`` with a valid ``rua`` is ``none``;
    ``null`` means no valid policy). Falls back to ``tags.p`` only when ``policy`` is absent (a site
    deployment older than that field).
    """
    policy = dmarc["policy"] if "policy" in dmarc else (dmarc.get("tags") or {}).get("p")
    if not isinstance(policy, str):
        return None
    policy = policy.lower()
    return policy if policy in _DMARC_POLICIES else None


async def check_mail_auth(client: AdminKitClient, domain: str) -> ToolResponse:
    try:
        resp = await client.call_api("POST", "/v1/check/mail", json={"target": domain, "options": {}})
    except ApiUnavailable:
        return await _from_site(client, domain)
    return map_check_result(TOOL, resp.json(), fallback_report_url=MAIL_AUTH_PAGE)


async def _from_site(client: AdminKitClient, domain: str) -> ToolResponse:
    spf_resp = await client.call_site("/api/mailauth", params={"kind": "spf", "domain": domain})
    dmarc_resp = await client.call_site("/api/mailauth", params={"kind": "dmarc", "domain": domain})
    spf = spf_resp.json()
    dmarc = dmarc_resp.json()

    findings = list(spf.get("findings", [])) + list(dmarc.get("findings", []))
    dmarc_found = dmarc.get("status") == "ok"
    dmarc_policy = _dmarc_policy(dmarc) if dmarc_found else None
    problems = [
        spf.get("status") != "ok",
        not dmarc_found,
        spf.get("allMechanism") == "+all",
        dmarc_found and dmarc_policy is None,
        dmarc_policy == "none",
    ]
    status: ToolStatus = "warn" if any(problems) else "ok"

    evidence: dict[str, Any] = {"spf": spf, "dmarc": dmarc}
    fix_hint = None
    if spf.get("status") != "ok":
        fix_hint = "Publish an SPF (v=spf1) TXT record for this domain."
    elif not dmarc_found:
        fix_hint = (
            "Publish a DMARC (_dmarc TXT) record for this domain, starting with p=none and a rua you read."
        )
    elif spf.get("allMechanism") == "+all":
        fix_hint = (
            "Replace +all in the SPF record with -all or ~all; +all allows anyone to send as this domain."
        )
    elif dmarc_policy is None:
        fix_hint = (
            "The DMARC record has no valid policy, so receivers apply no DMARC processing; "
            "add p=none (monitoring) with a rua you read."
        )
    elif dmarc_policy == "none":
        fix_hint = (
            "DMARC is monitoring-only (p=none); move to p=quarantine or p=reject once reports look clean."
        )

    return ToolResponse(
        tool=TOOL,
        status=status,
        result={
            "domain": domain,
            "spf_status": spf.get("status"),
            "dmarc_status": dmarc.get("status"),
            "dmarc_policy": dmarc_policy,
            "findings": findings,
        },
        evidence=evidence,
        fix_hint=fix_hint,
        report_url=MAIL_AUTH_PAGE,
    )
