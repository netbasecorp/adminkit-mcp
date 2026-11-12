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


def _spf_permerror(spf: dict[str, Any]) -> bool:
    """Whether an /api/mailauth SPF result is a permanent error (RFC 7208), as spf.py's FAIL.

    Reads ``permerror`` (lookup/void-lookup limits, syntax errors, broken include/redirect targets,
    loops); falls back to ``lookupLimitExceeded`` for a site deployment older than that field.
    """
    if "permerror" in spf:
        return spf["permerror"] is True
    return spf.get("lookupLimitExceeded") is True


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
    spf_status = spf.get("status")
    spf_found = spf_status == "ok"
    spf_permerror = spf_found and _spf_permerror(spf)
    # The effective "all" only means something when the walk finished without a permerror.
    spf_all = spf.get("allMechanism") if spf_found and not spf_permerror else None
    dmarc_found = dmarc.get("status") == "ok"
    dmarc_policy = _dmarc_policy(dmarc) if dmarc_found else None
    # Same verdict as checks/.../mail/spf.py: more than one record, a permerror or "+all" fail; only
    # "-all" is clean, while "~all" (low), "?all" and no "all" (medium) are warnings.
    failures = [spf_status == "multiple-records", spf_permerror, spf_all == "+all"]
    problems = [
        not spf_found,
        spf_permerror,
        not dmarc_found,
        spf_found and not spf_permerror and spf_all != "-all",
        dmarc_found and dmarc_policy is None,
        dmarc_policy == "none",
    ]
    status: ToolStatus = "fail" if any(failures) else "warn" if any(problems) else "ok"

    evidence: dict[str, Any] = {"spf": spf, "dmarc": dmarc}
    fix_hint = None
    if spf_status == "multiple-records":
        fix_hint = (
            "Merge the domain's SPF records into a single v=spf1 TXT record; "
            "more than one is a permanent error (RFC 7208 §4.5)."
        )
    elif not spf_found:
        fix_hint = "Publish an SPF (v=spf1) TXT record for this domain."
    elif spf_permerror:
        fix_hint = (
            "The SPF record is a permanent error (permerror) for receivers: fix the problem in the findings "
            "(over 10 DNS lookups, over 2 void lookups, a syntax error, or a broken include/redirect)."
        )
    elif not dmarc_found:
        fix_hint = (
            "Publish a DMARC (_dmarc TXT) record for this domain, starting with p=none and a rua you read."
        )
    elif spf_all == "+all":
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
    elif spf_all in ("?all", None):
        fix_hint = (
            "The SPF record has no terminating all (or ends in ?all), so unlisted senders get a neutral "
            "result; end it with ~all while testing, then -all."
        )
    elif spf_all == "~all":
        fix_hint = "Once all legitimate senders are listed in SPF, change ~all to -all."

    return ToolResponse(
        tool=TOOL,
        status=status,
        result={
            "domain": domain,
            "spf_status": spf_status,
            "spf_all": spf_all,
            "spf_permerror": spf_permerror,
            "dmarc_status": dmarc.get("status"),
            "dmarc_policy": dmarc_policy,
            "findings": findings,
        },
        evidence=evidence,
        fix_hint=fix_hint,
        report_url=MAIL_AUTH_PAGE,
    )
