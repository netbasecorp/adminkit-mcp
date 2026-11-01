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


async def check_mail_auth(client: AdminKitClient, domain: str) -> ToolResponse:
    try:
        resp = await client.call_api("POST", "/v1/check/mail", json={"target": domain, "options": {}})
    except ApiUnavailable:
        return await _from_site(client, domain)
    return map_check_result(TOOL, resp.json())


async def _from_site(client: AdminKitClient, domain: str) -> ToolResponse:
    spf_resp = await client.call_site("/api/mailauth", params={"kind": "spf", "domain": domain})
    dmarc_resp = await client.call_site("/api/mailauth", params={"kind": "dmarc", "domain": domain})
    spf = spf_resp.json()
    dmarc = dmarc_resp.json()

    findings = list(spf.get("findings", [])) + list(dmarc.get("findings", []))
    problems = [
        spf.get("status") != "ok",
        dmarc.get("status") != "ok",
        spf.get("allMechanism") == "+all",
        dmarc.get("tags", {}).get("p") == "none",
    ]
    status: ToolStatus = "warn" if any(problems) else "ok"

    evidence: dict[str, Any] = {"spf": spf, "dmarc": dmarc}
    fix_hint = None
    if spf.get("status") != "ok":
        fix_hint = "Publish an SPF (v=spf1) TXT record for this domain."
    elif dmarc.get("status") != "ok":
        fix_hint = "Publish a DMARC (_dmarc TXT) record for this domain."
    elif spf.get("allMechanism") == "+all":
        fix_hint = (
            "Replace +all in the SPF record with -all or ~all; +all allows anyone to send as this domain."
        )
    elif dmarc.get("tags", {}).get("p") == "none":
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
            "findings": findings,
        },
        evidence=evidence,
        fix_hint=fix_hint,
        report_url=MAIL_AUTH_PAGE,
    )
