from __future__ import annotations

from typing import Any

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.tools.check_mail_auth import check_mail_auth
from fakes.fake_api import (
    all_not_implemented_api,
    check_result_payload,
    dmarc_payload,
    json_handler,
    make_client,
    spf_payload,
)


async def test_check_mail_auth_uses_live_api_when_available() -> None:
    api = make_client(
        {
            ("POST", "/v1/check/mail"): json_handler(
                200, check_result_payload(check="mail.auth", target="example.com")
            )
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_mail_auth(client, "example.com")
    finally:
        await client.aclose()
    assert result.status == "ok"


async def test_check_mail_auth_falls_back_and_is_ok_when_well_configured() -> None:
    api = all_not_implemented_api()
    site = make_client(
        {
            ("GET", "/api/mailauth"): lambda request: json_handler(
                200,
                spf_payload(domain="example.com")
                if request.url.params.get("kind") == "spf"
                else dmarc_payload(domain="example.com"),
            )(request)
        },
        base_url="https://adminkit.net",
    )
    client = AdminKitClient(api, site)
    try:
        result = await check_mail_auth(client, "example.com")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.fix_hint is None


async def test_check_mail_auth_flags_missing_spf() -> None:
    api = all_not_implemented_api()
    site = make_client(
        {
            ("GET", "/api/mailauth"): lambda request: json_handler(
                200,
                spf_payload(domain="example.com", status="not-found")
                if request.url.params.get("kind") == "spf"
                else dmarc_payload(domain="example.com"),
            )(request)
        },
        base_url="https://adminkit.net",
    )
    client = AdminKitClient(api, site)
    try:
        result = await check_mail_auth(client, "example.com")
    finally:
        await client.aclose()
    assert result.status == "warn"
    assert result.fix_hint is not None and "SPF" in result.fix_hint


async def test_check_mail_auth_flags_permissive_spf() -> None:
    api = all_not_implemented_api()
    site = make_client(
        {
            ("GET", "/api/mailauth"): lambda request: json_handler(
                200,
                spf_payload(domain="example.com", all_mechanism="+all")
                if request.url.params.get("kind") == "spf"
                else dmarc_payload(domain="example.com"),
            )(request)
        },
        base_url="https://adminkit.net",
    )
    client = AdminKitClient(api, site)
    try:
        result = await check_mail_auth(client, "example.com")
    finally:
        await client.aclose()
    assert result.status == "warn"
    assert result.fix_hint is not None and "+all" in result.fix_hint


async def _run_with_dmarc(dmarc: dict[str, Any]) -> ToolResponse:
    api = all_not_implemented_api()
    site = make_client(
        {
            ("GET", "/api/mailauth"): lambda request: json_handler(
                200,
                spf_payload(domain="example.com") if request.url.params.get("kind") == "spf" else dmarc,
            )(request)
        },
        base_url="https://adminkit.net",
    )
    client = AdminKitClient(api, site)
    try:
        return await check_mail_auth(client, "example.com")
    finally:
        await client.aclose()


def _site_dmarc(record: str, tags: dict[str, str], **extra: Any) -> dict[str, Any]:
    # Shape of /api/mailauth?kind=dmarc (site/functions/api/mailauth.ts DmarcResult).
    return {
        "domain": "example.com",
        "status": "ok",
        "record": record,
        "tags": tags,
        "findings": [],
        "suggestedRecord": "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com; adkim=r; aspf=r",
        **extra,
    }


async def test_check_mail_auth_no_p_with_valid_rua_reads_policy_none() -> None:
    # RFC 9989 §4.10.1: no p but a valid rua -> the site reports policy "none" while tags has no "p".
    dmarc = _site_dmarc(
        "v=DMARC1; rua=mailto:agg@example.com",
        {"v": "DMARC1", "rua": "mailto:agg@example.com"},
        policy="none",
    )
    result = await _run_with_dmarc(dmarc)
    assert result.status == "warn"
    assert result.result["dmarc_policy"] == "none"
    assert result.fix_hint is not None and "monitoring-only (p=none)" in result.fix_hint


async def test_check_mail_auth_policy_null_is_no_valid_policy() -> None:
    dmarc = _site_dmarc("v=DMARC1; p=maybe", {"v": "DMARC1", "p": "maybe"}, policy=None)
    result = await _run_with_dmarc(dmarc)
    assert result.status == "warn"
    assert result.result["dmarc_policy"] is None
    assert result.fix_hint is not None and "no valid policy" in result.fix_hint


async def test_check_mail_auth_policy_field_wins_over_tags_p() -> None:
    # policy null wins even if tags.p looks valid; policy "reject" with no p in tags is clean.
    result = await _run_with_dmarc(_site_dmarc("v=DMARC1; p=none", {"v": "DMARC1", "p": "none"}, policy=None))
    assert result.result["dmarc_policy"] is None
    result = await _run_with_dmarc(_site_dmarc("v=DMARC1; p=Reject", {"v": "DMARC1"}, policy="reject"))
    assert result.status == "ok"
    assert result.fix_hint is None


async def test_check_mail_auth_old_deployment_falls_back_to_tags_p() -> None:
    # No "policy" field (site deployment before RFC 9989 parity): use tags.p.
    result = await _run_with_dmarc(_site_dmarc("v=DMARC1; p=none", {"v": "DMARC1", "p": "none"}))
    assert result.status == "warn"
    assert result.result["dmarc_policy"] == "none"
    result = await _run_with_dmarc(_site_dmarc("v=DMARC1; p=reject", {"v": "DMARC1", "p": "reject"}))
    assert result.status == "ok"
    assert result.result["dmarc_policy"] == "reject"


async def test_check_mail_auth_missing_dmarc_suggests_p_none() -> None:
    result = await _run_with_dmarc(dmarc_payload(domain="example.com", status="not-found"))
    assert result.status == "warn"
    assert result.fix_hint is not None and "p=none" in result.fix_hint
