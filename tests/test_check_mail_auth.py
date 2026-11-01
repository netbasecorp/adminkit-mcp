from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
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
