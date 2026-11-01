from __future__ import annotations

import httpx

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.check_domain import check_domain
from fakes.fake_api import Handler, all_not_implemented_api, check_result_payload, json_handler, make_client


async def test_check_domain_not_available_when_all_sub_checks_are_501() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_domain(client, "example.com")
    finally:
        await client.aclose()
    assert result.status == "not_available"
    assert result.report_url == "https://adminkit.net/tools/whois/"


async def test_check_domain_aggregates_available_sub_checks() -> None:
    api = make_client(
        {
            ("POST", "/v1/check/whois"): json_handler(
                200, check_result_payload(check="whois", target="example.com", status="ok")
            ),
            ("POST", "/v1/check/tls"): json_handler(
                200, check_result_payload(check="tls", target="example.com", status="warn")
            ),
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_domain(client, "example.com")
    finally:
        await client.aclose()
    assert result.status == "warn"
    assert set(result.result["checks"].keys()) == {"whois", "tls"}


async def test_check_domain_uses_http_headers_kind() -> None:
    """Regression test for the http -> http-headers wiring bug: the HTTP sub-check must hit
    `/v1/check/http-headers`, never the nonexistent `/v1/check/http`, and its findings must
    surface in the aggregate."""
    seen_paths: list[str] = []

    def recording_handler(check: str, status: str, findings: list[dict[str, object]]) -> Handler:
        def handler(request: httpx.Request) -> httpx.Response:
            seen_paths.append(request.url.path)
            return httpx.Response(
                200,
                json=check_result_payload(
                    check=check, target="example.com", status=status, findings=findings
                ),
            )

        return handler

    api = make_client(
        {
            ("POST", "/v1/check/whois"): recording_handler("whois", "ok", []),
            ("POST", "/v1/check/tls"): recording_handler("tls", "ok", []),
            ("POST", "/v1/check/http-headers"): recording_handler(
                "http-headers",
                "warn",
                [{"id": "http.missing_hsts", "fix_hint": "Add Strict-Transport-Security."}],
            ),
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_domain(client, "example.com")
    finally:
        await client.aclose()

    assert "/v1/check/http-headers" in seen_paths
    assert "/v1/check/http" not in seen_paths
    assert set(result.result["checks"].keys()) == {"whois", "tls", "http-headers"}
    http_headers_result = result.result["checks"]["http-headers"]
    assert http_headers_result["result"]["findings"] == [
        {"id": "http.missing_hsts", "fix_hint": "Add Strict-Transport-Security."}
    ]
    assert result.status == "warn"


async def test_check_domain_fail_outranks_warn() -> None:
    api = make_client(
        {
            ("POST", "/v1/check/whois"): json_handler(
                200, check_result_payload(check="whois", target="example.com", status="warn")
            ),
            ("POST", "/v1/check/tls"): json_handler(
                200, check_result_payload(check="tls", target="example.com", status="fail")
            ),
            ("POST", "/v1/check/http-headers"): json_handler(
                200, check_result_payload(check="http-headers", target="example.com", status="ok")
            ),
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await check_domain(client, "example.com")
    finally:
        await client.aclose()
    assert result.status == "fail"
    assert set(result.result["checks"].keys()) == {"whois", "tls", "http-headers"}
