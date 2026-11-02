from __future__ import annotations

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.explain_report import explain_report
from fakes.fake_api import (
    ai_explain_payload,
    all_not_implemented_api,
    check_result_payload,
    json_handler,
    make_client,
    make_recording_client,
    problem_payload,
)


async def test_explain_report_fetches_report_then_calls_ai() -> None:
    calls: list[str] = []
    report = check_result_payload(
        check="spf",
        target="example.com",
        status="warn",
        summary="SPF has too many lookups",
        report_url="https://api.adminkit.net/v1/report/rpt_01H8",
    )
    explanation = ai_explain_payload(check="spf", target="example.com")
    api = make_recording_client(
        calls,
        {
            ("GET", "/v1/report/rpt_01H8"): json_handler(200, report),
            ("POST", "/v1/ai/explain"): json_handler(200, explanation),
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await explain_report(client, "rpt_01H8")
    finally:
        await client.aclose()

    assert result.status == "ok"
    assert result.result["explanation"] == explanation["explanation"]
    assert result.result["cited_evidence_ids"] == explanation["cited_evidence_ids"]
    assert result.report_url == report["report_url"] + "?utm_source=mcp"
    assert calls == ["GET /v1/report/rpt_01H8", "POST /v1/ai/explain"]
    assert "/v1/reports/rpt_01H8/explain" not in calls
    assert not any(path.startswith("/v1/reports/") for _method, path in (c.split(" ", 1) for c in calls))


async def test_explain_report_ai_disabled_returns_honest_not_available() -> None:
    report = check_result_payload(check="spf", target="example.com", status="ok", summary="All clear")
    api = make_client(
        {
            ("GET", "/v1/report/rpt_01H8"): json_handler(200, report),
            ("POST", "/v1/ai/explain"): json_handler(
                503,
                problem_payload(
                    status=503,
                    title="Service Unavailable",
                    detail="AI explanation is disabled: no ADMINKIT_CLAUDE_API_KEY is configured.",
                    type_="https://adminkit.net/problems/ai-disabled",
                ),
            ),
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await explain_report(client, "rpt_01H8")
    finally:
        await client.aclose()

    assert result.status == "not_available"
    assert "explanation" not in result.result
    assert "disabled" in result.result["message"].lower() or "key" in result.result["message"].lower()


async def test_explain_report_unknown_token_is_honest_not_available() -> None:
    api = make_client(
        {
            ("GET", "/v1/report/rpt_missing"): json_handler(
                404, problem_payload(status=404, title="Not Found", detail="unknown or expired report link.")
            ),
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await explain_report(client, "rpt_missing")
    finally:
        await client.aclose()

    assert result.status == "not_available"
    assert "rpt_missing" in result.result["message"]
    assert "explanation" not in result.result


async def test_explain_report_requires_auth() -> None:
    report = check_result_payload(check="spf", target="example.com", status="ok", summary="All clear")
    api = make_client(
        {
            ("GET", "/v1/report/rpt_01H8"): json_handler(200, report),
            ("POST", "/v1/ai/explain"): json_handler(
                401,
                problem_payload(
                    status=401,
                    title="Unauthorized",
                    detail="an X-API-Key is required for this endpoint.",
                    type_="https://adminkit.net/problems/missing-api-key",
                ),
            ),
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await explain_report(client, "rpt_01H8")
    finally:
        await client.aclose()

    assert result.status == "error"
    assert "api key" in result.result["message"].lower() or "X-API-Key" in result.result["message"]
    assert "explanation" not in result.result


async def test_explain_report_daily_cap_is_honest_error() -> None:
    report = check_result_payload(check="spf", target="example.com", status="ok", summary="All clear")
    api = make_client(
        {
            ("GET", "/v1/report/rpt_01H8"): json_handler(200, report),
            ("POST", "/v1/ai/explain"): json_handler(
                429,
                problem_payload(
                    status=429,
                    title="Too Many Requests",
                    detail="daily AI budget exceeded for this organization.",
                    type_="https://adminkit.net/problems/ai-daily-cap",
                ),
            ),
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await explain_report(client, "rpt_01H8")
    finally:
        await client.aclose()

    assert result.status == "error"
    assert result.result["message"] == "daily AI budget exceeded for this organization."


async def test_explain_report_citation_invalid_fails_closed() -> None:
    report = check_result_payload(check="spf", target="example.com", status="ok", summary="All clear")
    api = make_client(
        {
            ("GET", "/v1/report/rpt_01H8"): json_handler(200, report),
            ("POST", "/v1/ai/explain"): json_handler(
                502,
                problem_payload(
                    status=502,
                    title="Bad Gateway",
                    detail="AI explanation failed citation validation: missing evidence id.",
                    type_="https://adminkit.net/problems/ai-citation-invalid",
                ),
            ),
        },
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await explain_report(client, "rpt_01H8")
    finally:
        await client.aclose()

    assert result.status == "error"
    assert "citation" in result.result["message"].lower()
    assert "explanation" not in result.result
