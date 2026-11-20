from __future__ import annotations

from typing import Any

import httpx
import pytest

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.spf_validate import MAX_RECORD_LENGTH, spf_validate
from fakes.fake_api import (
    all_not_implemented_api,
    json_handler,
    make_client,
    make_recording_client,
    problem_payload,
    spf_validate_payload,
)

API_BASE = "https://api.adminkit.net"
SITE_BASE = "https://adminkit.net"


async def _validate(payload: dict[str, Any], record: str) -> Any:
    api = make_client({("GET", "/v1/tools/spf-validate"): json_handler(200, payload)}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        return await spf_validate(client, record)
    finally:
        await client.aclose()


async def test_spf_validate_tool_valid_record_is_ok() -> None:
    payload = spf_validate_payload()
    result = await _validate(payload, "v=spf1 include:_spf.example.com -all")
    assert result.status == "ok"
    assert result.result["verdict"] == "valid"
    assert result.result["has_version"] is True
    assert result.result["lookup_term_count"] == 1
    assert result.result["lookup_term_limit"] == 10
    assert result.result["findings"] == []
    assert result.fix_hint is None
    assert result.evidence == payload
    assert result.report_url == "https://adminkit.net/tools/spf-validate/?utm_source=mcp"


async def test_spf_validate_tool_warnings_map_to_warn_with_fix_hint() -> None:
    findings: list[dict[str, Any]] = [
        {"severity": "info", "code": "x", "message": "Informational.", "term": None},
        {"severity": "warning", "code": "softfail-all", "message": "'~all' only soft-fails.", "term": "~all"},
    ]
    payload = spf_validate_payload(record="v=spf1 ~all", verdict="valid_with_warnings", findings=findings)
    result = await _validate(payload, "v=spf1 ~all")
    assert result.status == "warn"
    assert result.fix_hint == "'~all' only soft-fails."
    assert result.result["findings"] == findings


async def test_spf_validate_tool_invalid_maps_to_fail_with_worst_finding_as_hint() -> None:
    findings: list[dict[str, Any]] = [
        {
            "severity": "warning",
            "code": "permissive-all",
            "message": "'+all' passes everyone.",
            "term": "+all",
        },
        {
            "severity": "error",
            "code": "missing-version",
            "message": "Record does not start with the required 'v=spf1' term (RFC 7208 §4.5).",
            "term": None,
        },
    ]
    payload = spf_validate_payload(record="+all", verdict="invalid", findings=findings)
    result = await _validate(payload, "+all")
    assert result.status == "fail"
    assert result.result["has_version"] is False
    assert result.fix_hint is not None and "v=spf1" in result.fix_hint


async def test_spf_validate_tool_calls_correct_path_with_record_param() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["record"] = request.url.params["record"]
        return httpx.Response(200, json=spf_validate_payload())

    api = make_client({("GET", "/v1/tools/spf-validate"): handler}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        await spf_validate(client, "v=spf1 ip4:192.0.2.0/24 -all")
    finally:
        await client.aclose()
    assert seen == {"path": "/v1/tools/spf-validate", "record": "v=spf1 ip4:192.0.2.0/24 -all"}


async def test_spf_validate_tool_api_422_is_explicit_error() -> None:
    problem = problem_payload(detail="record must be a non-empty SPF TXT record string.")
    api = make_client({("GET", "/v1/tools/spf-validate"): json_handler(422, problem)}, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await spf_validate(client, "v=spf1 -all")
    finally:
        await client.aclose()
    assert result.status == "error"
    assert result.result == {"message": "record must be a non-empty SPF TXT record string."}
    assert result.report_url == "https://adminkit.net/tools/spf-validate/?utm_source=mcp"


async def test_spf_validate_tool_api_429_is_rate_limited_envelope_without_retry() -> None:
    calls: list[str] = []
    body = problem_payload(status=429, title="Too Many Requests", detail="Rate limit exceeded.")
    body["retry_after_seconds"] = 3
    api = make_recording_client(
        calls, {("GET", "/v1/tools/spf-validate"): json_handler(429, body)}, base_url=API_BASE
    )
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await spf_validate(client, "v=spf1 -all")
    finally:
        await client.aclose()
    assert calls == ["GET /v1/tools/spf-validate"]
    assert result.status == "error"
    assert result.result["rate_limited"] is True
    assert result.result["retry_after_seconds"] == 3
    assert "retry in 3 s" in result.result["message"]


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ("", "record must not be empty."),
        ("\t \n", "record must not be empty."),
        ("v=spf1 " + "a" * MAX_RECORD_LENGTH, f"record must be at most {MAX_RECORD_LENGTH} characters."),
    ],
)
async def test_spf_validate_tool_rejects_bad_input_without_a_request(record: str, message: str) -> None:
    calls: list[str] = []
    routes: dict[Any, Any] = {}
    api = make_recording_client(calls, routes, base_url=API_BASE)
    client = AdminKitClient(api, all_not_implemented_api(base_url=SITE_BASE))
    try:
        result = await spf_validate(client, record)
    finally:
        await client.aclose()
    assert calls == []
    assert result.status == "error"
    assert result.result == {"message": message}


async def test_spf_validate_tool_accepts_record_at_the_length_cap() -> None:
    record = "v=spf1 " + "a" * (MAX_RECORD_LENGTH - len("v=spf1 "))
    result = await _validate(spf_validate_payload(record=record), record)
    assert result.status == "ok"
