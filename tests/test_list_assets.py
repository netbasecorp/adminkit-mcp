"""`list_assets`: read-only `GET /v1/assets` behind a configured API key. All HTTP is mocked
(`fakes/fake_api.py`); the key below is a fake placeholder, not a credential."""

from __future__ import annotations

from typing import Any

import httpx

from adminkit_mcp.client import API_KEY_HEADER, AdminKitClient
from adminkit_mcp.config import Settings, for_hosted_http
from adminkit_mcp.server import build_server
from adminkit_mcp.tools.list_assets import list_assets
from fakes.fake_api import (
    all_not_implemented_api,
    asset_payload,
    json_handler,
    make_recording_client,
    problem_payload,
)

FAKE_KEY = "ak_test_FAKE_PLACEHOLDER"
KEY_HEADERS = {API_KEY_HEADER: FAKE_KEY}

PASSING = {"passing": True, "reason": "all checks ok", "checked_at": "2026-11-15T10:00:00Z"}
FAILING = {"passing": False, "reason": "tls: certificate expired", "checked_at": "2026-11-15T10:05:00Z"}


def _client(
    calls: list[str],
    handler: Any,
    *,
    headers: dict[str, str] | None = KEY_HEADERS,
) -> AdminKitClient:
    api = make_recording_client(
        calls, {("GET", "/v1/assets"): handler}, base_url="https://api.adminkit.net", headers=headers
    )
    return AdminKitClient(api, all_not_implemented_api(base_url="https://adminkit.net"))


async def _run(client: AdminKitClient) -> dict[str, Any]:
    try:
        return (await list_assets(client)).to_dict()
    finally:
        await client.aclose()


async def test_no_api_key_returns_key_required_and_sends_no_request() -> None:
    calls: list[str] = []
    out = await _run(_client(calls, json_handler(200, {"assets": []}), headers=None))
    assert calls == []
    assert out["status"] == "error"
    assert "API key" in out["result"]["message"]
    assert "assets" not in out["result"]


async def test_sends_get_with_key_header_and_maps_passing_failing_and_unchecked() -> None:
    calls: list[str] = []
    seen_keys: list[str | None] = []
    body = {
        "assets": [
            asset_payload(
                asset_id="ast_ok",
                value="ok.example.com",
                last_checked_at="2026-11-15T10:00:00Z",
                status=PASSING,
            ),
            asset_payload(
                asset_id="ast_bad",
                kind="ip",
                value="192.0.2.10",
                last_checked_at="2026-11-15T10:05:00Z",
                status=FAILING,
            ),
            asset_payload(asset_id="ast_new", value="new.example.com", verified=False),
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        seen_keys.append(request.headers.get(API_KEY_HEADER))
        return httpx.Response(200, json=body)

    out = await _run(_client(calls, handler))

    assert calls == ["GET /v1/assets"]
    assert seen_keys == [FAKE_KEY]
    assert out["status"] == "warn"
    result = out["result"]
    assert result["count"] == 3
    assert result["failing"] == ["ast_bad"]
    assert result["not_checked"] == ["ast_new"]
    by_id = {a["id"]: a for a in result["assets"]}
    assert by_id["ast_ok"] == {
        "id": "ast_ok",
        "kind": "domain",
        "value": "ok.example.com",
        "verified": True,
        "last_checked_at": "2026-11-15T10:00:00Z",
        "status": PASSING,
    }
    assert by_id["ast_bad"]["status"] == FAILING
    assert by_id["ast_new"]["status"] is None
    assert by_id["ast_new"]["last_checked_at"] is None
    assert by_id["ast_new"]["verified"] is False
    assert out["report_url"] == "https://adminkit.net/account/assets/?utm_source=mcp"


async def test_all_passing_is_ok_with_no_fix_hint() -> None:
    body = {"assets": [asset_payload(last_checked_at="2026-11-15T10:00:00Z", status=PASSING)]}
    out = await _run(_client([], json_handler(200, body)))
    assert out["status"] == "ok"
    assert out["fix_hint"] is None
    assert out["result"]["failing"] == []


async def test_older_api_without_status_fields_maps_to_nulls() -> None:
    body = {"assets": [asset_payload(asset_id="ast_old", include_status_fields=False)]}
    out = await _run(_client([], json_handler(200, body)))
    asset = out["result"]["assets"][0]
    assert asset["status"] is None
    assert asset["last_checked_at"] is None
    assert out["result"]["not_checked"] == ["ast_old"]
    assert out["status"] == "ok"


async def test_malformed_status_maps_to_null() -> None:
    malformed: list[Any] = [
        "failing",
        {"passing": "no", "checked_at": "2026-11-15T10:00:00Z"},
        {"passing": False},
        {"reason": "x", "checked_at": "2026-11-15T10:00:00Z"},
        [],
    ]
    body = {
        "assets": [
            asset_payload(asset_id=f"ast_{i}", last_checked_at=12345, status=s)  # type: ignore[arg-type]
            for i, s in enumerate(malformed)
        ]
    }
    out = await _run(_client([], json_handler(200, body)))
    assert [a["status"] for a in out["result"]["assets"]] == [None] * len(malformed)
    assert [a["last_checked_at"] for a in out["result"]["assets"]] == [None] * len(malformed)
    assert out["result"]["failing"] == []


async def test_never_echoes_api_key_or_verification_token() -> None:
    body = {"assets": [asset_payload(status=FAILING, last_checked_at="2026-11-15T10:05:00Z")]}
    out = await _run(_client([], json_handler(200, body)))
    text = repr(out)
    assert FAKE_KEY not in text
    assert "verification_token" not in text
    assert "FAKE-TOKEN" not in text


async def test_unexpected_body_is_error_not_crash() -> None:
    out = await _run(_client([], json_handler(200, {"items": []})))
    assert out["status"] == "error"


async def test_401_returns_error_envelope() -> None:
    handler = json_handler(401, problem_payload(status=401, title="Unauthorized", detail="invalid api key"))
    out = await _run(_client([], handler))
    assert out["status"] == "error"
    assert "API key" in out["result"]["message"]
    assert FAKE_KEY not in repr(out)


async def test_403_returns_error_envelope() -> None:
    handler = json_handler(403, problem_payload(status=403, title="Forbidden", detail="forbidden"))
    out = await _run(_client([], handler))
    assert out["status"] == "error"
    assert "API key" in out["result"]["message"]


async def test_429_returns_error_envelope() -> None:
    handler = json_handler(429, problem_payload(status=429, title="Too Many Requests", detail="rate-limited"))
    out = await _run(_client([], handler))
    assert out["status"] == "error"
    assert out["result"]["message"] == "rate-limited"
    assert out["fix_hint"]


async def test_501_returns_not_available() -> None:
    out = await _run(_client([], json_handler(501, {"title": "Not Implemented", "status": 501})))
    assert out["status"] == "not_available"


async def test_list_assets_registered_and_round_trips_through_fastmcp() -> None:
    calls: list[str] = []
    client = _client(calls, json_handler(200, {"assets": [asset_payload(status=PASSING)]}))
    mcp = build_server(client)
    try:
        tools = {t.name: t for t in await mcp.list_tools()}
        assert "list_assets" in tools
        description = tools["list_assets"].description or ""
        assert "Read-only" in description
        assert "API key" in description
        content = await mcp.call_tool("list_assets", {})
    finally:
        await client.aclose()
    assert content
    assert calls == ["GET /v1/assets"]


async def test_hosted_http_settings_never_carry_a_key_so_list_assets_refuses() -> None:
    keyed = AdminKitClient.from_settings(Settings(api_key=FAKE_KEY))
    hosted = AdminKitClient.from_settings(for_hosted_http(Settings(api_key=FAKE_KEY)))
    try:
        assert keyed.has_api_key is True
        assert hosted.has_api_key is False
        out = (await list_assets(hosted)).to_dict()
    finally:
        await keyed.aclose()
        await hosted.aclose()
    assert out["status"] == "error"
    assert "API key" in out["result"]["message"]
