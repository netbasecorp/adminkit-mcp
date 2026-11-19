"""`get_asset`: read-only `GET /v1/assets/{asset_id}` behind a configured API key. All HTTP is
mocked (`fakes/fake_api.py`); the key below is a fake placeholder, not a credential."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from adminkit_mcp.client import API_KEY_HEADER, AdminKitClient
from adminkit_mcp.config import Settings, for_hosted_http
from adminkit_mcp.server import build_server
from adminkit_mcp.tools.get_asset import get_asset
from fakes.fake_api import (
    all_not_implemented_api,
    asset_payload,
    json_handler,
    make_recording_client,
    problem_payload,
)

FAKE_KEY = "ak_test_FAKE_PLACEHOLDER"
KEY_HEADERS = {API_KEY_HEADER: FAKE_KEY}
ASSET_ID = "ast_01HFAKE0000000000000000001"
PATH = f"/v1/assets/{ASSET_ID}"

PASSING = {"passing": True, "reason": "all checks ok", "checked_at": "2026-11-15T10:00:00Z"}
FAILING = {"passing": False, "reason": "tls: certificate expired", "checked_at": "2026-11-15T10:05:00Z"}


def _client(
    calls: list[str],
    handler: Any,
    *,
    path: str = PATH,
    headers: dict[str, str] | None = KEY_HEADERS,
) -> AdminKitClient:
    api = make_recording_client(
        calls, {("GET", path): handler}, base_url="https://api.adminkit.net", headers=headers
    )
    return AdminKitClient(api, all_not_implemented_api(base_url="https://adminkit.net"))


async def _run(client: AdminKitClient, asset_id: str = ASSET_ID) -> dict[str, Any]:
    try:
        return (await get_asset(client, asset_id)).to_dict()
    finally:
        await client.aclose()


async def test_no_api_key_returns_key_required_and_sends_no_request() -> None:
    calls: list[str] = []
    out = await _run(_client(calls, json_handler(200, asset_payload()), headers=None))
    assert calls == []
    assert out["status"] == "error"
    assert "API key" in out["result"]["message"]
    assert "asset" not in out["result"]


@pytest.mark.parametrize(
    "bad_id",
    ["../x", "a/b", "", "a" * 300, "..", "a?b", "a#b", "a b", "a\tb", "a\x00b", "a\x7fb", "a%2Fb", "a\\b"],
)
async def test_bad_asset_id_is_rejected_without_http(bad_id: str) -> None:
    calls: list[str] = []
    out = await _run(_client(calls, json_handler(200, asset_payload())), bad_id)
    assert calls == []
    assert out["status"] == "error"
    assert out["result"]["message"].startswith("Invalid asset_id")
    assert "No request was sent" in out["result"]["message"]


async def test_bad_asset_id_without_key_also_sends_nothing() -> None:
    calls: list[str] = []
    out = await _run(_client(calls, json_handler(200, asset_payload()), headers=None), "../x")
    assert calls == []
    assert out["status"] == "error"


async def test_asset_id_is_percent_encoded_in_path() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.raw_path.decode())
        return httpx.Response(200, json=asset_payload(asset_id="ast_é:1"))

    out = await _run(_client([], handler, path="/v1/assets/ast_é:1"), "ast_é:1")
    assert seen == ["/v1/assets/ast_%C3%A9%3A1"]
    assert out["status"] == "ok"


async def test_passing_status_sends_get_with_key_and_maps_fields() -> None:
    calls: list[str] = []
    seen_keys: list[str | None] = []
    body = asset_payload(
        asset_id=ASSET_ID, value="ok.example.com", last_checked_at="2026-11-15T10:00:00Z", status=PASSING
    )

    def handler(request: httpx.Request) -> httpx.Response:
        seen_keys.append(request.headers.get(API_KEY_HEADER))
        return httpx.Response(200, json=body)

    out = await _run(_client(calls, handler))
    assert calls == [f"GET {PATH}"]
    assert seen_keys == [FAKE_KEY]
    assert out["status"] == "ok"
    assert out["fix_hint"] is None
    assert out["result"]["asset"] == {
        "id": ASSET_ID,
        "kind": "domain",
        "value": "ok.example.com",
        "verified": True,
        "value_valid": True,
        "last_checked_at": "2026-11-15T10:00:00Z",
        "status": PASSING,
    }
    assert "passing" in out["result"]["summary"]
    assert out["report_url"] == "https://adminkit.net/account/assets/?utm_source=mcp"


async def test_failing_status_is_warn_with_reason() -> None:
    body = asset_payload(
        kind="ip", value="192.0.2.10", last_checked_at="2026-11-15T10:05:00Z", status=FAILING
    )
    out = await _run(_client([], json_handler(200, body)))
    assert out["status"] == "warn"
    assert out["result"]["asset"]["status"] == FAILING
    assert "tls: certificate expired" in out["result"]["summary"]
    assert out["fix_hint"]


async def test_null_status_is_not_checked_yet() -> None:
    out = await _run(_client([], json_handler(200, asset_payload(verified=False))))
    assert out["status"] == "ok"
    asset = out["result"]["asset"]
    assert asset["status"] is None
    assert asset["last_checked_at"] is None
    assert asset["verified"] is False
    assert "not been checked" in out["result"]["summary"]


async def test_older_api_without_status_fields_maps_to_nulls() -> None:
    out = await _run(_client([], json_handler(200, asset_payload(include_status_fields=False))))
    assert out["result"]["asset"]["status"] is None
    assert out["result"]["asset"]["last_checked_at"] is None


async def test_malformed_status_maps_to_null() -> None:
    body = asset_payload(status={"passing": "no", "checked_at": "2026-11-15T10:00:00Z"})
    out = await _run(_client([], json_handler(200, body)))
    assert out["result"]["asset"]["status"] is None
    assert out["status"] == "ok"


async def test_404_returns_asset_not_found_envelope() -> None:
    handler = json_handler(404, problem_payload(status=404, title="Not Found", detail="asset not found."))
    out = await _run(_client([], handler))
    assert out["status"] == "error"
    assert out["result"]["message"] == "Asset not found in your organization."
    assert "asset" not in out["result"]


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


async def test_unexpected_body_is_error_not_crash() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"])

    out = await _run(_client([], handler))
    assert out["status"] == "error"


async def test_never_echoes_api_key_or_verification_token() -> None:
    body = asset_payload(status=FAILING, last_checked_at="2026-11-15T10:05:00Z")
    out = await _run(_client([], json_handler(200, body)))
    text = repr(out)
    assert FAKE_KEY not in text
    assert "verification_token" not in text
    assert "FAKE-TOKEN" not in text


async def test_get_asset_listed_by_server_and_round_trips_through_fastmcp() -> None:
    calls: list[str] = []
    client = _client(calls, json_handler(200, asset_payload(status=PASSING)))
    mcp = build_server(client)
    try:
        tools = {t.name: t for t in await mcp.list_tools()}
        assert "get_asset" in tools
        description = tools["get_asset"].description or ""
        assert "Read-only" in description
        assert "API key" in description
        assert tools["get_asset"].inputSchema["required"] == ["asset_id"]
        content = await mcp.call_tool("get_asset", {"asset_id": ASSET_ID})
    finally:
        await client.aclose()
    assert content
    assert calls == [f"GET {PATH}"]


async def test_hosted_http_settings_never_carry_a_key_so_get_asset_refuses() -> None:
    hosted = AdminKitClient.from_settings(for_hosted_http(Settings(api_key=FAKE_KEY)))
    try:
        assert hosted.has_api_key is False
        out = (await get_asset(hosted, ASSET_ID)).to_dict()
    finally:
        await hosted.aclose()
    assert out["status"] == "error"
    assert "API key" in out["result"]["message"]


async def test_value_valid_false_is_reported_with_warn_and_readd_hint() -> None:
    body = asset_payload(
        value="https://example.com/",
        last_checked_at="2026-11-15T10:00:00Z",
        status=PASSING,
        value_valid=False,
    )
    out = await _run(_client([], json_handler(200, body)))
    asset = out["result"]["asset"]
    assert asset["value_valid"] is False
    assert asset["value"] == "https://example.com/"
    assert out["status"] == "warn"
    assert "remove this asset and add it again" in out["result"]["summary"]
    assert "add it again" in out["fix_hint"]
    assert set(out["result"]) == {"summary", "asset"}


async def test_value_valid_absent_maps_to_true() -> None:
    body = asset_payload(last_checked_at="2026-11-15T10:00:00Z", status=PASSING)
    assert "value_valid" not in body
    out = await _run(_client([], json_handler(200, body)))
    assert out["result"]["asset"]["value_valid"] is True
    assert out["status"] == "ok"
    assert out["fix_hint"] is None


async def test_value_valid_true_is_passed_through() -> None:
    body = asset_payload(last_checked_at="2026-11-15T10:00:00Z", status=PASSING, value_valid=True)
    out = await _run(_client([], json_handler(200, body)))
    assert out["result"]["asset"]["value_valid"] is True
    assert out["status"] == "ok"


async def test_get_asset_description_documents_value_valid() -> None:
    client = _client([], json_handler(200, asset_payload()))
    try:
        tools = {t.name: t for t in await build_server(client).list_tools()}
    finally:
        await client.aclose()
    assert "value_valid" in (tools["get_asset"].description or "")
