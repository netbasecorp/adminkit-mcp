from __future__ import annotations

import adminkit_mcp.tools.get_radar as get_radar_module
from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.tools.get_radar import ALLOWED_PROTOCOLS, get_radar
from fakes.fake_api import all_not_implemented_api, json_handler, make_client

# Mirrors `RadarProtocol` in `platform/adminkit/radar/models.py` (read-only reference, never
# imported: `mcp/` is MIT and must not depend on the proprietary `platform/` package). Keep
# this literal set in sync by hand if the live contract ever adds/removes a protocol.
_LIVE_RADAR_CONTRACT_PROTOCOLS = frozenset({"mqtt", "modbus", "mcp", "rtsp", "telnet", "dns"})


def test_get_radar_allowed_protocols_match_contract() -> None:
    assert ALLOWED_PROTOCOLS == _LIVE_RADAR_CONTRACT_PROTOCOLS


def test_get_radar_docstring_no_stale_not_live() -> None:
    doc = get_radar_module.__doc__ or ""
    assert "not live" not in doc.lower()
    assert "not yet" not in doc.lower()


async def test_get_radar_no_protocol_points_to_radar_page() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await get_radar(client)
    finally:
        await client.aclose()
    assert result.status == "not_available"
    assert result.report_url == "https://adminkit.net/radar/?utm_source=mcp"


async def test_get_radar_rejects_unknown_protocol() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await get_radar(client, "ftp")
    finally:
        await client.aclose()
    assert result.status == "error"


async def test_get_radar_not_available_for_valid_protocol() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await get_radar(client, "mcp")
    finally:
        await client.aclose()
    assert result.status == "not_available"


async def test_get_radar_uses_live_api_when_available() -> None:
    payload = {
        "protocol": "mcp",
        "period": "30d",
        "points": [{"date": "2026-10-01T00:00:00Z", "count": 3}],
        "generated_at": "2026-10-22T00:00:00Z",
    }
    api = make_client({("GET", "/v1/radar/mcp/trends"): json_handler(200, payload)}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    try:
        result = await get_radar(client, "MCP")
    finally:
        await client.aclose()
    assert result.status == "ok"
    assert result.result["protocol"] == "mcp"
    assert result.result["points"] == payload["points"]
