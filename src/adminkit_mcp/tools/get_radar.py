"""`get_radar` tool (spec section 18.8): aggregated honeypot/telemetry trends (k>=5 only).

Live on the public API (M10, `platform/adminkit/radar/router.py`): `GET
/v1/radar/{protocol}/trends`, no auth required. The `protocol` argument is optional at the
tool level only because the contract has no site-wide summary endpoint, just a per-protocol
one, so when it is omitted this links to the public Radar page instead of guessing a default
protocol. `ALLOWED_PROTOCOLS` mirrors `adminkit.radar.models.RadarProtocol` exactly; the
`ApiUnavailable` fallback below is only for a temporary outage, not because Radar itself
isn't shipped.
"""

from __future__ import annotations

from adminkit_mcp.client import AdminKitClient, ApiUnavailable
from adminkit_mcp.envelope import ToolResponse, not_available_yet

TOOL = "get_radar"
RADAR_PAGE = "https://adminkit.net/radar/"
ALLOWED_PROTOCOLS = frozenset({"mqtt", "modbus", "mcp", "rtsp", "telnet", "dns"})


async def get_radar(client: AdminKitClient, protocol: str | None = None) -> ToolResponse:
    if protocol is None:
        return not_available_yet(
            TOOL,
            report_url=RADAR_PAGE,
            detail="Pass a protocol (mqtt, modbus, mcp, rtsp, telnet, dns) for trend data, or see the "
            "Radar page.",
        )
    protocol = protocol.strip().lower()
    if protocol not in ALLOWED_PROTOCOLS:
        return ToolResponse(
            tool=TOOL,
            status="error",
            result={"message": f"protocol must be one of: {', '.join(sorted(ALLOWED_PROTOCOLS))}"},
            report_url=RADAR_PAGE,
        )

    try:
        resp = await client.call_api("GET", f"/v1/radar/{protocol}/trends")
    except ApiUnavailable:
        return not_available_yet(
            TOOL,
            report_url=RADAR_PAGE,
            detail=f"Radar trend data for {protocol} could not be reached on the public API right now.",
        )
    payload = resp.json()
    return ToolResponse(
        tool=TOOL,
        status="ok",
        result={
            "protocol": payload.get("protocol"),
            "period": payload.get("period"),
            "points": payload.get("points", []),
        },
        evidence=payload,
        report_url=RADAR_PAGE,
    )
