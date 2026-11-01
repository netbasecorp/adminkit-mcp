"""Builds the AdminKit FastMCP server: registers the 8 tools from spec section 18.8, plus
5 "offline utility" tools (spec section 18.1/18.7) wrapping the no-auth `/v1/tools/*`
endpoints (subnet/IP/MAC/UA math) — grouped separately below since they are a reversible
enhancement on top of the original 8, not part of the named spec section 18.8 list.

Each tool function is a thin wrapper that unpacks arguments, calls into
`adminkit_mcp.tools.*` with the shared `AdminKitClient`, and returns a plain dict (the
`ToolResponse` envelope) — FastMCP serialises it as the tool's structured content.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.config import Settings
from adminkit_mcp.tools.check_domain import check_domain as _check_domain
from adminkit_mcp.tools.check_ip import check_ip as _check_ip
from adminkit_mcp.tools.check_mail_auth import check_mail_auth as _check_mail_auth
from adminkit_mcp.tools.check_mcp_endpoint import check_mcp_endpoint as _check_mcp_endpoint
from adminkit_mcp.tools.check_owned_ports import check_owned_ports as _check_owned_ports
from adminkit_mcp.tools.dns_lookup import dns_lookup as _dns_lookup
from adminkit_mcp.tools.explain_report import explain_report as _explain_report
from adminkit_mcp.tools.get_radar import get_radar as _get_radar
from adminkit_mcp.tools.ip_info import ip_info as _ip_info
from adminkit_mcp.tools.ipv6_info import ipv6_info as _ipv6_info
from adminkit_mcp.tools.mac_vendor import mac_vendor as _mac_vendor
from adminkit_mcp.tools.subnet_calc import subnet_calc as _subnet_calc
from adminkit_mcp.tools.user_agent import user_agent as _user_agent


def build_server(client: AdminKitClient, *, settings: Settings | None = None) -> FastMCP:
    """Builds a FastMCP server bound to `client`. `settings` controls the default for the
    `allow_private` argument of `check_mcp_endpoint` (CI runners set it via env/flag)."""
    allow_private_default = settings.allow_private_targets if settings else False
    mcp: FastMCP[Any] = FastMCP(
        name="adminkit",
        instructions=(
            "AdminKit network and MCP security check tools. Each tool returns a short "
            "result, the raw evidence behind it, an optional one-line fix_hint, and a "
            "report_url to the corresponding public page. See https://adminkit.net."
        ),
    )

    @mcp.tool()
    async def check_ip(ip: str | None = None) -> dict[str, Any]:
        """Check the caller's own public IP: ASN, geolocation hint, and whether it looks
        like a shared/CGNAT address. `ip` is reserved for a future verified lookup."""
        return (await _check_ip(client, ip)).to_dict()

    @mcp.tool()
    async def dns_lookup(name: str, type: str = "A") -> dict[str, Any]:
        """DNS lookup for a name. `type` is one of A, AAAA, MX, TXT, NS, CAA, PTR, SOA, CNAME."""
        return (await _dns_lookup(client, name, type)).to_dict()

    @mcp.tool()
    async def check_mail_auth(domain: str) -> dict[str, Any]:
        """Check SPF and DMARC posture for a domain's outbound mail authentication."""
        return (await _check_mail_auth(client, domain)).to_dict()

    @mcp.tool()
    async def check_domain(domain: str) -> dict[str, Any]:
        """Aggregate domain health overview: whois, TLS, HTTP headers (Check API)."""
        return (await _check_domain(client, domain)).to_dict()

    @mcp.tool()
    async def check_owned_ports(target: str) -> dict[str, Any]:
        """Check commonly-exposed device ports on a target you have verified you own.
        Requires AdminKit asset ownership verification; never an unverified scan."""
        return (await _check_owned_ports(client, target)).to_dict()

    @mcp.tool()
    async def explain_report(report_id: str) -> dict[str, Any]:
        """Get an AI-generated, citation-backed explanation of a previously saved AdminKit report."""
        return (await _explain_report(client, report_id)).to_dict()

    @mcp.tool()
    async def get_radar(protocol: str | None = None) -> dict[str, Any]:
        """Get aggregated honeypot/telemetry trend data for a protocol (mqtt, modbus,
        mcp, rtsp, telnet, dns). Only ever aggregated across >=5 tenants."""
        return (await _get_radar(client, protocol)).to_dict()

    @mcp.tool()
    async def check_mcp_endpoint(url: str, allow_private: bool = allow_private_default) -> dict[str, Any]:
        """Probe an MCP server endpoint for anonymous access: whether `initialize` and
        `tools/list` succeed without credentials, auth/OAuth discovery, TLS, and
        dangerous-looking tool names. Never calls a tool. `allow_private` permits probing
        loopback/private targets (CI use only); it is refused by default."""
        return (await _check_mcp_endpoint(client, url, allow_private)).to_dict()

    # --- Offline utilities (spec section 18.1/18.7): pure math over /v1/tools/*, no
    # third-party host contacted. A reversible enhancement on top of the 8 tools above.

    @mcp.tool()
    async def subnet_calc(cidr: str) -> dict[str, Any]:
        """Calculate IPv4/IPv6 subnet details for a CIDR: network/broadcast/netmask,
        usable host range and count, and private/global/loopback/multicast flags."""
        return (await _subnet_calc(client, cidr)).to_dict()

    @mcp.tool()
    async def ip_info(ip: str) -> dict[str, Any]:
        """Inspect any IPv4 or IPv6 address: version, private/global/loopback/link-local/
        multicast/reserved flags, decimal integer form, and compressed/exploded notation.
        Pure address math, not a lookup against the address's owner."""
        return (await _ip_info(client, ip)).to_dict()

    @mcp.tool()
    async def ipv6_info(ip: str) -> dict[str, Any]:
        """Inspect an IPv6 address in depth: its /64 network, reverse-pointer form, and any
        embedded IPv4 (IPv4-mapped, 6to4, Teredo) — derived locally, nothing is queried."""
        return (await _ipv6_info(client, ip)).to_dict()

    @mcp.tool()
    async def mac_vendor(mac: str) -> dict[str, Any]:
        """Look up the registered vendor for a MAC-48 address or bare OUI prefix against
        the bundled IEEE registry snapshot. Returns found=false honestly if unmatched."""
        return (await _mac_vendor(client, mac)).to_dict()

    @mcp.tool()
    async def user_agent(ua: str) -> dict[str, Any]:
        """Parse a User-Agent string into browser, OS, and device family/version, plus
        a bot/crawler flag. Unmatched fields come back null, never guessed at."""
        return (await _user_agent(client, ua)).to_dict()

    return mcp
