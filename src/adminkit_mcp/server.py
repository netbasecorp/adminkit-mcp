"""Builds the AdminKit FastMCP server: registers the 8 tools from spec section 18.8, plus
8 "offline utility" tools (spec section 18.1/18.7) wrapping the no-auth `/v1/tools/*`
endpoints (subnet/IP/CIDR/EUI-64/MAC/UA math and static SPF syntax) — grouped separately
below since they are a reversible enhancement on top of the original 8, not part of the named
spec section 18.8 list.
`list_assets` and `get_asset` are read-only, API-key-only views of the caller's own
monitored assets (L0 monitoring), also outside the 18.8 list.

Each tool function is a thin wrapper that unpacks arguments, calls into
`adminkit_mcp.tools.*` with the shared `AdminKitClient`, and returns a plain dict (the
`ToolResponse` envelope) — FastMCP serialises it as the tool's structured content.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from adminkit_mcp import __version__
from adminkit_mcp.client import AdminKitClient, ApiRateLimited
from adminkit_mcp.config import Settings
from adminkit_mcp.hosted import refuse_private_target
from adminkit_mcp.tools._common import rate_limited_response
from adminkit_mcp.tools.check_domain import WHOIS_PAGE
from adminkit_mcp.tools.check_domain import check_domain as _check_domain
from adminkit_mcp.tools.check_ip import check_ip as _check_ip
from adminkit_mcp.tools.check_mail_auth import MAIL_AUTH_PAGE
from adminkit_mcp.tools.check_mail_auth import check_mail_auth as _check_mail_auth
from adminkit_mcp.tools.check_mcp_endpoint import MCP_CHECK_PAGE
from adminkit_mcp.tools.check_mcp_endpoint import check_mcp_endpoint as _check_mcp_endpoint
from adminkit_mcp.tools.check_owned_ports import PORT_CHECK_PAGE
from adminkit_mcp.tools.check_owned_ports import check_owned_ports as _check_owned_ports
from adminkit_mcp.tools.dns_lookup import DNS_LOOKUP_PAGE
from adminkit_mcp.tools.dns_lookup import dns_lookup as _dns_lookup
from adminkit_mcp.tools.explain_report import explain_report as _explain_report
from adminkit_mcp.tools.get_asset import get_asset as _get_asset
from adminkit_mcp.tools.get_radar import get_radar as _get_radar
from adminkit_mcp.tools.ip_in_cidr import ip_in_cidr as _ip_in_cidr
from adminkit_mcp.tools.ip_info import ip_info as _ip_info
from adminkit_mcp.tools.ipv6_eui64 import ipv6_eui64 as _ipv6_eui64
from adminkit_mcp.tools.ipv6_info import ipv6_info as _ipv6_info
from adminkit_mcp.tools.list_assets import list_assets as _list_assets
from adminkit_mcp.tools.mac_vendor import mac_vendor as _mac_vendor
from adminkit_mcp.tools.spf_validate import spf_validate as _spf_validate
from adminkit_mcp.tools.subnet_calc import subnet_calc as _subnet_calc
from adminkit_mcp.tools.user_agent import user_agent as _user_agent


def _rate_limit_aware[**P](
    fn: Callable[P, Awaitable[dict[str, Any]]],
) -> Callable[P, Awaitable[dict[str, Any]]]:
    """Turns an `ApiRateLimited` (API 429) that a tool did not handle itself into the standard
    error envelope ("rate limited ... retry in N s") instead of a generic tool error. No retry.
    `functools.wraps` keeps the signature and docstring FastMCP builds the tool schema from."""

    @functools.wraps(fn)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> dict[str, Any]:
        try:
            return await fn(*args, **kwargs)
        except ApiRateLimited as exc:
            return rate_limited_response(fn.__name__, exc).to_dict()

    return wrapper


def build_server(client: AdminKitClient, *, settings: Settings | None = None) -> FastMCP:
    """Builds a FastMCP server bound to `client`. `settings` controls the default for the
    `allow_private` argument of `check_mcp_endpoint` (CI runners set it via env/flag), and
    whether hosted-HTTP-mode guards (plan row A14) are active: `settings.hosted_http` is
    only True when serving `--http`, never for stdio/local use."""
    allow_private_default = settings.allow_private_targets if settings else False
    hosted_mode = bool(settings and settings.hosted_http)
    mcp: FastMCP[Any] = FastMCP(
        name="adminkit",
        instructions=(
            "AdminKit network and MCP security check tools. Each tool returns a short "
            "result, the raw evidence behind it, an optional one-line fix_hint, and a "
            "report_url to the corresponding public page. See https://adminkit.net."
        ),
    )
    # `initialize` reports serverInfo.version from the lowlevel server's `version`, falling
    # back to the installed `mcp` SDK version when unset. FastMCP takes no `version` argument
    # anywhere in `mcp>=1.2,<2`, but every release in that range builds `self._mcp_server`
    # (lowlevel `Server`, which stores `self.version`) and reads it in
    # `create_initialization_options`: `server_version=self.version if self.version else
    # pkg_version("mcp")` (mcp 1.2.0 lowlevel/server.py:137, mcp 1.30.0 :183).
    mcp._mcp_server.version = __version__

    @mcp.tool()
    @_rate_limit_aware
    async def check_ip(ip: str | None = None) -> dict[str, Any]:
        """Check the caller's own public IP: ASN, geolocation hint, and whether it looks
        like a shared/CGNAT address. `ip` is reserved for a future verified lookup."""
        return (await _check_ip(client, ip)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def dns_lookup(name: str, type: str = "A") -> dict[str, Any]:
        """DNS lookup for a name. `type` is one of A, AAAA, MX, TXT, NS, CAA, PTR, SOA, CNAME,
        SRV, SSHFP, TLSA. SRV/TLSA owner names may start with `_` service labels, e.g.
        `_sip._tcp.example.com` or `_443._tcp.example.com`."""
        if hosted_mode:
            refused = await refuse_private_target("dns_lookup", name, report_url=DNS_LOOKUP_PAGE)
            if refused:
                return refused.to_dict()
        return (await _dns_lookup(client, name, type)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def check_mail_auth(domain: str) -> dict[str, Any]:
        """Check SPF and DMARC posture for a domain's outbound mail authentication."""
        if hosted_mode:
            refused = await refuse_private_target("check_mail_auth", domain, report_url=MAIL_AUTH_PAGE)
            if refused:
                return refused.to_dict()
        return (await _check_mail_auth(client, domain)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def check_domain(domain: str) -> dict[str, Any]:
        """Aggregate domain health overview: whois, TLS, HTTP headers (Check API)."""
        if hosted_mode:
            refused = await refuse_private_target("check_domain", domain, report_url=WHOIS_PAGE)
            if refused:
                return refused.to_dict()
        return (await _check_domain(client, domain)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def check_owned_ports(target: str) -> dict[str, Any]:
        """Check commonly-exposed device ports on a target you have verified you own.
        Requires AdminKit asset ownership verification; never an unverified scan."""
        if hosted_mode:
            refused = await refuse_private_target("check_owned_ports", target, report_url=PORT_CHECK_PAGE)
            if refused:
                return refused.to_dict()
        return (await _check_owned_ports(client, target)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def explain_report(report_id: str) -> dict[str, Any]:
        """Get an AI-generated, citation-backed explanation of a previously saved AdminKit report."""
        return (await _explain_report(client, report_id)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def get_radar(protocol: str | None = None) -> dict[str, Any]:
        """Get aggregated honeypot/telemetry trend data for a protocol (mqtt, modbus,
        mcp, rtsp, telnet, dns). Only ever aggregated across >=5 tenants."""
        return (await _get_radar(client, protocol)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def check_mcp_endpoint(url: str, allow_private: bool = allow_private_default) -> dict[str, Any]:
        """Probe an MCP server endpoint for anonymous access: whether `initialize` and
        `tools/list` succeed without credentials, auth/OAuth discovery, TLS, and
        dangerous-looking tool names. Never calls a tool. `allow_private` permits probing
        loopback/private targets (CI use only); it is refused by default, and always refused
        on the public hosted endpoint regardless of this argument."""
        if hosted_mode:
            refused = await refuse_private_target(
                "check_mcp_endpoint", url, report_url=MCP_CHECK_PAGE, is_url=True
            )
            if refused:
                return refused.to_dict()
            allow_private = False
        return (await _check_mcp_endpoint(client, url, allow_private)).to_dict()

    # --- Account (read-only, needs ADMINKIT_API_KEY): the caller's own monitored assets.

    @mcp.tool()
    @_rate_limit_aware
    async def list_assets() -> dict[str, Any]:
        """Read-only: list your own AdminKit assets (GET /v1/assets) with each one's kind,
        value, verified flag, value_valid (false = the stored value does not parse for its kind,
        so remove the asset and add it again; true when the API omits it), last_checked_at, and
        stored monitored status (passing, reason, checked_at; null = not checked yet), to see
        which assets are failing or need re-adding. Requires an
        AdminKit API key (ADMINKIT_API_KEY); without one it returns an "API key required"
        result and sends no request. Never creates, verifies, checks, or deletes anything."""
        return (await _list_assets(client)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def get_asset(asset_id: str) -> dict[str, Any]:
        """Read-only: get ONE of your own AdminKit assets by id (GET /v1/assets/{asset_id},
        ids as returned by list_assets) with its kind, value, verified flag, value_valid (false =
        remove the asset and add it again), last_checked_at, and stored monitored status
        (passing, reason, checked_at; null = not checked yet).
        Requires an AdminKit API key (ADMINKIT_API_KEY); without one it returns an "API key
        required" result and sends no request. An unknown id and another organization's id
        both return "asset not found". Never creates, verifies, checks, or deletes anything."""
        return (await _get_asset(client, asset_id)).to_dict()

    # --- Offline utilities (spec section 18.1/18.7): pure math over /v1/tools/*, no
    # third-party host contacted. A reversible enhancement on top of the 8 tools above.

    @mcp.tool()
    @_rate_limit_aware
    async def subnet_calc(cidr: str) -> dict[str, Any]:
        """Calculate IPv4/IPv6 subnet details for a CIDR: network/broadcast/netmask,
        usable host range and count, and private/global/loopback/multicast flags."""
        return (await _subnet_calc(client, cidr)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def ip_info(ip: str) -> dict[str, Any]:
        """Inspect any IPv4 or IPv6 address: version, private/global/loopback/link-local/
        multicast/reserved flags, decimal integer form, and compressed/exploded notation.
        Pure address math, not a lookup against the address's owner."""
        return (await _ip_info(client, ip)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def ipv6_info(ip: str) -> dict[str, Any]:
        """Inspect an IPv6 address in depth: its /64 network, reverse-pointer form, and any
        embedded IPv4 (IPv4-mapped, 6to4, Teredo) — derived locally, nothing is queried."""
        return (await _ipv6_info(client, ip)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def mac_vendor(mac: str) -> dict[str, Any]:
        """Look up the registered vendor for a MAC-48 address or bare OUI prefix against
        the bundled IEEE registry snapshot. Returns found=false honestly if unmatched."""
        return (await _mac_vendor(client, mac)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def user_agent(ua: str) -> dict[str, Any]:
        """Parse a User-Agent string into browser, OS, and device family/version, plus
        a bot/crawler flag. Unmatched fields come back null, never guessed at."""
        return (await _user_agent(client, ua)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def ip_in_cidr(ip: str, cidr: str) -> dict[str, Any]:
        """Check whether an IPv4/IPv6 address falls inside a CIDR range; returns `contains`
        and the normalized network. An address of the other IP version is simply not contained."""
        return (await _ip_in_cidr(client, ip, cidr)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def ipv6_eui64(prefix: str, mac: str) -> dict[str, Any]:
        """Derive the SLAAC address a device with MAC-48 `mac` would form in IPv6 `prefix`
        (/64 or shorter): the modified EUI-64 interface id (U/L bit flipped) and the full
        address in compressed/exploded form. Computed locally, nothing is queried."""
        return (await _ipv6_eui64(client, prefix, mac)).to_dict()

    @mcp.tool()
    @_rate_limit_aware
    async def spf_validate(record: str) -> dict[str, Any]:
        """Statically validate an SPF TXT record string (e.g. 'v=spf1 include:_spf.example.com
        ~all'): verdict, findings with severity, and the lookup-term count of this record only.
        No DNS lookups and no include/redirect following; use check_mail_auth for a domain's
        live, fully resolved SPF."""
        return (await _spf_validate(client, record)).to_dict()

    return mcp
