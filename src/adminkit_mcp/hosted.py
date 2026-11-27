"""Hosted-HTTP-mode protections (plan row A14): `mcp.adminkit.net` is a public, anonymous,
read-only endpoint, so it needs guards that stdio/local use (an operator's own Claude
Desktop, CI) does not:

- per-client-IP rate limiting with a 429 response, since FastMCP's own `RateLimiter`
  (`ratelimit.py`) only throttles this server's *outbound* calls, not inbound callers;
- a refusal for any tool argument that names a private/loopback/link-local target, reusing
  the probe's address tables (`adminkit_mcp.probe.targets.classify_hosted_target`) — even
  though most tools only forward the target to the live Check API rather than contacting it
  directly, a public anonymous endpoint must never be usable to point *any* check at an
  internal network. The argument is normalised first (whitespace, trailing dots, scheme, port,
  path, IPv6 brackets) and the check fails closed: an argument that does not parse to a host,
  or (for tools that connect to the target) a name that does not resolve, is refused too;
- rate-limit keys that group an IPv6 client by its /64, since one subscriber usually holds a
  whole /64 and could otherwise rotate source addresses to dodge the limit;
- statelessness and the request-body size cap, both set on the FastMCP `Settings` object
  the SDK already understands (`stateless_http`, `max_request_body_size`) rather than
  reimplemented here.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from adminkit_mcp.config import Settings
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.probe.targets import classify_hosted_target
from adminkit_mcp.ratelimit import PerClientRateLimiter

UNKNOWN_CLIENT = "unknown"


async def refuse_private_target(
    tool: str,
    host_or_url: str,
    *,
    report_url: str | None,
    is_url: bool = False,
    require_resolvable: bool = True,
) -> ToolResponse | None:
    """Returns a `ToolResponse` refusing the call if `host_or_url` names a private/loopback/
    link-local host (or does not parse to a host at all), otherwise `None` so the caller
    proceeds normally. Bare hosts, `host:port`, `[v6]:port`, trailing-dot names and URLs are
    all reduced to their host first (`is_url` is kept for callers that pass a URL; the same
    normalisation handles both). `require_resolvable=False` is for DNS-only tools
    (`dns_lookup`, `check_mail_auth`): the Check API only queries DNS for those and never
    connects to the name, and record-only owner names (`_dmarc.`, SRV, TXT) legitimately have
    no address, so an unresolvable name is let through there; tools that connect to the
    target refuse it."""
    del is_url  # normalisation strips the scheme/path whether or not the caller says URL
    verdict, host = await classify_hosted_target(host_or_url)
    if verdict == "public" or (verdict == "unresolvable" and not require_resolvable):
        return None
    if verdict == "private":
        message = f"The public hosted endpoint refuses to target private/loopback host {host!r}."
    elif verdict == "unresolvable":
        message = (
            f"The public hosted endpoint refuses to target {host!r}: it does not resolve to any "
            "address, so it cannot be verified as public."
        )
    else:
        message = (
            f"The public hosted endpoint refuses target {host_or_url.strip()!r}: it is not a "
            "valid hostname, IP address or URL."
        )
    return ToolResponse(
        tool=tool,
        status="skipped",
        result={
            "message": f"{message} Run `adminkit-mcp` locally (pip install adminkit-mcp) to check "
            "your own network."
        },
        report_url=report_url,
    )


def client_rate_limit_key(client_ip: str) -> str:
    """Rate-limit key for a client address: an IPv4 address (or IPv4-mapped IPv6 address)
    is keyed by its own /32 address; any other IPv6 address by its /64 network, since one
    subscriber normally gets a whole /64 and could otherwise rotate through 2**64 source
    addresses to get a fresh bucket each time. Non-IP values are used as-is."""
    try:
        ip = ipaddress.ip_address(client_ip.split("%", 1)[0])
    except ValueError:
        return client_ip
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.IPv6Network((ip, 64), strict=False))
    return str(ip)


def _client_ip(scope: Scope) -> str:
    client = scope.get("client")
    return client[0] if client else UNKNOWN_CLIENT


class ClientRateLimitMiddleware:
    """Raw ASGI middleware: answers 429 once a client (IPv4 address / IPv6 /64, see
    `client_rate_limit_key`) exceeds `limiter`'s budget (with a
    `Retry-After` header in whole seconds, >= 1, from that client's token bucket), without
    touching the request body (so it never interferes with the size-cap middleware the MCP
    SDK already wires in via `max_request_body_size`)."""

    def __init__(self, app: ASGIApp, limiter: PerClientRateLimiter) -> None:
        self._app = app
        self._limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        client_key = client_rate_limit_key(_client_ip(scope))
        if not self._limiter.allow(client_key):
            retry_after = self._limiter.retry_after(client_key)
            response = JSONResponse(
                {
                    "error": "rate_limited",
                    "detail": "Too many requests from this client; slow down.",
                    "retry_after_seconds": retry_after,
                },
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
            await response(scope, receive, send)
            return
        await self._app(scope, receive, send)


def build_hosted_http_app(mcp: FastMCP[Any], *, settings: Settings) -> ASGIApp:
    """Returns the ASGI app to serve for `--http` (plan row A14): the FastMCP streamable-HTTP
    app, forced stateless and body-size-capped, wrapped in per-client-IP rate limiting."""
    mcp.settings.stateless_http = True
    mcp.settings.max_request_body_size = settings.hosted_max_body_bytes

    app: Starlette = mcp.streamable_http_app()
    limiter = PerClientRateLimiter(
        rate=settings.hosted_rate_limit_per_minute / 60.0,
        burst=settings.hosted_rate_limit_burst,
    )
    return ClientRateLimitMiddleware(app, limiter)


__all__ = ["build_hosted_http_app", "client_rate_limit_key", "refuse_private_target"]
