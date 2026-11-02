"""Hosted-HTTP-mode protections (plan row A14): `mcp.adminkit.net` is a public, anonymous,
read-only endpoint, so it needs guards that stdio/local use (an operator's own Claude
Desktop, CI) does not:

- per-client-IP rate limiting with a 429 response, since FastMCP's own `RateLimiter`
  (`ratelimit.py`) only throttles this server's *outbound* calls, not inbound callers;
- a refusal for any tool argument that names a private/loopback/link-local target, reusing
  the probe's existing resolver (`adminkit_mcp.probe.targets`) — even though most tools only
  forward the target to the live Check API rather than contacting it directly, a public
  anonymous endpoint must never be usable to point *any* check at an internal network;
- statelessness and the request-body size cap, both set on the FastMCP `Settings` object
  the SDK already understands (`stateless_http`, `max_request_body_size`) rather than
  reimplemented here.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from adminkit_mcp.config import Settings
from adminkit_mcp.envelope import ToolResponse
from adminkit_mcp.probe.targets import resolve_host_is_private
from adminkit_mcp.ratelimit import PerClientRateLimiter

UNKNOWN_CLIENT = "unknown"


async def refuse_private_target(
    tool: str, host_or_url: str, *, report_url: str | None, is_url: bool = False
) -> ToolResponse | None:
    """Returns a `ToolResponse` refusing the call if `host_or_url` names a private/loopback/
    link-local host, otherwise `None` so the caller proceeds normally. `is_url=True` pulls
    the hostname out of a URL argument (`check_mcp_endpoint`); other tools pass a bare
    domain/host argument directly."""
    host = urlsplit(host_or_url).hostname if is_url else host_or_url
    if not host:
        return None
    if not await resolve_host_is_private(host):
        return None
    return ToolResponse(
        tool=tool,
        status="skipped",
        result={
            "message": f"The public hosted endpoint refuses to target private/loopback host "
            f"{host!r}. Run `adminkit-mcp` locally (pip install adminkit-mcp) to check your own "
            "network."
        },
        report_url=report_url,
    )


def _client_ip(scope: Scope) -> str:
    client = scope.get("client")
    return client[0] if client else UNKNOWN_CLIENT


class ClientRateLimitMiddleware:
    """Raw ASGI middleware: answers 429 once a client IP exceeds `limiter`'s budget, without
    touching the request body (so it never interferes with the size-cap middleware the MCP
    SDK already wires in via `max_request_body_size`)."""

    def __init__(self, app: ASGIApp, limiter: PerClientRateLimiter) -> None:
        self._app = app
        self._limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        if not self._limiter.allow(_client_ip(scope)):
            response = JSONResponse(
                {"error": "rate_limited", "detail": "Too many requests from this client; slow down."},
                status_code=429,
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


__all__ = ["build_hosted_http_app", "refuse_private_target"]
