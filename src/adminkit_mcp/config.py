"""Environment configuration. No secrets are ever logged (AGENTS.md)."""

from __future__ import annotations

import os
from dataclasses import dataclass, replace

DEFAULT_API_BASE = "https://api.adminkit.net"
DEFAULT_SITE_BASE = "https://adminkit.net"
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_RATE_LIMIT_PER_SECOND = 5.0
# Plan row A14: the public hosted endpoint throttles each client IP to this many requests
# per minute (with a short burst), separately from `rate_limit_per_second` above (which
# limits this server's own outbound calls to the Check API, not inbound callers).
DEFAULT_HOSTED_RATE_LIMIT_PER_MINUTE = 30.0
DEFAULT_HOSTED_RATE_LIMIT_BURST = 5.0
# Hosted tool calls are small JSON-RPC requests (a domain, an IP, a URL) -- far below the MCP
# SDK's own 4 MiB default -- so a public anonymous endpoint caps the request body much lower.
DEFAULT_HOSTED_MAX_BODY_BYTES = 64 * 1024


@dataclass(frozen=True)
class Settings:
    api_base: str = DEFAULT_API_BASE
    site_base: str = DEFAULT_SITE_BASE
    api_key: str | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    rate_limit_per_second: float = DEFAULT_RATE_LIMIT_PER_SECOND
    allow_private_targets: bool = False
    # True only when serving `--http` (plan row A14): a public, anonymous endpoint, so tools
    # that take a target refuse private/loopback ones unconditionally and never forward an
    # API key, regardless of what the host environment or a caller's tool argument asks for.
    hosted_http: bool = False
    hosted_rate_limit_per_minute: float = DEFAULT_HOSTED_RATE_LIMIT_PER_MINUTE
    hosted_rate_limit_burst: float = DEFAULT_HOSTED_RATE_LIMIT_BURST
    hosted_max_body_bytes: int = DEFAULT_HOSTED_MAX_BODY_BYTES

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            api_base=os.environ.get("ADMINKIT_API_BASE", DEFAULT_API_BASE).rstrip("/"),
            site_base=os.environ.get("ADMINKIT_SITE_BASE", DEFAULT_SITE_BASE).rstrip("/"),
            api_key=os.environ.get("ADMINKIT_API_KEY") or None,
            timeout_seconds=float(os.environ.get("ADMINKIT_MCP_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
            rate_limit_per_second=float(
                os.environ.get("ADMINKIT_MCP_RATE_LIMIT_PER_SECOND", DEFAULT_RATE_LIMIT_PER_SECOND)
            ),
            allow_private_targets=os.environ.get("ADMINKIT_MCP_ALLOW_PRIVATE", "").lower()
            in ("1", "true", "yes"),
            hosted_rate_limit_per_minute=float(
                os.environ.get(
                    "ADMINKIT_MCP_HOSTED_RATE_LIMIT_PER_MINUTE", DEFAULT_HOSTED_RATE_LIMIT_PER_MINUTE
                )
            ),
            hosted_rate_limit_burst=float(
                os.environ.get("ADMINKIT_MCP_HOSTED_RATE_LIMIT_BURST", DEFAULT_HOSTED_RATE_LIMIT_BURST)
            ),
            hosted_max_body_bytes=int(
                os.environ.get("ADMINKIT_MCP_HOSTED_MAX_BODY_BYTES", DEFAULT_HOSTED_MAX_BODY_BYTES)
            ),
        )


def for_hosted_http(settings: Settings) -> Settings:
    """Settings adjusted for the public, anonymous hosted HTTP endpoint (plan row A14):
    never forwards whatever `ADMINKIT_API_KEY` the host environment happens to have set for
    other uses on the same box, and flips on the hosted-mode guards in `server.py`/`hosted.py`
    (private-target refusal, per-client rate limit, request-size cap)."""
    return replace(settings, api_key=None, hosted_http=True)
