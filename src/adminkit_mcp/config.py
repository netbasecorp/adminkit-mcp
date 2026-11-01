"""Environment configuration. No secrets are ever logged (AGENTS.md)."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_API_BASE = "https://api.adminkit.net"
DEFAULT_SITE_BASE = "https://adminkit.net"
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_RATE_LIMIT_PER_SECOND = 5.0


@dataclass(frozen=True)
class Settings:
    api_base: str = DEFAULT_API_BASE
    site_base: str = DEFAULT_SITE_BASE
    api_key: str | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    rate_limit_per_second: float = DEFAULT_RATE_LIMIT_PER_SECOND
    allow_private_targets: bool = False

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
        )
