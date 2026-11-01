"""Refuses to probe private/loopback targets unless explicitly allowed (CI use only).

Active probing is only safe against targets the caller actually controls (spec section 8
rule 1). A public MCP tool has no ownership-verification step, so the floor is: never
touch a private network from a server a stranger can invoke, unless the operator opted
in (`--allow-private` / `ADMINKIT_MCP_ALLOW_PRIVATE=1`), which is meant for CI runners
scanning their own localhost test fixture.
"""

from __future__ import annotations

import asyncio
import ipaddress
from urllib.parse import urlsplit


class PrivateTargetError(Exception):
    """Raised when a target resolves to a private/loopback/link-local address."""


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


async def resolve_host_is_private(host: str) -> bool:
    """True if `host` is a private/loopback literal, or resolves only to such addresses."""
    if host.lower() in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return _is_private_ip(ip)

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
    except OSError:
        # Unresolvable hosts are rejected later by the HTTP call itself; do not block here.
        return False
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    return all(_is_private_ip(ipaddress.ip_address(addr)) for addr in addresses)


async def check_target_allowed(url: str, *, allow_private: bool) -> None:
    """Raises `PrivateTargetError` if `url`'s host is private/loopback and not allowed."""
    if allow_private:
        return
    host = urlsplit(url).hostname
    if not host:
        return
    if await resolve_host_is_private(host):
        raise PrivateTargetError(
            f"refusing to probe private/loopback host {host!r} (pass allow_private=True for CI use)"
        )
