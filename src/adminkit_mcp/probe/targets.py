"""Refuses to probe private/loopback targets unless explicitly allowed (CI use only).

Active probing is only safe against targets the caller actually controls (spec section 8
rule 1). A public MCP tool has no ownership-verification step, so the floor is: never
touch a private network from a server a stranger can invoke, unless the operator opted
in (`--allow-private` / `ADMINKIT_MCP_ALLOW_PRIVATE=1`), which is meant for CI runners
scanning their own localhost test fixture.

A name is refused when ANY address it resolves to is not globally routable. The probe's own
HTTP client additionally uses `PinnedNetworkBackend`, which re-runs the same check for every TCP
connection and connects to the address it just vetted, so a second (rebound) DNS answer cannot
steer the socket to a private address between the check and the connect.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class PrivateTargetError(Exception):
    """Raised when a target resolves to a private/loopback/link-local address."""


# Range tables and `_is_public_address` mirror the logic of `is_public_address` in the
# proprietary control plane (platform/adminkit/check/netguard.py, Netbase JSC). Copied, not
# imported: this package is MIT-licensed and ships independently of `platform/`.
_BLOCKED_V4 = tuple(
    ipaddress.IPv4Network(n)
    for n in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",  # RFC 1918
        "100.64.0.0/10",  # RFC 6598 shared address space (CGNAT), incl. 100.100.100.200 metadata
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, incl. cloud metadata 169.254.169.254
        "172.16.0.0/12",  # RFC 1918
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # TEST-NET-1
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "192.168.0.0/16",  # RFC 1918
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, incl. limited broadcast
    )
)
_BLOCKED_V6 = tuple(
    ipaddress.IPv6Network(n)
    for n in (
        "::/96",  # unspecified, loopback, deprecated IPv4-compatible
        "64:ff9b:1::/48",  # local-use NAT64
        "100::/64",  # discard-only
        "2001::/23",  # IETF protocol assignments, incl. Teredo
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4 (embeds an arbitrary IPv4 address)
        "3fff::/20",  # documentation
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
    )
)
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_LOCAL_NAMES = ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback")


def _is_public_address(ip: IPAddress) -> bool:
    """True only for a globally routable unicast address; IPv4-mapped and NAT64 forms are
    judged by the IPv4 address they embed."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _is_public_address(ip.ipv4_mapped)
        if ip in _NAT64_WELL_KNOWN:
            return _is_public_address(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip.is_site_local or any(ip in net for net in _BLOCKED_V6):
            return False
    elif any(ip in net for net in _BLOCKED_V4):
        return False
    return ip.is_global and not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_private_ip(ip: IPAddress) -> bool:
    return not _is_public_address(ip)


def _parse_ip(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return None


async def _resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


async def resolve_host_is_private(host: str) -> bool:
    """True if `host` is a private/loopback literal, or ANY address it resolves to is non-public."""
    if host.lower().rstrip(".") in _LOCAL_NAMES:
        return True
    ip = _parse_ip(host)
    if ip is not None:
        return _is_private_ip(ip)
    try:
        addresses = await _resolve(host)
    except OSError:
        # Unresolvable hosts are rejected later by the HTTP call itself; do not block here.
        return False
    return any(_is_private_ip(ipaddress.ip_address(addr.split("%", 1)[0])) for addr in addresses)


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


async def pin_public_address(host: str) -> str:
    """Resolve `host` once, refuse it if any answer is non-public, and return the vetted
    address to connect to. Raises `PrivateTargetError` or `OSError` (unresolvable)."""
    if host.lower().rstrip(".") in _LOCAL_NAMES:
        raise PrivateTargetError(f"refusing to connect to private/loopback host {host!r}")
    literal = _parse_ip(host)
    addresses = [str(literal)] if literal is not None else await _resolve(host)
    if not addresses:
        raise OSError(f"{host!r} has no address")
    for addr in addresses:
        if _is_private_ip(ipaddress.ip_address(addr.split("%", 1)[0])):
            raise PrivateTargetError(f"refusing to connect to private/loopback host {host!r}")
    return addresses[0]


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """`httpcore` backend that vets every TCP connection with `pin_public_address` and connects
    to the vetted IP. TLS runs afterwards with the request's own hostname as SNI / certificate
    name, and the Host header is untouched, so only the socket destination is pinned."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend | None = None) -> None:
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            ip = await pin_public_address(host)
        except (PrivateTargetError, OSError) as exc:
            raise httpcore.ConnectError(str(exc)) from exc
        return await self._inner.connect_tcp(
            ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Iterable[Any] | None = None
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("unix socket connections are refused")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def pinned_async_client(inner: httpcore.AsyncNetworkBackend | None = None) -> httpx.AsyncClient:
    """An `httpx.AsyncClient` whose every connection goes through `PinnedNetworkBackend`.

    httpx 0.28 has no public hook for an httpcore network backend, so the transport's pool is
    rebuilt with the same TLS context and the pinned backend (trust_env is off so an env proxy
    cannot bypass the pin)."""
    transport = httpx.AsyncHTTPTransport()
    old_pool = transport._pool
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=old_pool._ssl_context,
        network_backend=PinnedNetworkBackend(inner),
    )
    return httpx.AsyncClient(transport=transport, trust_env=False)
