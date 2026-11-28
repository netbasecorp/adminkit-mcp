"""Guards every test in this suite against real network access (AGENTS.md); see ``_no_real_network``.

Tests that need a real HTTP server use the `fake_mcp_server` fixtures, which only ever bind 127.0.0.1.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterator
from typing import Any, NoReturn

import pytest

from fakes.fake_mcp_server import fake_mcp_server  # noqa: F401 -- re-exported fixture

# --- Outbound-network guard (AGENTS.md: tests never touch a real third-party host) ---------------
# Mirrors ``platform/tests/conftest.py::_no_real_network``; copied per project on purpose (projects
# are packaged separately and never import each other's tests).

_LOCAL_NAMES = frozenset({"", "localhost", "localhost."})


def _ip_literal(host: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return None
    try:
        return ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None


def _is_local_name(host: object) -> bool:
    """``host`` may be resolved without asking any real DNS server: localhost or an IP literal."""
    if host is None:
        return True
    name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
    return name in _LOCAL_NAMES or _ip_literal(name) is not None


def _is_loopback_address(sock: socket.socket, address: object) -> bool:
    """AF_UNIX (and other non-IP families) are not network; IP addresses must be loopback.

    Port 53 is refused even on loopback: the system stub resolver lives there (127.0.0.53
    systemd-resolved, 127.0.0.11 Docker's embedded DNS) and forwards to the real internet. Fake
    DNS servers in tests bind an ephemeral port instead.
    """
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return True
    if not isinstance(address, tuple) or len(address) < 2 or address[1] == 53:
        return False
    if address[0] in _LOCAL_NAMES - {""}:
        return True
    ip = _ip_literal(address[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip is not None and ip.is_loopback


@pytest.fixture(autouse=True)
def _no_real_network() -> Iterator[list[str]]:
    """Fail loudly on any non-loopback TCP connect, UDP send or DNS lookup from a test.

    Covers asyncio, httpx/anyio and dnspython alike: they all end in ``socket.socket.connect`` /
    ``connect_ex`` / ``sendto`` / ``sendmsg`` or ``socket.getaddrinfo``. Every blocked attempt is
    also recorded and failed at teardown, because product code may catch the AssertionError and
    turn it into an "error" result, which would otherwise hide the leak. Yields the record so the
    guard's self-test can clear it.
    """
    blocked: list[str] = []
    originals: dict[tuple[object, str], Any] = {}

    def block(what: str) -> NoReturn:
        blocked.append(what)
        raise AssertionError(f"test attempted real network access: {what}")

    def patch(owner: object, name: str, wrapper: Callable[..., Any]) -> None:
        originals[(owner, name)] = getattr(owner, name)
        setattr(owner, name, wrapper)

    real = socket.socket
    real_connect, real_connect_ex = real.connect, real.connect_ex
    real_sendto, real_sendmsg = real.sendto, real.sendmsg
    real_getaddrinfo = socket.getaddrinfo
    real_gethostbyname, real_gethostbyname_ex = socket.gethostbyname, socket.gethostbyname_ex

    def connect(self: socket.socket, address: Any) -> None:
        if not _is_loopback_address(self, address):
            block(f"connect to non-loopback/resolver address {address!r}")
        real_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> int:
        if not _is_loopback_address(self, address):
            block(f"connect_ex to non-loopback/resolver address {address!r}")
        return real_connect_ex(self, address)

    def sendto(self: socket.socket, data: Any, *args: Any) -> int:
        if args and not _is_loopback_address(self, args[-1]):
            block(f"sendto non-loopback/resolver address {args[-1]!r}")
        return real_sendto(self, data, *args)

    def sendmsg(self: socket.socket, buffers: Any, *args: Any) -> int:
        if len(args) >= 3 and args[2] is not None and not _is_loopback_address(self, args[2]):
            block(f"sendmsg to non-loopback/resolver address {args[2]!r}")
        return real_sendmsg(self, buffers, *args)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if not _is_local_name(host):
            block(f"getaddrinfo of {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    def gethostbyname(host: str) -> str:
        if not _is_local_name(host):
            block(f"gethostbyname of {host!r}")
        return real_gethostbyname(host)

    def gethostbyname_ex(host: str) -> tuple[str, list[str], list[str]]:
        if not _is_local_name(host):
            block(f"gethostbyname_ex of {host!r}")
        return real_gethostbyname_ex(host)

    wrappers: list[tuple[object, str, Callable[..., Any]]] = [
        (real, "connect", connect),
        (real, "connect_ex", connect_ex),
        (real, "sendto", sendto),
        (real, "sendmsg", sendmsg),
        (socket, "getaddrinfo", getaddrinfo),
        (socket, "gethostbyname", gethostbyname),
        (socket, "gethostbyname_ex", gethostbyname_ex),
    ]
    for owner, name, wrapper in wrappers:
        patch(owner, name, wrapper)
    try:
        yield blocked
    finally:
        for (owner, name), original in originals.items():
            setattr(owner, name, original)
    if blocked:
        pytest.fail(f"test attempted real network access: {blocked}")
