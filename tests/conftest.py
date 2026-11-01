"""Guards every test in this suite against connecting anywhere but loopback (AGENTS.md).

Patches the single chokepoint every asyncio/httpx code path in this repo eventually goes
through: `socket.socket.connect`. Tests that need a real HTTP server use the
`fake_mcp_server` fixtures, which only ever bind 127.0.0.1.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from typing import Any

import pytest

from fakes.fake_mcp_server import fake_mcp_server  # noqa: F401 -- re-exported fixture

_real_connect = socket.socket.connect
_Address = tuple[Any, ...] | str


def _guarded_connect(self: socket.socket, address: _Address) -> None:
    host = address[0] if isinstance(address, tuple) else address
    if isinstance(host, str):
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and not ip.is_loopback:
            raise AssertionError(f"test attempted to connect to non-loopback address {host!r}")
    _real_connect(self, address)


@pytest.fixture(autouse=True)
def _block_non_loopback_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    yield
