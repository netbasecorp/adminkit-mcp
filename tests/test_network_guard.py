"""Proves the autouse ``_no_real_network`` guard in conftest.py blocks every outbound path.

192.0.2.0/24 is TEST-NET-1 (RFC 5737) and nothing is ever sent: the guard raises before the real
socket call. Each test clears the guard's record so the teardown check passes.
"""

from __future__ import annotations

import socket

import pytest


def test_guard_blocks_dns_lookup(_no_real_network: list[str]) -> None:
    with pytest.raises(AssertionError, match="getaddrinfo"):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(AssertionError, match="gethostbyname"):
        socket.gethostbyname("example.com")
    assert len(_no_real_network) == 2
    _no_real_network.clear()


def test_guard_blocks_udp_sendto(_no_real_network: list[str]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, pytest.raises(AssertionError):
        sock.sendto(b"\x00", ("192.0.2.1", 53))
    # the system stub resolver (127.0.0.53 systemd-resolved, 127.0.0.11 Docker) forwards upstream
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, pytest.raises(AssertionError):
        sock.sendto(b"\x00", ("127.0.0.53", 53))
    assert _no_real_network == [
        "sendto non-loopback/resolver address ('192.0.2.1', 53)",
        "sendto non-loopback/resolver address ('127.0.0.53', 53)",
    ]
    _no_real_network.clear()


def test_guard_blocks_tcp_connect(_no_real_network: list[str]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(AssertionError, match="non-loopback"):
            sock.connect(("192.0.2.1", 80))
        with pytest.raises(AssertionError, match="non-loopback"):
            sock.connect_ex(("192.0.2.1", 80))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(AssertionError):
        sock.connect(("example.com", 80))  # a hostname is resolved inside C, so it is blocked too
    assert len(_no_real_network) == 3
    _no_real_network.clear()


def test_guard_allows_loopback(_no_real_network: list[str]) -> None:
    assert socket.getaddrinfo("localhost", 80)
    assert socket.getaddrinfo("127.0.0.1", 80)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"\x00", ("127.0.0.1", 9))  # discard port; UDP needs no listener
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        with pytest.raises(OSError):  # nothing listens here, but the guard lets it through
            sock.connect(("127.0.0.1", 1))
    assert _no_real_network == []
