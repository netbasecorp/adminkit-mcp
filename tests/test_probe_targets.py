from __future__ import annotations

import asyncio
import socket

import pytest

from adminkit_mcp.probe.targets import PrivateTargetError, check_target_allowed, resolve_host_is_private


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "10.0.0.5", "192.168.1.1", "172.16.0.1", "::1", "169.254.1.1"],
)
async def test_private_literals_are_detected(host: str) -> None:
    assert await resolve_host_is_private(host) is True


@pytest.mark.parametrize("host", ["93.184.216.34", "1.1.1.1"])
async def test_public_literals_are_not_private(host: str) -> None:
    assert await resolve_host_is_private(host) is False


async def test_check_target_allowed_refuses_private_by_default() -> None:
    with pytest.raises(PrivateTargetError):
        await check_target_allowed("http://127.0.0.1:9999/mcp", allow_private=False)


async def test_check_target_allowed_permits_private_when_flagged() -> None:
    await check_target_allowed("http://127.0.0.1:9999/mcp", allow_private=True)  # must not raise


async def test_check_target_allowed_permits_public_ip_literal_by_default() -> None:
    await check_target_allowed("https://93.184.216.34/mcp", allow_private=False)  # must not raise


async def test_hostname_resolving_only_to_private_addresses_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_getaddrinfo(host: str, port: object, **kwargs: object) -> list[object]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
    assert await resolve_host_is_private("internal.example.test") is True


async def test_hostname_resolving_to_a_public_address_is_not_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_getaddrinfo(host: str, port: object, **kwargs: object) -> list[object]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
    assert await resolve_host_is_private("public.example.test") is False


async def test_unresolvable_hostname_is_not_treated_as_private(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_getaddrinfo(host: str, port: object, **kwargs: object) -> list[object]:
        raise OSError("name resolution failed")

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
    assert await resolve_host_is_private("does-not-resolve.example.test") is False
