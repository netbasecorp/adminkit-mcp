"""SSRF guards for the MCP probe: server-supplied follow-up URLs, range table, DNS rebinding.

No network: `httpx.MockTransport`, a fake `getaddrinfo`, and a recording httpcore backend."""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import httpcore
import httpx
import pytest

from adminkit_mcp.probe import mcp_probe, targets
from adminkit_mcp.probe.mcp_probe import _as_metadata_url, probe_mcp_endpoint
from adminkit_mcp.probe.targets import resolve_host_is_private

PUBLIC = "93.184.216.34"


def _fake_dns(monkeypatch: pytest.MonkeyPatch, answers: list[list[str]]) -> list[str]:
    """Each lookup returns the next answer list (the last one repeats); returns the lookup log."""
    calls: list[str] = []

    async def fake_getaddrinfo(host: str, port: object, **kwargs: object) -> list[object]:
        answer = answers[min(len(calls), len(answers) - 1)]
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in answer]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
    return calls


async def test_probe_follow_up_urls_guarded(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns(monkeypatch, [[PUBLIC]])
    seen_hosts: list[str] = []

    def sse_server(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host)
        if request.url.host != "mcp.example.test":
            return httpx.Response(200, json={"leaked": True})
        if request.method == "POST":
            return httpx.Response(405)
        if request.url.path == "/sse":
            body = "event: endpoint\ndata: http://10.0.0.1/msg\n\n"
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=body)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(sse_server)) as client:
        sse_result = await probe_mcp_endpoint("https://mcp.example.test/sse", client=client)

    def oauth_server(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host)
        if request.url.host != "mcp.example.test":
            return httpx.Response(200, json={"issuer": "internal", "secret": "leaked"})
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(200, json={"authorization_servers": ["http://127.0.0.1:1/"]})
        return httpx.Response(401, headers={"www-authenticate": "Bearer"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(oauth_server)) as client:
        oauth_result = await probe_mcp_endpoint("https://mcp.example.test/mcp", client=client)

    assert set(seen_hosts) == {"mcp.example.test"}
    sse_hops = sse_result.to_dict()["evidence"]["refused_hops"]
    assert sse_hops[0]["hop"] == "sse_message_endpoint"
    evidence = oauth_result.to_dict()["evidence"]
    assert "authorization_server" not in evidence["oauth_metadata"]
    assert evidence["refused_hops"][0]["hop"] == "oauth_authorization_server"
    assert "leaked" not in json.dumps(oauth_result.to_dict())


async def test_sse_endpoint_on_another_public_origin_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns(monkeypatch, [[PUBLIC]])
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.method == "POST":
            return httpx.Response(405)
        body = "event: endpoint\ndata: https://other.example.test/msg\n\n"
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await probe_mcp_endpoint("https://mcp.example.test/sse", client=client)
    assert all("other.example.test" not in u for u in seen)
    assert "same origin" in result.to_dict()["evidence"]["refused_hops"][0]["reason"]


async def test_public_authorization_server_metadata_still_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns(monkeypatch, [[PUBLIC]])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(200, json={"authorization_servers": ["https://auth.example.test/"]})
        if request.url.host == "auth.example.test":
            assert request.url.path == "/.well-known/oauth-authorization-server"
            return httpx.Response(200, json={"issuer": "https://auth.example.test/"})
        return httpx.Response(401)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await probe_mcp_endpoint("https://mcp.example.test/mcp", client=client)
    evidence = result.to_dict()["evidence"]
    assert evidence["oauth_metadata"]["authorization_server"]["issuer"] == "https://auth.example.test/"
    assert "refused_hops" not in evidence


@pytest.mark.parametrize(
    "issuer",
    [
        "https://a.example.test/?x=1",
        "https://a.example.test/#f",
        "file:///etc/passwd",
        "https://u@a.example.test/",
    ],
)
def test_as_metadata_url_rejects_unusable_issuer(issuer: str) -> None:
    assert _as_metadata_url(issuer) is None


@pytest.mark.parametrize(
    "host", ["100.64.0.1", "100.100.100.200", "fec0::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1"]
)
async def test_extra_private_ranges_are_detected(host: str) -> None:
    assert await resolve_host_is_private(host) is True


async def test_public_literal_still_public() -> None:
    assert await resolve_host_is_private(PUBLIC) is False
    assert await resolve_host_is_private("64:ff9b::5db8:d822") is False  # NAT64 of a public v4


async def test_mixed_answer_is_private(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns(monkeypatch, [[PUBLIC, "10.0.0.5"]])
    assert await resolve_host_is_private("mixed.example.test") is True


class _RecordingBackend(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        self.connects: list[str] = []

    async def connect_tcp(
        self, host: str, port: int, *args: Any, **kwargs: Any
    ) -> httpcore.AsyncNetworkStream:
        self.connects.append(host)
        raise httpcore.ConnectError("test backend never opens sockets")


async def test_rebinding_host_is_never_connected_to(monkeypatch: pytest.MonkeyPatch) -> None:
    lookups = _fake_dns(monkeypatch, [[PUBLIC], ["10.0.0.5"]])
    backend = _RecordingBackend()
    original = targets.pinned_async_client
    monkeypatch.setattr(mcp_probe, "pinned_async_client", lambda: original(backend))
    result = await probe_mcp_endpoint("https://rebind.example.test/mcp")
    assert len(lookups) >= 2  # vetted once, re-resolved (and refused) at connect time
    assert backend.connects == []
    assert result.status == "error"


async def test_pinned_client_connects_to_vetted_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns(monkeypatch, [[PUBLIC]])
    backend = _RecordingBackend()
    async with targets.pinned_async_client(backend) as client:
        with pytest.raises(httpx.ConnectError):
            await client.get("https://pinned.example.test/")
    assert backend.connects == [PUBLIC]
