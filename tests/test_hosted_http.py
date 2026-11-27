"""Hosted HTTP mode (plan row A14): `adminkit-mcp --http` is what will be fronted as
`https://mcp.adminkit.net/mcp` — public, anonymous, rate-limited, and read-only. Exercises
the real FastMCP streamable-HTTP ASGI app (`adminkit_mcp.hosted.build_hosted_http_app`)
through `httpx.ASGITransport`, so no socket is ever opened (see `conftest.py`)."""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import Any, cast

import httpx
import pytest

import adminkit_mcp
from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.config import Settings, for_hosted_http
from adminkit_mcp.hosted import build_hosted_http_app, client_rate_limit_key, refuse_private_target
from adminkit_mcp.server import build_server
from fakes.fake_api import all_not_implemented_api, make_recording_client

_INITIALIZE_BODY = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "0.0.1"},
        },
    }
).encode()

_MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
_BASE_URL = "http://127.0.0.1:8765"


@asynccontextmanager
async def _run_asgi_lifespan(app: Any) -> AsyncIterator[None]:
    """Drives the ASGI lifespan protocol by hand: `httpx.ASGITransport` sends plain HTTP
    requests only, but the streamable-HTTP session manager needs its lifespan `startup`
    (opens its task group) to have run first, same as a real uvicorn server does."""
    inbox: asyncio.Queue[dict[str, str]] = asyncio.Queue()
    startup_complete = asyncio.Event()
    shutdown_complete = asyncio.Event()

    async def receive() -> dict[str, str]:
        return await inbox.get()

    async def send(message: dict[str, str]) -> None:
        if message["type"] == "lifespan.startup.complete":
            startup_complete.set()
        elif message["type"] == "lifespan.shutdown.complete":
            shutdown_complete.set()

    task = asyncio.create_task(app({"type": "lifespan"}, receive, send))
    await inbox.put({"type": "lifespan.startup"})
    await startup_complete.wait()
    try:
        yield
    finally:
        await inbox.put({"type": "lifespan.shutdown"})
        await shutdown_complete.wait()
        await task


def _hosted_app(settings: Settings, *, client: AdminKitClient) -> Any:
    mcp = build_server(client, settings=settings)
    return build_hosted_http_app(mcp, settings=settings)


async def test_initialize_succeeds_over_hosted_http() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    settings = for_hosted_http(Settings())
    app = _hosted_app(settings, client=client)

    async with _run_asgi_lifespan(app):
        transport = httpx.ASGITransport(app=app, client=("203.0.113.5", 12345))
        async with httpx.AsyncClient(transport=transport, base_url=_BASE_URL) as http_client:
            resp = await http_client.post("/mcp", content=_INITIALIZE_BODY, headers=_MCP_HEADERS)
    await client.aclose()

    assert resp.status_code == 200
    assert resp.text.startswith("event: message")
    payload = json.loads(resp.text.split("data:", 1)[1].strip())
    assert payload["result"]["serverInfo"]["name"] == "adminkit"
    assert payload["result"]["serverInfo"]["version"] == adminkit_mcp.__version__


async def test_exceeding_rate_limit_returns_429() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    settings = replace(
        for_hosted_http(Settings()), hosted_rate_limit_per_minute=60.0, hosted_rate_limit_burst=1.0
    )
    app = _hosted_app(settings, client=client)

    async with _run_asgi_lifespan(app):
        transport = httpx.ASGITransport(app=app, client=("203.0.113.5", 12345))
        async with httpx.AsyncClient(transport=transport, base_url=_BASE_URL) as http_client:
            first = await http_client.post("/mcp", content=_INITIALIZE_BODY, headers=_MCP_HEADERS)
            second = await http_client.post("/mcp", content=_INITIALIZE_BODY, headers=_MCP_HEADERS)
    await client.aclose()

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["error"] == "rate_limited"


async def test_rate_limit_is_scoped_per_client_ip() -> None:
    """A single noisy client exhausting its own budget must not 429 a different client IP."""
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    settings = replace(
        for_hosted_http(Settings()), hosted_rate_limit_per_minute=60.0, hosted_rate_limit_burst=1.0
    )
    app = _hosted_app(settings, client=client)

    async with _run_asgi_lifespan(app):
        transport_a = httpx.ASGITransport(app=app, client=("203.0.113.5", 1))
        transport_b = httpx.ASGITransport(app=app, client=("203.0.113.9", 1))
        async with httpx.AsyncClient(transport=transport_a, base_url=_BASE_URL) as client_a:
            await client_a.post("/mcp", content=_INITIALIZE_BODY, headers=_MCP_HEADERS)
            throttled = await client_a.post("/mcp", content=_INITIALIZE_BODY, headers=_MCP_HEADERS)
        async with httpx.AsyncClient(transport=transport_b, base_url=_BASE_URL) as client_b:
            other_client = await client_b.post("/mcp", content=_INITIALIZE_BODY, headers=_MCP_HEADERS)
    await client.aclose()

    assert throttled.status_code == 429
    assert other_client.status_code == 200


async def test_oversized_body_is_rejected() -> None:
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    settings = replace(for_hosted_http(Settings()), hosted_max_body_bytes=16)
    app = _hosted_app(settings, client=client)
    assert len(_INITIALIZE_BODY) > 16

    async with _run_asgi_lifespan(app):
        transport = httpx.ASGITransport(app=app, client=("203.0.113.5", 12345))
        async with httpx.AsyncClient(transport=transport, base_url=_BASE_URL) as http_client:
            resp = await http_client.post("/mcp", content=_INITIALIZE_BODY, headers=_MCP_HEADERS)
    await client.aclose()

    assert resp.status_code == 413


@pytest.mark.parametrize("target", ["127.0.0.1", "localhost", "10.1.2.3", "169.254.1.1"])
async def test_private_target_refused_for_hosted_tool(target: str) -> None:
    calls: list[str] = []
    api = make_recording_client(calls, {}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    mcp = build_server(client, settings=for_hosted_http(Settings()))

    try:
        result = await mcp.call_tool("dns_lookup", {"name": target})
    finally:
        await client.aclose()
    structured = cast("dict[str, Any]", result[1])  # type: ignore[index]

    assert not calls, "the Check API must never be called for a refused private target"
    assert structured["status"] == "skipped"
    assert target in structured["result"]["message"]


async def test_private_target_is_allowed_in_non_hosted_mode() -> None:
    """stdio/local use (the default, no `settings` or `hosted_http=False`) must keep
    probing a caller's own localhost fixtures — only the public hosted endpoint refuses."""
    payload: dict[str, Any] = {
        "check": "dns",
        "target": "127.0.0.1",
        "status": "ok",
        "summary": "",
        "findings": [],
        "evidence": {},
        "score": None,
        "duration_ms": 1,
        "version": "1",
        "report_url": None,
    }
    calls: list[str] = []
    api = make_recording_client(
        calls,
        {("POST", "/v1/check/dns"): lambda _req: httpx.Response(200, json=payload)},
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    mcp = build_server(client)  # no settings -> hosted_http defaults to False

    try:
        await mcp.call_tool("dns_lookup", {"name": "127.0.0.1"})
    finally:
        await client.aclose()

    assert calls == ["POST /v1/check/dns"]


async def test_no_api_key_forwarded_in_hosted_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADMINKIT_API_KEY", "super-secret-key")
    settings = for_hosted_http(Settings.from_env())
    assert settings.api_key is None

    client = AdminKitClient.from_settings(settings)
    try:
        api_headers = client._api_client.headers  # noqa: SLF001 -- asserting no key leaked into it
        assert "x-api-key" not in {k.lower() for k in api_headers}
    finally:
        await client.aclose()


async def test_api_key_is_forwarded_outside_hosted_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression guard: local/stdio use (CI, an operator's own key) must be unaffected."""
    monkeypatch.setenv("ADMINKIT_API_KEY", "super-secret-key")
    settings = Settings.from_env()
    assert settings.api_key == "super-secret-key"

    client = AdminKitClient.from_settings(settings)
    try:
        api_headers = client._api_client.headers  # noqa: SLF001
        assert api_headers.get("x-api-key") == "super-secret-key"
    finally:
        await client.aclose()


def test_hosted_keys_ipv6_clients_by_64() -> None:
    a1 = client_rate_limit_key("2001:db8:1:2:aaaa::1")
    a2 = client_rate_limit_key("2001:db8:1:2:ffff:ffff:ffff:ffff")
    other = client_rate_limit_key("2001:db8:1:3::1")
    assert a1 == a2 == "2001:db8:1:2::/64"
    assert other != a1
    # IPv4 is keyed by the /32 address, unchanged; IPv4-mapped IPv6 by its embedded IPv4.
    assert client_rate_limit_key("203.0.113.5") == "203.0.113.5"
    assert client_rate_limit_key("203.0.113.6") != client_rate_limit_key("203.0.113.5")
    assert client_rate_limit_key("::ffff:203.0.113.5") == "203.0.113.5"
    assert client_rate_limit_key("fe80::1%eth0") == "fe80::/64"
    assert client_rate_limit_key("unknown") == "unknown"


async def test_hosted_rate_limit_shares_one_bucket_per_ipv6_64() -> None:
    """End to end: a second address in the same /64 is throttled, another /64 is not."""
    api = all_not_implemented_api()
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    settings = replace(
        for_hosted_http(Settings()), hosted_rate_limit_per_minute=60.0, hosted_rate_limit_burst=1.0
    )
    app = _hosted_app(settings, client=client)

    statuses: list[int] = []
    async with _run_asgi_lifespan(app):
        for addr in ("2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:3::1"):
            transport = httpx.ASGITransport(app=app, client=(addr, 1))
            async with httpx.AsyncClient(transport=transport, base_url=_BASE_URL) as http_client:
                resp = await http_client.post("/mcp", content=_INITIALIZE_BODY, headers=_MCP_HEADERS)
                statuses.append(resp.status_code)
    await client.aclose()

    assert statuses == [200, 429, 200]


def _fake_resolver(monkeypatch: pytest.MonkeyPatch, answers: dict[str, list[str]]) -> list[str]:
    """Replaces getaddrinfo with a table lookup (no real DNS); unknown names raise OSError."""
    asked: list[str] = []

    async def fake_getaddrinfo(host: str, port: object, **kwargs: object) -> list[object]:
        asked.append(host)
        if host not in answers:
            raise OSError("name resolution failed")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0)) for addr in answers[host]]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
    return asked


_BYPASS_INPUTS = ["127.0.0.1.", "10.0.0.1:22", " 10.0.0.1", "http://127.0.0.1/", "[::1]:80"]


@pytest.mark.parametrize("target", _BYPASS_INPUTS)
@pytest.mark.parametrize("tool,arg", [("dns_lookup", "name"), ("check_domain", "domain")])
async def test_hosted_refuses_trailing_dot_and_port_suffixed_private_literals(
    monkeypatch: pytest.MonkeyPatch, target: str, tool: str, arg: str
) -> None:
    asked = _fake_resolver(monkeypatch, {})
    calls: list[str] = []
    api = make_recording_client(calls, {}, base_url="https://api.adminkit.net")
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    mcp = build_server(client, settings=for_hosted_http(Settings()))

    try:
        result = await mcp.call_tool(tool, {arg: target})
    finally:
        await client.aclose()
    structured = cast("dict[str, Any]", result[1])  # type: ignore[index]

    assert not calls, "the Check API must never be called for a refused private target"
    assert not asked, "a private literal must be refused without any DNS lookup"
    assert structured["status"] == "skipped"
    assert "private/loopback" in structured["result"]["message"]


@pytest.mark.parametrize("target", _BYPASS_INPUTS)
async def test_refuse_private_target_normalises_bypass_inputs(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    _fake_resolver(monkeypatch, {})
    for is_url in (False, True):
        refused = await refuse_private_target("t", target, report_url=None, is_url=is_url)
        assert refused is not None and refused.status == "skipped"


async def test_hosted_example_com_handling_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """A public name (fake resolver answer) still goes through to the Check API, with or
    without a trailing dot / URL form; a name resolving to a private address is refused."""
    _fake_resolver(monkeypatch, {"example.com": ["93.184.216.34"], "internal.example.com": ["10.1.2.3"]})
    for value in ("example.com", "example.com.", " Example.COM ", "https://example.com/x"):
        assert await refuse_private_target("check_domain", value, report_url=None) is None
    refused = await refuse_private_target("check_domain", "internal.example.com", report_url=None)
    assert refused is not None and "private/loopback" in refused.result["message"]

    payload: dict[str, Any] = {
        "check": "dns",
        "target": "example.com",
        "status": "ok",
        "summary": "",
        "findings": [],
        "evidence": {},
        "score": None,
        "duration_ms": 1,
        "version": "1",
        "report_url": None,
    }
    calls: list[str] = []
    api = make_recording_client(
        calls,
        {("POST", "/v1/check/dns"): lambda _req: httpx.Response(200, json=payload)},
        base_url="https://api.adminkit.net",
    )
    site = all_not_implemented_api(base_url="https://adminkit.net")
    client = AdminKitClient(api, site)
    mcp = build_server(client, settings=for_hosted_http(Settings()))
    try:
        await mcp.call_tool("dns_lookup", {"name": "example.com"})
    finally:
        await client.aclose()
    assert calls == ["POST /v1/check/dns"]


@pytest.mark.parametrize(
    "target", ["", "   ", "http://", "10.0.0.1:notaport", "exa mple.com", "127.1", "0x7f.1", "2130706433"]
)
async def test_hosted_refuses_unparseable_targets(monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    _fake_resolver(monkeypatch, {})
    refused = await refuse_private_target("check_domain", target, report_url=None)
    assert refused is not None and refused.status == "skipped"


async def test_hosted_unresolvable_name_refused_only_for_connecting_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed for tools that connect to the target; DNS-only tools may look up
    record-only names such as `_dmarc.example.com` that have no address."""
    _fake_resolver(monkeypatch, {})
    refused = await refuse_private_target("check_domain", "nx.example.test", report_url=None)
    assert refused is not None and "does not resolve" in refused.result["message"]
    assert (
        await refuse_private_target(
            "dns_lookup", "_dmarc.example.test", report_url=None, require_resolvable=False
        )
        is None
    )
    # ...but a private literal is still refused for DNS-only tools.
    assert (
        await refuse_private_target("dns_lookup", "127.0.0.1.", report_url=None, require_resolvable=False)
        is not None
    )
