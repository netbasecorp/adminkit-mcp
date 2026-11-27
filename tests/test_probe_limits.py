"""Overall deadline and byte caps for the MCP probe, against real misbehaving servers on 127.0.0.1.

Each server here is a synthetic stdlib fixture: one trickles a body a byte at a time (so no
single read ever times out), others stream an endless SSE feed, one unterminated SSE line or
an oversize JSON body. The probe must return within deadline + 1 s, stop reading at its caps
and say why in `evidence.limits`.
"""

from __future__ import annotations

import threading
import time
import tracemalloc
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from adminkit_mcp.cli import main
from adminkit_mcp.probe.mcp_probe import ProbeLimits, probe_mcp_endpoint

Behaviour = Callable[[BaseHTTPRequestHandler], None]
SMALL = ProbeLimits(max_body_bytes=64 * 1024, max_sse_event_bytes=16 * 1024, max_sse_stream_bytes=128 * 1024)


class _Stats:
    def __init__(self) -> None:
        self.bytes_sent = 0
        self.lock = threading.Lock()

    def add(self, n: int) -> None:
        with self.lock:
            self.bytes_sent += n


def _write(handler: BaseHTTPRequestHandler, stats: _Stats, data: bytes) -> bool:
    try:
        handler.wfile.write(data)
        handler.wfile.flush()
    except (BrokenPipeError, ConnectionResetError):
        return False
    stats.add(len(data))
    return True


@pytest.fixture
def serve() -> Iterator[Callable[[dict[tuple[str, str], Behaviour]], str]]:
    """`serve({(method, path): behaviour}) -> base_url`; unknown routes answer 404."""
    servers: list[ThreadingHTTPServer] = []

    def start(routes: dict[tuple[str, str], Behaviour]) -> str:
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 -- stdlib signature
                pass

            def _dispatch(self, method: str) -> None:
                if method == "POST":
                    self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
                behaviour = routes.get((method, self.path.split("?")[0]))
                if behaviour is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.close_connection = True
                behaviour(self)

            def do_GET(self) -> None:  # noqa: N802 -- stdlib handler method name
                self._dispatch("GET")

            def do_POST(self) -> None:  # noqa: N802 -- stdlib handler method name
                self._dispatch("POST")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _headers(handler: BaseHTTPRequestHandler, content_type: str, length: int | None = None) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    if length is not None:
        handler.send_header("Content-Length", str(length))
    handler.send_header("Connection", "close")
    handler.end_headers()


def _trickle(stats: _Stats) -> Behaviour:
    """Headers, then one byte every 0.2 s for a minute: every read succeeds, nothing completes."""

    def behaviour(handler: BaseHTTPRequestHandler) -> None:
        _headers(handler, "application/json", length=10_000)
        for _ in range(300):
            if not _write(handler, stats, b" "):
                return
            time.sleep(0.2)

    return behaviour


def _json(payload: bytes) -> Behaviour:
    def behaviour(handler: BaseHTTPRequestHandler) -> None:
        _headers(handler, "application/json", length=len(payload))
        handler.wfile.write(payload)

    return behaviour


def _status(code: int) -> Behaviour:
    def behaviour(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(code)
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    return behaviour


def _endless_sse(stats: _Stats, first: bytes, chunk: bytes) -> Behaviour:
    """An SSE stream that sends `first`, then `chunk` until the client hangs up (or ~1 GiB)."""

    def behaviour(handler: BaseHTTPRequestHandler) -> None:
        _headers(handler, "text/event-stream")
        if not _write(handler, stats, first):
            return
        while stats.bytes_sent < 1 << 30:
            if not _write(handler, stats, chunk):
                return

    return behaviour


_INIT_OK = b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"slow"}}}'


async def _timed_probe(url: str, **kwargs: Any) -> tuple[dict[str, Any], float]:
    started = time.monotonic()
    result = await probe_mcp_endpoint(url, allow_private=True, **kwargs)
    return result.to_dict(), time.monotonic() - started


def _limits(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    notes: dict[str, dict[str, Any]] = {}
    for note in payload["evidence"].get("limits", []):
        notes.setdefault(note["limit"], note)  # the first hop each limit cut
    return notes


async def test_deadline_cuts_a_trickling_initialize(serve: Callable[..., str]) -> None:
    base = serve({("POST", "/mcp"): _trickle(_Stats())})
    payload, elapsed = await _timed_probe(base + "/mcp", timeout=30.0, deadline=1.5)
    assert elapsed < 1.5 + 1.0
    assert payload["status"] == "error"
    assert "deadline of 1.5 s" in payload["summary"]
    note = _limits(payload)["deadline"]
    assert note["hop"] == "initialize"
    assert note["skipped_hops"] == ["sse_stream"]


async def test_deadline_keeps_what_was_learned_before_it(serve: Callable[..., str]) -> None:
    calls: list[int] = []
    stats = _Stats()
    trickle = _trickle(stats)

    def init_then_trickle(handler: BaseHTTPRequestHandler) -> None:
        calls.append(1)
        (_json(_INIT_OK) if len(calls) == 1 else trickle)(handler)

    base = serve({("POST", "/mcp"): init_then_trickle})
    payload, elapsed = await _timed_probe(base + "/mcp", timeout=30.0, deadline=1.5)
    assert elapsed < 1.5 + 1.0
    assert payload["status"] == "fail"
    assert "mcp.no_auth_required" in {f["id"] for f in payload["findings"]}
    assert payload["evidence"]["server_info"] == {"name": "slow"}
    note = _limits(payload)["deadline"]
    assert note["hop"] == "tools_list"
    assert note["skipped_hops"] == ["oauth_protected_resource"]


async def test_deadline_cuts_a_silent_legacy_sse_stream(serve: Callable[..., str]) -> None:
    def silent_sse(handler: BaseHTTPRequestHandler) -> None:
        _headers(handler, "text/event-stream")
        for _ in range(300):
            if not _write(handler, _Stats(), b": ping\n"):
                return
            time.sleep(0.2)

    base = serve({("POST", "/sse"): _status(405), ("GET", "/sse"): silent_sse})
    payload, elapsed = await _timed_probe(base + "/sse", timeout=30.0, deadline=1.5)
    assert elapsed < 1.5 + 1.0
    assert payload["status"] == "error"
    assert _limits(payload)["deadline"]["hop"] == "sse_stream"


def test_cli_deadline_flag(serve: Callable[..., str], capsys: pytest.CaptureFixture[str]) -> None:
    import json

    base = serve({("POST", "/mcp"): _trickle(_Stats())})
    started = time.monotonic()
    exit_code = main(["probe", base + "/mcp", "--allow-private", "--timeout", "30", "--deadline", "1"])
    assert time.monotonic() - started < 2.0
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert _limits(payload)["deadline"]["hop"] == "initialize"


async def test_endless_sse_stream_stops_at_stream_cap(serve: Callable[..., str]) -> None:
    stats = _Stats()
    base = serve(
        {("POST", "/sse"): _status(405), ("GET", "/sse"): _endless_sse(stats, b"", b": ping\n" * 512)}
    )
    tracemalloc.start()
    try:
        payload, elapsed = await _timed_probe(base + "/sse", timeout=30.0, deadline=10.0, limits=SMALL)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert elapsed < 5.0
    assert payload["status"] == "error"
    note = _limits(payload)["stream_bytes"]
    assert note["hop"] == "sse_stream"
    assert peak < 4 * 1024 * 1024
    time.sleep(0.2)
    assert stats.bytes_sent < 64 * 1024 * 1024  # the server saw the client hang up early


async def test_endless_sse_event_stops_at_event_cap(serve: Callable[..., str]) -> None:
    sse = _endless_sse(_Stats(), b"event: endpoint\n", b"data: " + b"A" * 1000 + b"\n")
    base = serve({("POST", "/sse"): _status(405), ("GET", "/sse"): sse})
    payload, _ = await _timed_probe(base + "/sse", deadline=10.0, limits=SMALL)
    assert _limits(payload)["sse_event_bytes"]["hop"] == "sse_stream"


async def test_unterminated_sse_line_stops_at_event_cap(serve: Callable[..., str]) -> None:
    sse = _endless_sse(_Stats(), b"data: ", b"B" * 4096)
    base = serve({("POST", "/sse"): _status(405), ("GET", "/sse"): sse})
    payload, _ = await _timed_probe(base + "/sse", deadline=10.0, limits=SMALL)
    assert _limits(payload)["sse_event_bytes"]["hop"] == "sse_stream"


async def test_endless_sse_after_initialize_keeps_partial_result(serve: Callable[..., str]) -> None:
    sse = _endless_sse(_Stats(), b"event: endpoint\ndata: /messages\n\n", b": ping\n" * 512)
    base = serve({("POST", "/sse"): _status(405), ("GET", "/sse"): sse, ("POST", "/messages"): _status(202)})
    payload, _ = await _timed_probe(base + "/sse", deadline=10.0, limits=SMALL)
    assert payload["evidence"]["transport"] == "legacy-sse"
    assert "mcp.no_auth_required" in {f["id"] for f in payload["findings"]}
    assert _limits(payload)["stream_bytes"]["hop"] == "legacy_initialize"


async def test_endless_streamable_sse_reply_stops_at_cap(serve: Callable[..., str]) -> None:
    sse = _endless_sse(_Stats(), b"", b": ping\n" * 512)
    base = serve({("POST", "/mcp"): sse})
    payload, elapsed = await _timed_probe(base + "/mcp", deadline=10.0, limits=SMALL)
    assert elapsed < 5.0
    assert payload["evidence"]["transport"] == "streamable-http"
    assert _limits(payload)["stream_bytes"]["hop"] == "initialize"


async def test_oversize_json_body_stops_at_body_cap(serve: Callable[..., str]) -> None:
    stats = _Stats()
    total = 512 * 1024 * 1024

    def huge_json(handler: BaseHTTPRequestHandler) -> None:
        _headers(handler, "application/json", length=total)
        chunk = b'{"x":"' + b"C" * 65536
        while stats.bytes_sent < total:
            if not _write(handler, stats, chunk):
                return

    base = serve({("POST", "/mcp"): huge_json})
    tracemalloc.start()
    try:
        payload, elapsed = await _timed_probe(base + "/mcp", timeout=30.0, deadline=10.0, limits=SMALL)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert elapsed < 5.0
    note = _limits(payload)["body_bytes"]
    assert note["hop"] == "initialize"
    assert "65536" in note["detail"]
    assert peak < 4 * 1024 * 1024
    time.sleep(0.2)
    assert stats.bytes_sent < 64 * 1024 * 1024


async def test_oversize_oauth_metadata_is_capped(serve: Callable[..., str]) -> None:
    big = b'{"authorization_servers": ["' + b"D" * (128 * 1024) + b'"]}'
    base = serve(
        {
            ("POST", "/mcp"): _status(401),
            ("GET", "/.well-known/oauth-protected-resource"): _json(big),
        }
    )
    payload, _ = await _timed_probe(base + "/mcp", deadline=10.0, limits=SMALL)
    assert payload["evidence"]["auth_required"] is True
    assert "oauth_metadata" not in payload["evidence"]
    assert _limits(payload)["body_bytes"]["hop"] == "oauth_protected_resource"


async def test_well_behaved_server_reports_no_limits(fake_mcp_server: Callable[..., str]) -> None:
    from fakes.fake_mcp_server import FakeMcpConfig

    for config in (
        FakeMcpConfig(tool_names=("search",)),
        FakeMcpConfig(tool_names=("search",), support_streamable_http=False, support_legacy_sse=True),
    ):
        payload, _ = await _timed_probe(fake_mcp_server(config) + "/mcp", deadline=10.0, limits=SMALL)
        assert payload["evidence"]["tool_names"] == ["search"]
        assert "limits" not in payload["evidence"]
