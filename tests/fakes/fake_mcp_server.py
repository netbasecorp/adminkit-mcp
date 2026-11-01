"""A real, local (127.0.0.1-only) fake MCP server for `check_mcp_endpoint` probe tests.

Supports streamable HTTP and the legacy HTTP+SSE transport, optional bearer-auth gating,
configurable tool names (including dangerous-looking ones), and OAuth discovery metadata
— everything the probe in `adminkit_mcp.probe.mcp_probe` needs to exercise. Deliberately
dependency-free (stdlib `http.server`) so it stays a thin test fixture, not a second
implementation to maintain.
"""

from __future__ import annotations

import json
import queue
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest


@dataclass
class FakeMcpConfig:
    require_auth: bool = False
    tool_names: tuple[str, ...] = ()
    support_streamable_http: bool = True
    support_legacy_sse: bool = False
    oauth_protected_resource: dict[str, Any] | None = None
    oauth_authorization_server: dict[str, Any] | None = None
    received_methods: list[str] = field(default_factory=list)


class _Handler(BaseHTTPRequestHandler):
    config: FakeMcpConfig
    sse_queues: dict[str, queue.Queue[str]]
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 -- stdlib signature
        pass  # keep test output quiet

    def _authorized(self) -> bool:
        return not self.config.require_auth or self.headers.get("Authorization") is not None

    def _send_json(
        self, status: int, payload: dict[str, Any], extra_headers: dict[str, str] | None = None
    ) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 -- stdlib handler method name
        path = urlsplit(self.path).path
        if path == "/.well-known/oauth-protected-resource":
            self._serve_well_known(self.config.oauth_protected_resource)
        elif path == "/.well-known/oauth-authorization-server":
            self._serve_well_known(self.config.oauth_authorization_server)
        elif path == "/sse" and self.config.support_legacy_sse:
            self._serve_sse()
        else:
            self._send_json(404, {"error": "not found"})

    def _serve_well_known(self, payload: dict[str, Any] | None) -> None:
        if payload is None:
            self._send_json(404, {"error": "not found"})
        else:
            self._send_json(200, payload)

    def _serve_sse(self) -> None:
        session_id = f"sess-{id(self)}"
        inbox: queue.Queue[str] = queue.Queue()
        self.sse_queues[session_id] = inbox
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(f"event: endpoint\ndata: /messages?session_id={session_id}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    data = inbox.get(timeout=2.0)
                except queue.Empty:
                    break
                self.wfile.write(f"event: message\ndata: {data}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.sse_queues.pop(session_id, None)

    def do_POST(self) -> None:  # noqa: N802 -- stdlib handler method name
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            data = {}
        method = data.get("method")
        if isinstance(method, str):
            self.config.received_methods.append(method)

        if path.startswith("/messages"):
            self._handle_legacy_message(path, method, data.get("id"))
        elif path in ("/mcp", "/") and self.config.support_streamable_http:
            self._handle_streamable(method, data.get("id"))
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_legacy_message(self, path: str, method: str | None, req_id: Any) -> None:
        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"}, {"WWW-Authenticate": 'Bearer realm="fake"'})
            return
        session_ids = parse_qs(urlsplit(path).query).get("session_id") or []
        session_id = session_ids[0] if session_ids else None
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()
        inbox = self.sse_queues.get(session_id) if session_id else None
        if inbox is not None:
            inbox.put(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": self._result_for(method)}))

    def _handle_streamable(self, method: str | None, req_id: Any) -> None:
        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"}, {"WWW-Authenticate": 'Bearer realm="fake"'})
            return
        self._send_json(200, {"jsonrpc": "2.0", "id": req_id, "result": self._result_for(method)})

    def _result_for(self, method: str | None) -> dict[str, Any]:
        if method == "initialize":
            return {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "fake-mcp-server", "version": "0.0.1"},
                "capabilities": {},
            }
        if method == "tools/list":
            return {"tools": [{"name": name} for name in self.config.tool_names]}
        return {}


def _make_server(config: FakeMcpConfig) -> ThreadingHTTPServer:
    handler_cls = type("_BoundFakeMcpHandler", (_Handler,), {"config": config, "sse_queues": {}})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    server.daemon_threads = True
    return server


@pytest.fixture
def fake_mcp_server() -> Iterator[Any]:
    """Yields `start(config) -> base_url`. Starts a real server bound to 127.0.0.1."""
    created: list[ThreadingHTTPServer] = []

    def start(config: FakeMcpConfig) -> str:
        server = _make_server(config)
        created.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        host_raw, port = server.server_address[0], server.server_address[1]
        host = host_raw.decode() if isinstance(host_raw, (bytes, bytearray)) else host_raw
        return f"http://{host}:{port}"

    yield start

    for server in created:
        server.shutdown()
        server.server_close()
