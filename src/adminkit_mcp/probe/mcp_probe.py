"""AdminKit's own MCP endpoint exposure probe (spec section 18.8, section 8 rules 1-2).

Speaks just enough MCP to call `initialize` and `tools/list` anonymously, and to read
whatever OAuth metadata a server chooses to publish. Tool *names* only are ever read.
`tools/call` is never sent — this is a pure read-only reconnaissance probe, not a scanner
that exercises tools. Supports both the modern streamable-HTTP transport and the legacy
HTTP+SSE transport, trying streamable HTTP first.

This module is an independent, from-scratch implementation written for the open-source
`mcp/` directory; it does not import or vendor code from the proprietary `checks/` library
(see `LICENSES.md`).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

import httpx

from adminkit_mcp.probe.sse import iter_sse_events
from adminkit_mcp.probe.targets import PrivateTargetError, check_target_allowed

ProbeStatus = Literal["ok", "warn", "fail", "error", "skipped"]
Severity = Literal["info", "low", "medium", "high", "critical"]

_PROTOCOL_VERSION = "2025-06-18"
_CLIENT_INFO = {"name": "adminkit-mcp-probe", "version": "0.1.0"}
_INITIALIZE_PARAMS: dict[str, Any] = {
    "protocolVersion": _PROTOCOL_VERSION,
    "capabilities": {},
    "clientInfo": _CLIENT_INFO,
}
_DEFAULT_TIMEOUT = 8.0

_DANGEROUS_TOOL_NAME_RE = re.compile(
    r"(shell|exec|eval|subprocess|\bcmd\b|command|run_code|system|delete|rm_|file_write|"
    r"write_file|http_fetch|fetch_url|curl|wget)",
    re.IGNORECASE,
)

_SEVERITY_PENALTY: dict[Severity, int] = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 0,
}


@dataclass
class McpFinding:
    id: str
    severity: Severity
    title: str
    detail: str
    fix_hint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "fix_hint": self.fix_hint,
        }


@dataclass
class McpProbeResult:
    url: str
    status: ProbeStatus
    summary: str
    score: int | None
    findings: list[McpFinding] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "summary": self.summary,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "evidence": self.evidence,
        }


def _skipped(url: str, message: str) -> McpProbeResult:
    return McpProbeResult(url=url, status="skipped", summary=message, score=None)


def _error(url: str, message: str, evidence: dict[str, Any] | None = None) -> McpProbeResult:
    return McpProbeResult(url=url, status="error", summary=message, score=None, evidence=evidence or {})


def _jsonrpc_request(id_: int, method: str, params: dict[str, Any]) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": id_, "method": method, "params": params}).encode()


def _extract_jsonrpc_result(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    result = data.get("result")
    return result if isinstance(result, dict) else None


async def probe_mcp_endpoint(
    url: str,
    *,
    client: httpx.AsyncClient | None = None,
    allow_private: bool = False,
    timeout: float = _DEFAULT_TIMEOUT,
) -> McpProbeResult:
    """Probe a single MCP endpoint URL and return findings + a 0-100 score.

    `client` lets tests and the GitHub Action inject an `httpx.AsyncClient` (e.g. one
    bound to a `MockTransport` or a real loopback fixture server); when omitted a
    short-lived client is created and closed internally.
    """
    try:
        await check_target_allowed(url, allow_private=allow_private)
    except PrivateTargetError as exc:
        return _skipped(url, str(exc))

    owns_client = client is None
    http_client = client or httpx.AsyncClient()
    try:
        return await _probe(url, http_client, timeout)
    finally:
        if owns_client:
            await http_client.aclose()


async def _probe(url: str, client: httpx.AsyncClient, timeout: float) -> McpProbeResult:
    is_tls = urlsplit(url).scheme == "https"
    evidence: dict[str, Any] = {"tls": is_tls, "transport": None}
    findings: list[McpFinding] = []

    streamable = await _probe_streamable_http(url, client, timeout)
    if streamable is None:
        legacy = await _probe_legacy_sse(url, client, timeout)
        if legacy is None:
            return _error(url, "could not reach MCP endpoint via streamable HTTP or legacy SSE", evidence)
        evidence["transport"] = "legacy-sse"
        _apply_transport_result(legacy, evidence, findings)
    else:
        evidence["transport"] = "streamable-http"
        _apply_transport_result(streamable, evidence, findings)

    if not is_tls:
        findings.append(
            McpFinding(
                id="mcp.no_tls",
                severity="medium",
                title="MCP endpoint is not served over TLS",
                detail=f"{url} uses plain HTTP.",
                fix_hint="Serve the MCP endpoint over HTTPS so credentials and tool data are not sent "
                "in clear text.",
            )
        )

    oauth_meta = await _discover_oauth_metadata(url, client, timeout)
    if oauth_meta:
        evidence["oauth_metadata"] = oauth_meta

    score = _score(findings)
    status = _status_for(findings)
    summary = f"{len(findings)} finding(s)" if findings else "no anonymous access found"
    return McpProbeResult(
        url=url, status=status, summary=summary, score=score, findings=findings, evidence=evidence
    )


@dataclass
class _TransportResult:
    auth_required: bool
    init_status: int
    www_authenticate: str | None = None
    server_info: dict[str, Any] | None = None
    negotiated_protocol_version: str | None = None
    tool_names: list[str] | None = None
    tools_list_status: int | None = None


def _apply_transport_result(
    tr: _TransportResult, evidence: dict[str, Any], findings: list[McpFinding]
) -> None:
    evidence["initialize_status"] = tr.init_status
    evidence["auth_required"] = tr.auth_required
    if tr.www_authenticate:
        evidence["www_authenticate"] = tr.www_authenticate
    if tr.server_info is not None:
        evidence["server_info"] = tr.server_info
    if tr.negotiated_protocol_version is not None:
        evidence["negotiated_protocol_version"] = tr.negotiated_protocol_version

    if not tr.auth_required:
        findings.append(
            McpFinding(
                id="mcp.no_auth_required",
                severity="high",
                title="MCP server accepted `initialize` without authentication",
                detail=f"`initialize` returned HTTP {tr.init_status} with no credentials presented.",
                fix_hint="Require OAuth 2.1 (or another credential) before serving MCP requests; "
                "see the MCP authorization specification.",
            )
        )
        if tr.tool_names is not None:
            evidence["tools_list_status"] = tr.tools_list_status
            evidence["tool_names"] = tr.tool_names
            findings.append(
                McpFinding(
                    id="mcp.tools_exposed_anonymously",
                    severity="medium",
                    title="MCP tool list readable without authentication",
                    detail=f"{len(tr.tool_names)} tool(s) listed: {', '.join(tr.tool_names) or '(none)'}",
                    fix_hint="Gate `tools/list` behind authentication; anonymous clients should not "
                    "enumerate tools.",
                )
            )
            dangerous = [name for name in tr.tool_names if _DANGEROUS_TOOL_NAME_RE.search(name)]
            if dangerous:
                findings.append(
                    McpFinding(
                        id="mcp.dangerous_tool_exposed",
                        severity="critical",
                        title="A high-risk tool name is exposed anonymously",
                        detail=f"Tool name(s) suggest shell/file/network access: {', '.join(dangerous)}",
                        fix_hint="Treat these as highly privileged: require auth, an allow-list, and "
                        "human approval before any call.",
                    )
                )


async def _probe_streamable_http(
    url: str, client: httpx.AsyncClient, timeout: float
) -> _TransportResult | None:
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    try:
        resp = await client.post(
            url,
            content=_jsonrpc_request(1, "initialize", _INITIALIZE_PARAMS),
            headers=headers,
            timeout=timeout,
        )
    except httpx.HTTPError:
        return None

    if resp.status_code in (401, 403):
        return _TransportResult(
            auth_required=True,
            init_status=resp.status_code,
            www_authenticate=resp.headers.get("www-authenticate"),
        )
    if resp.status_code in (404, 405, 406):
        return None  # this origin does not speak streamable HTTP at this path
    if resp.status_code != 200:
        return _TransportResult(auth_required=True, init_status=resp.status_code)

    result = _extract_jsonrpc_result(_parse_body(resp))
    session_id = resp.headers.get("mcp-session-id")
    tool_names: list[str] | None = None
    tools_status: int | None = None
    try:
        tools_headers = dict(headers)
        if session_id:
            tools_headers["Mcp-Session-Id"] = session_id
        tools_resp = await client.post(
            url, content=_jsonrpc_request(2, "tools/list", {}), headers=tools_headers, timeout=timeout
        )
        tools_status = tools_resp.status_code
        if tools_resp.status_code == 200:
            tools_result = _extract_jsonrpc_result(_parse_body(tools_resp))
            if tools_result is not None:
                tools = tools_result.get("tools", [])
                tool_names = [t.get("name", "") for t in tools if isinstance(t, dict)]
    except httpx.HTTPError:
        pass

    return _TransportResult(
        auth_required=False,
        init_status=resp.status_code,
        server_info=(result or {}).get("serverInfo"),
        negotiated_protocol_version=(result or {}).get("protocolVersion"),
        tool_names=tool_names,
        tools_list_status=tools_status,
    )


def _parse_body(resp: httpx.Response) -> Any:
    content_type = resp.headers.get("content-type", "")
    try:
        if "text/event-stream" in content_type:
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    return json.loads(line[len("data:") :].strip())
            return None
        return json.loads(resp.text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


async def _probe_legacy_sse(url: str, client: httpx.AsyncClient, timeout: float) -> _TransportResult | None:
    """Legacy MCP HTTP+SSE transport: GET an SSE stream, read an `endpoint` event naming
    the POST URL for JSON-RPC requests, then read replies back over the same stream."""
    origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
    sse_url = url if url.rstrip("/").endswith("/sse") else origin + "/sse"
    try:
        async with client.stream(
            "GET", sse_url, headers={"Accept": "text/event-stream"}, timeout=timeout
        ) as resp:
            if resp.status_code != 200 or "text/event-stream" not in resp.headers.get("content-type", ""):
                return None
            events = iter_sse_events(resp.aiter_lines())

            endpoint: str | None = None
            async for ev in events:
                if ev.event == "endpoint":
                    endpoint = ev.data
                    break
            if endpoint is None:
                return _TransportResult(auth_required=True, init_status=resp.status_code)

            message_url = urljoin(sse_url, endpoint)
            init_resp = await client.post(
                message_url,
                content=_jsonrpc_request(1, "initialize", _INITIALIZE_PARAMS),
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            if init_resp.status_code in (401, 403):
                return _TransportResult(
                    auth_required=True,
                    init_status=init_resp.status_code,
                    www_authenticate=init_resp.headers.get("www-authenticate"),
                )

            init_result = await _read_matching_message(events, expect_id=1)

            tool_names: list[str] | None = None
            tools_status: int | None = None
            tools_resp = await client.post(
                message_url,
                content=_jsonrpc_request(2, "tools/list", {}),
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            tools_status = tools_resp.status_code
            if tools_resp.status_code < 400:
                tools_result = await _read_matching_message(events, expect_id=2)
                if tools_result is not None:
                    tools = tools_result.get("tools", [])
                    tool_names = [t.get("name", "") for t in tools if isinstance(t, dict)]

            return _TransportResult(
                auth_required=False,
                init_status=init_resp.status_code,
                server_info=(init_result or {}).get("serverInfo"),
                negotiated_protocol_version=(init_result or {}).get("protocolVersion"),
                tool_names=tool_names,
                tools_list_status=tools_status,
            )
    except httpx.HTTPError:
        return None


async def _read_matching_message(
    events: Any, *, expect_id: int, max_events: int = 10
) -> dict[str, Any] | None:
    seen = 0
    async for ev in events:
        seen += 1
        if ev.event == "message":
            try:
                data = json.loads(ev.data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(data, dict) and data.get("id") == expect_id:
                return _extract_jsonrpc_result(data)
        if seen >= max_events:
            break
    return None


async def _discover_oauth_metadata(
    url: str, client: httpx.AsyncClient, timeout: float
) -> dict[str, Any] | None:
    origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
    try:
        resp = await client.get(
            origin + "/.well-known/oauth-protected-resource",
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        data = json.loads(resp.text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None

    out: dict[str, Any] = {"protected_resource": data}
    auth_servers = data.get("authorization_servers")
    if isinstance(auth_servers, list) and auth_servers and isinstance(auth_servers[0], str):
        as_meta_url = auth_servers[0].rstrip("/") + "/.well-known/oauth-authorization-server"
        try:
            as_resp = await client.get(as_meta_url, headers={"Accept": "application/json"}, timeout=timeout)
            if as_resp.status_code == 200:
                out["authorization_server"] = json.loads(as_resp.text)
        except (httpx.HTTPError, json.JSONDecodeError, UnicodeDecodeError):
            pass
    return out


def _score(findings: list[McpFinding]) -> int:
    score = 100
    for finding in findings:
        score -= _SEVERITY_PENALTY.get(finding.severity, 0)
    return max(0, min(100, score))


def _status_for(findings: list[McpFinding]) -> ProbeStatus:
    if any(f.severity in ("critical", "high") for f in findings):
        return "fail"
    if findings:
        return "warn"
    return "ok"
