"""AdminKit's own MCP endpoint exposure probe (spec section 18.8, section 8 rules 1-2).

Speaks just enough MCP to call `initialize` and `tools/list` anonymously, and to read
whatever OAuth metadata a server chooses to publish. Tool *names* only are ever read.
`tools/call` is never sent — this is a pure read-only reconnaissance probe, not a scanner
that exercises tools. Supports both the modern streamable-HTTP transport and the legacy
HTTP+SSE transport, trying streamable HTTP first.

Every probe runs under one overall deadline (all hops: target vetting, initialize,
tools/list, the legacy SSE stream, OAuth metadata) and every response body / SSE event is
read as a stream and capped. A hop cut short by either is skipped and listed in the
additive `evidence.limits` (`[{hop, limit, detail}]`) instead of hanging or buffering.

This module is an independent, from-scratch implementation written for the open-source
`mcp/` directory; it does not import or vendor code from the proprietary `checks/` library
(see `LICENSES.md`).
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from adminkit_mcp import __version__
from adminkit_mcp.probe.sse import StreamLimitError, iter_capped_lines, iter_sse_events
from adminkit_mcp.probe.targets import PrivateTargetError, check_target_allowed, pinned_async_client

ProbeStatus = Literal["ok", "warn", "fail", "error", "skipped"]
Severity = Literal["info", "low", "medium", "high", "critical"]

_PROTOCOL_VERSION = "2025-06-18"
_CLIENT_INFO = {"name": "adminkit-mcp-probe", "version": __version__}
_INITIALIZE_PARAMS: dict[str, Any] = {
    "protocolVersion": _PROTOCOL_VERSION,
    "capabilities": {},
    "clientInfo": _CLIENT_INFO,
}
_DEFAULT_TIMEOUT = 8.0
_DEFAULT_DEADLINE = 20.0
# Backstop only: every hop is already bounded by the deadline itself.
_DEADLINE_GRACE = 0.5

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


@dataclass(frozen=True)
class ProbeLimits:
    """Byte caps for everything read from the probed server."""

    max_body_bytes: int = 1024 * 1024
    max_sse_event_bytes: int = 512 * 1024
    max_sse_stream_bytes: int = 2 * 1024 * 1024


@dataclass
class _ProbeContext:
    client: httpx.AsyncClient
    timeout: float
    deadline: float
    deadline_at: float  # event-loop time
    allow_private: bool = False
    limits: ProbeLimits = field(default_factory=ProbeLimits)
    refused_hops: list[dict[str, str]] = field(default_factory=list)
    limit_notes: list[dict[str, Any]] = field(default_factory=list)

    def remaining(self) -> float:
        return self.deadline_at - asyncio.get_running_loop().time()

    def note_limit(self, hop: str, limit: str, detail: str) -> None:
        self.limit_notes.append({"hop": hop, "limit": limit, "detail": detail})

    def note_deadline(self, hop: str) -> None:
        """First call records the hop the deadline cut; later hops are listed as skipped."""
        for note in self.limit_notes:
            if note["limit"] == "deadline":
                note.setdefault("skipped_hops", []).append(hop)
                return
        self.note_limit(hop, "deadline", _deadline_detail(self.deadline))

    @property
    def deadline_hit(self) -> bool:
        return any(note["limit"] == "deadline" for note in self.limit_notes)

    def add_to(self, evidence: dict[str, Any]) -> None:
        if self.refused_hops:
            evidence["refused_hops"] = self.refused_hops
        if self.limit_notes:
            evidence["limits"] = self.limit_notes


def _deadline_detail(deadline: float) -> str:
    return f"overall probe deadline of {deadline:g} s reached"


async def _bounded[T](ctx: _ProbeContext, hop: str, fn: Callable[[], Awaitable[T]]) -> T | None:
    """Run one hop within what is left of the overall deadline; None if it is cut or skipped."""
    if ctx.remaining() <= 0:
        ctx.note_deadline(hop)
        return None
    try:
        async with asyncio.timeout_at(ctx.deadline_at):
            return await fn()
    except TimeoutError:
        ctx.note_deadline(hop)
        return None


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
    deadline: float = _DEFAULT_DEADLINE,
    limits: ProbeLimits | None = None,
) -> McpProbeResult:
    """Probe a single MCP endpoint URL and return findings + a 0-100 score.

    `client` lets tests and the GitHub Action inject an `httpx.AsyncClient` (e.g. one
    bound to a `MockTransport` or a real loopback fixture server); when omitted a
    short-lived client is created and closed internally. Without `allow_private` that
    internal client pins every connection to a vetted public address (DNS rebinding guard).
    Server-controlled follow-up URLs (SSE message endpoint, OAuth authorization server)
    are vetted the same way before they are requested.

    `timeout` bounds each request; `deadline` (seconds) bounds the whole probe, and
    `limits` caps the bytes read from any response body or SSE event.
    """
    loop = asyncio.get_running_loop()
    deadline_at = loop.time() + deadline
    try:
        async with asyncio.timeout_at(deadline_at):
            await check_target_allowed(url, allow_private=allow_private)
    except PrivateTargetError as exc:
        return _skipped(url, str(exc))
    except TimeoutError:
        note = {"hop": "target", "limit": "deadline", "detail": _deadline_detail(deadline)}
        return _error(url, _deadline_detail(deadline) + " while vetting the target", {"limits": [note]})

    owns_client = client is None
    if client is not None:
        http_client = client
    elif allow_private:
        http_client = httpx.AsyncClient()
    else:
        http_client = pinned_async_client()
    ctx = _ProbeContext(
        client=http_client,
        timeout=timeout,
        deadline=deadline,
        deadline_at=deadline_at,
        allow_private=allow_private,
        limits=limits or ProbeLimits(),
    )
    try:
        async with asyncio.timeout_at(deadline_at + _DEADLINE_GRACE):
            return await _probe(url, ctx)
    except TimeoutError:
        ctx.note_deadline("probe")
        evidence: dict[str, Any] = {}
        ctx.add_to(evidence)
        return _error(url, _deadline_detail(deadline), evidence)
    finally:
        if owns_client:
            await http_client.aclose()


async def _probe(url: str, ctx: _ProbeContext) -> McpProbeResult:
    is_tls = urlsplit(url).scheme == "https"
    evidence: dict[str, Any] = {"tls": is_tls, "transport": None}
    findings: list[McpFinding] = []

    streamable = await _probe_streamable_http(url, ctx)
    if streamable is None:
        legacy = await _probe_legacy_sse(url, ctx)
        if legacy is None:
            ctx.add_to(evidence)
            if ctx.deadline_hit:
                summary = _deadline_detail(ctx.deadline) + " before the MCP endpoint answered"
            else:
                summary = "could not reach MCP endpoint via streamable HTTP or legacy SSE"
            return _error(url, summary, evidence)
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

    oauth_meta = await _discover_oauth_metadata(url, ctx)
    if oauth_meta:
        evidence["oauth_metadata"] = oauth_meta
    ctx.add_to(evidence)

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


@dataclass
class _Reply:
    status_code: int
    headers: httpx.Headers
    data: Any = None  # parsed JSON body (or first SSE event), None if absent/unparseable/capped


async def _request(
    ctx: _ProbeContext,
    hop: str,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    content: bytes | None = None,
    read_body: bool = True,
) -> _Reply:
    """One request with a capped, streamed body read (only for 200 replies). Raises httpx errors."""
    async with ctx.client.stream(method, url, headers=headers, content=content, timeout=ctx.timeout) as resp:
        data = await _read_json_body(ctx, hop, resp) if read_body and resp.status_code == 200 else None
        return _Reply(resp.status_code, resp.headers, data)


async def _fetch(
    ctx: _ProbeContext,
    hop: str,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    content: bytes | None = None,
) -> _Reply | None:
    """`_request` bounded by the deadline; None on a transport error or when cut/skipped."""

    async def run() -> _Reply | None:
        try:
            return await _request(ctx, hop, method, url, headers=headers, content=content)
        except httpx.HTTPError:
            return None

    return await _bounded(ctx, hop, run)


async def _read_json_body(ctx: _ProbeContext, hop: str, resp: httpx.Response) -> Any:
    """JSON from a body, or from the first event of an SSE body; stops reading at the caps."""
    limits = ctx.limits
    try:
        if "text/event-stream" in resp.headers.get("content-type", ""):
            lines = iter_capped_lines(
                resp.aiter_bytes(),
                max_line_bytes=limits.max_sse_event_bytes,
                max_total_bytes=limits.max_sse_stream_bytes,
            )
            events = iter_sse_events(lines, max_event_bytes=limits.max_sse_event_bytes)
            try:
                async for ev in events:
                    return json.loads(ev.data)
            finally:
                await events.aclose()
            return None
        body = bytearray()
        async for chunk in resp.aiter_bytes():
            body += chunk
            if len(body) > limits.max_body_bytes:
                raise StreamLimitError("body_bytes", limits.max_body_bytes)
        return json.loads(bytes(body))
    except StreamLimitError as exc:
        ctx.note_limit(hop, exc.limit, str(exc))
        return None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


async def _probe_streamable_http(url: str, ctx: _ProbeContext) -> _TransportResult | None:
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    resp = await _fetch(
        ctx,
        "initialize",
        "POST",
        url,
        headers=headers,
        content=_jsonrpc_request(1, "initialize", _INITIALIZE_PARAMS),
    )
    if resp is None:
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

    result = _extract_jsonrpc_result(resp.data)
    session_id = resp.headers.get("mcp-session-id")
    tool_names: list[str] | None = None
    tools_headers = dict(headers)
    if session_id:
        tools_headers["Mcp-Session-Id"] = session_id
    tools_resp = await _fetch(
        ctx, "tools_list", "POST", url, headers=tools_headers, content=_jsonrpc_request(2, "tools/list", {})
    )
    tools_status = tools_resp.status_code if tools_resp is not None else None
    if tools_resp is not None and tools_resp.status_code == 200:
        tool_names = _tool_names(_extract_jsonrpc_result(tools_resp.data))

    return _TransportResult(
        auth_required=False,
        init_status=resp.status_code,
        server_info=(result or {}).get("serverInfo"),
        negotiated_protocol_version=(result or {}).get("protocolVersion"),
        tool_names=tool_names,
        tools_list_status=tools_status,
    )


def _tool_names(tools_result: dict[str, Any] | None) -> list[str] | None:
    if tools_result is None:
        return None
    tools = tools_result.get("tools", [])
    return [t.get("name", "") for t in tools if isinstance(t, dict)] if isinstance(tools, list) else []


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port or {"http": 80, "https": 443}.get(scheme)
    return scheme, (parts.hostname or "").lower(), port


async def _hop_refusal(url: str, allow_private: bool) -> str | None:
    """Why a server-supplied follow-up URL must not be requested, or None if it may be."""
    try:
        await check_target_allowed(url, allow_private=allow_private)
    except PrivateTargetError as exc:
        return str(exc)
    return None


@dataclass
class _LegacyProgress:
    """How far the legacy session got, so a cut-short session still reports what it saw."""

    hop: str = "sse_stream"
    result: _TransportResult | None = None


async def _probe_legacy_sse(url: str, ctx: _ProbeContext) -> _TransportResult | None:
    """Legacy MCP HTTP+SSE transport: GET an SSE stream, read an `endpoint` event naming
    the POST URL for JSON-RPC requests, then read replies back over the same stream.

    The whole session shares one deadline-bounded stream; if the deadline or a byte cap
    cuts it, whatever was already learned (e.g. `initialize` accepted anonymously) is kept."""
    progress = _LegacyProgress()
    if ctx.remaining() <= 0:
        ctx.note_deadline(progress.hop)
        return None
    try:
        async with asyncio.timeout_at(ctx.deadline_at):
            return await _legacy_session(url, ctx, progress)
    except TimeoutError:
        ctx.note_deadline(progress.hop)
    except StreamLimitError as exc:
        ctx.note_limit(progress.hop, exc.limit, str(exc))
    except httpx.HTTPError:
        pass
    return progress.result


async def _legacy_session(url: str, ctx: _ProbeContext, progress: _LegacyProgress) -> _TransportResult | None:
    origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
    sse_url = url if url.rstrip("/").endswith("/sse") else origin + "/sse"
    limits = ctx.limits
    async with ctx.client.stream(
        "GET", sse_url, headers={"Accept": "text/event-stream"}, timeout=ctx.timeout
    ) as resp:
        if resp.status_code != 200 or "text/event-stream" not in resp.headers.get("content-type", ""):
            return None
        lines = iter_capped_lines(
            resp.aiter_bytes(),
            max_line_bytes=limits.max_sse_event_bytes,
            max_total_bytes=limits.max_sse_stream_bytes,
        )
        events = iter_sse_events(lines, max_event_bytes=limits.max_sse_event_bytes)

        endpoint: str | None = None
        async for ev in events:
            if ev.event == "endpoint":
                endpoint = ev.data
                break
        if endpoint is None:
            return _TransportResult(auth_required=True, init_status=resp.status_code)

        message_url = urljoin(sse_url, endpoint)
        # The endpoint comes from the probed server: never let it move the probe to
        # another origin, and vet it like the user URL.
        reason: str | None = None
        if _origin(message_url) != _origin(sse_url):
            reason = "SSE message endpoint is not on the same origin as the SSE stream"
        else:
            reason = await _hop_refusal(message_url, ctx.allow_private)
        if reason is not None:
            ctx.refused_hops.append({"hop": "sse_message_endpoint", "reason": reason})
            return None

        json_headers = {"Content-Type": "application/json"}
        progress.hop = "legacy_initialize"
        init_resp = await _request(
            ctx,
            progress.hop,
            "POST",
            message_url,
            headers=json_headers,
            content=_jsonrpc_request(1, "initialize", _INITIALIZE_PARAMS),
            read_body=False,
        )
        if init_resp.status_code in (401, 403):
            return _TransportResult(
                auth_required=True,
                init_status=init_resp.status_code,
                www_authenticate=init_resp.headers.get("www-authenticate"),
            )
        result = progress.result = _TransportResult(auth_required=False, init_status=init_resp.status_code)

        init_result = await _read_matching_message(events, expect_id=1)
        result.server_info = (init_result or {}).get("serverInfo")
        result.negotiated_protocol_version = (init_result or {}).get("protocolVersion")

        progress.hop = "legacy_tools_list"
        tools_resp = await _request(
            ctx,
            progress.hop,
            "POST",
            message_url,
            headers=json_headers,
            content=_jsonrpc_request(2, "tools/list", {}),
            read_body=False,
        )
        result.tools_list_status = tools_resp.status_code
        if tools_resp.status_code < 400:
            result.tool_names = _tool_names(await _read_matching_message(events, expect_id=2))
        return result


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


def _as_metadata_url(issuer: str) -> str | None:
    """`<issuer>/.well-known/oauth-authorization-server`, or None for an unusable issuer
    (not http(s), no host, userinfo, query or fragment)."""
    try:
        parts = urlsplit(issuer.strip())
        _ = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    if parts.query or parts.fragment or "?" in issuer or "#" in issuer or "@" in parts.netloc:
        return None
    path = parts.path.rstrip("/") + "/.well-known/oauth-authorization-server"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


async def _discover_oauth_metadata(url: str, ctx: _ProbeContext) -> dict[str, Any] | None:
    origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
    accept_json = {"Accept": "application/json"}
    resp = await _fetch(
        ctx,
        "oauth_protected_resource",
        "GET",
        origin + "/.well-known/oauth-protected-resource",
        headers=accept_json,
    )
    if resp is None or resp.status_code != 200 or not isinstance(resp.data, dict):
        return None
    data = resp.data

    out: dict[str, Any] = {"protected_resource": data}
    auth_servers = data.get("authorization_servers")
    if isinstance(auth_servers, list) and auth_servers and isinstance(auth_servers[0], str):
        hop = "oauth_authorization_server"
        as_meta_url = _as_metadata_url(auth_servers[0])
        reason: str | None
        if as_meta_url is None:
            reason = "authorization server issuer is not a plain http(s) URL"
        else:
            checked = as_meta_url
            vetting = await _bounded(ctx, hop, lambda: _hop_vetting(checked, ctx.allow_private))
            if vetting is None:
                return out  # deadline reached while vetting; already noted
            reason = vetting[0]
        if reason is not None or as_meta_url is None:
            ctx.refused_hops.append({"hop": hop, "reason": reason or ""})
            return out
        as_resp = await _fetch(ctx, hop, "GET", as_meta_url, headers=accept_json)
        if as_resp is not None and as_resp.status_code == 200 and as_resp.data is not None:
            out["authorization_server"] = as_resp.data
    return out


async def _hop_vetting(url: str, allow_private: bool) -> tuple[str | None]:
    """`_hop_refusal` wrapped so that "allowed" (None) is distinguishable from "cut" in `_bounded`."""
    return (await _hop_refusal(url, allow_private),)


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
