"""Fake AdminKit Check API and interim site functions, built on `httpx.MockTransport` —
no real socket is ever opened (see `platform/openapi.stub.yaml`, `site/functions/api/*`).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

Handler = Callable[[httpx.Request], httpx.Response]
Route = tuple[str, str]  # (method, path)


def make_client(routes: dict[Route, Handler], *, base_url: str) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        route_handler = routes.get(key)
        if route_handler is None:
            return httpx.Response(404, json={"type": "about:blank", "title": "Not Found", "status": 404})
        return route_handler(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=base_url)


def make_recording_client(
    calls: list[str], routes: dict[Route, Handler], *, base_url: str
) -> httpx.AsyncClient:
    """Like `make_client`, but appends `"METHOD /path"` to `calls` for every request seen --
    lets a test assert both which routes were hit and in what order, and that a phantom route
    was never requested at all."""

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        route_handler = routes.get((request.method, request.url.path))
        if route_handler is None:
            return httpx.Response(404, json={"type": "about:blank", "title": "Not Found", "status": 404})
        return route_handler(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=base_url)


def json_handler(status: int, body: dict[str, Any]) -> Handler:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    return handler


def not_implemented() -> Handler:
    return json_handler(
        501, {"type": "about:blank", "title": "Not Implemented", "status": 501, "detail": "not shipped yet"}
    )


def all_not_implemented_api(base_url: str = "https://api.adminkit.net") -> httpx.AsyncClient:
    """An API client where every `/v1/check/*`-style route returns 501, forcing fallback."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(501, json={"type": "about:blank", "title": "Not Implemented", "status": 501})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=base_url)


def check_result_payload(
    *,
    check: str,
    target: str,
    status: str = "ok",
    summary: str = "",
    findings: list[dict[str, Any]] | None = None,
    evidence: dict[str, Any] | None = None,
    score: int | None = None,
    report_url: str | None = None,
) -> dict[str, Any]:
    return {
        "check": check,
        "target": target,
        "status": status,
        "summary": summary,
        "findings": findings or [],
        "evidence": evidence or {},
        "score": score,
        "duration_ms": 1,
        "version": "1",
        "report_url": report_url,
    }


def ip_payload(
    *, ip: str = "203.0.113.5", is_ipv6: bool = False, asn: int = 64500, cgnat_hint: bool = False
) -> dict[str, Any]:
    return {
        "ip": ip,
        "isIPv6": is_ipv6,
        "asn": asn,
        "asOrganization": "Example Networks",
        "country": "US",
        "city": None,
        "region": None,
        "timezone": None,
        "httpProtocol": "HTTP/2",
        "tlsVersion": "TLSv1.3",
        "cgnatHint": cgnat_hint,
        "cgnatReason": "shared-address-space" if cgnat_hint else None,
    }


def dns_payload(
    *, name: str, type_: str, status: str = "ok", answers: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {"name": name, "type": type_, "status": status, "answers": answers or [], "message": None}


def spf_payload(*, domain: str, status: str = "ok", all_mechanism: str | None = "-all") -> dict[str, Any]:
    return {
        "domain": domain,
        "status": status,
        "record": "v=spf1 -all" if status == "ok" else None,
        "lookupCount": 0,
        "lookupLimitExceeded": False,
        "allMechanism": all_mechanism,
        "mechanisms": [],
        "findings": [f"SPF status: {status}"],
    }


def dmarc_payload(*, domain: str, status: str = "ok", policy: str = "reject") -> dict[str, Any]:
    return {
        "domain": domain,
        "status": status,
        "record": f"v=DMARC1; p={policy}" if status == "ok" else None,
        "tags": {"p": policy} if status == "ok" else {},
        "findings": [f"DMARC policy: {policy}"],
        "suggestedRecord": f"v=DMARC1; p={policy}; rua=mailto:dmarc-reports@{domain}; pct=100",
    }


def problem_payload(
    *, status: int = 422, title: str = "Unprocessable Entity", detail: str, type_: str = "about:blank"
) -> dict[str, Any]:
    """RFC 9457 problem document, as returned by `platform/adminkit/common/errors.py`."""
    return {"type": type_, "title": title, "status": status, "detail": detail}


def ai_explain_payload(
    *,
    check: str = "spf",
    target: str = "example.com",
    model: str = "claude-fake-5",
    explanation: str = "The SPF record allows too many lookups [spf.too_many_lookups].",
    cited_evidence_ids: list[str] | None = None,
    input_tokens: int = 128,
    output_tokens: int = 64,
    generated_at: str = "2026-10-22T00:00:00Z",
) -> dict[str, Any]:
    """`AiExplainResponse` shape (`platform/adminkit/ai/models.py`)."""
    return {
        "check": check,
        "target": target,
        "model": model,
        "explanation": explanation,
        "cited_evidence_ids": cited_evidence_ids or ["spf.too_many_lookups"],
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "generated_at": generated_at,
    }


def subnet_payload(
    *, cidr: str = "192.0.2.0/24", version: int = 4, network: str = "192.0.2.0"
) -> dict[str, Any]:
    return {
        "cidr": cidr,
        "version": version,
        "network": network,
        "prefix_length": 24,
        "netmask": "255.255.255.0",
        "broadcast": "192.0.2.255",
        "wildcard": "0.0.0.255",
        "total_addresses": "256",
        "usable_hosts": "254",
        "first_usable": "192.0.2.1",
        "last_usable": "192.0.2.254",
        "is_private": False,
        "is_global": False,
        "is_loopback": False,
        "is_multicast": False,
    }


def ip_info_payload(*, ip: str = "203.0.113.9", version: int = 4) -> dict[str, Any]:
    return {
        "ip": ip,
        "version": version,
        "is_private": False,
        "is_global": True,
        "is_loopback": False,
        "is_link_local": False,
        "is_multicast": False,
        "is_reserved": False,
        "reverse_dns": "9.113.0.203.in-addr.arpa",
        "integer": "3405803529",
        "compressed": ip,
        "exploded": ip,
    }


def ipv6_info_payload(
    *,
    ip: str = "2001:db8::1",
    embedded_ipv4: str | None = None,
    embedded_ipv4_kind: str | None = None,
) -> dict[str, Any]:
    return {
        "ip": ip,
        "version": 6,
        "is_private": False,
        "is_global": False,
        "is_link_local": False,
        "is_multicast": False,
        "is_loopback": False,
        "is_reserved": True,
        "compressed": ip,
        "exploded": "2001:0db8:0000:0000:0000:0000:0000:0001",
        "reverse_pointer": "1.0.0.0...d.b.8.0.1.0.0.2.ip6.arpa",
        "network_64": "2001:db8::/64",
        "embedded_ipv4": embedded_ipv4,
        "embedded_ipv4_kind": embedded_ipv4_kind,
        "teredo_server": None,
    }


def mac_vendor_payload(
    *,
    mac: str = "AA:BB:CC:DD:EE:FF",
    found: bool = True,
    organization: str | None = "Example Networks Inc.",
) -> dict[str, Any]:
    return {
        "mac": mac,
        "is_oui_only": False,
        "found": found,
        "organization": organization if found else None,
        "matched_prefix": "AABBCC" if found else None,
        "assignment": "MA-L" if found else None,
        "locally_administered": False,
        "multicast": False,
    }


def user_agent_payload(
    *,
    ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0",
    browser_family: str | None = "Chrome",
    is_bot: bool = False,
) -> dict[str, Any]:
    return {
        "ua": ua,
        "browser_family": browser_family,
        "browser_version": "119.0.0" if browser_family else None,
        "os_family": "Windows" if browser_family else None,
        "os_version": "10" if browser_family else None,
        "device_family": None,
        "device_brand": None,
        "device_model": None,
        "is_bot": is_bot,
    }
