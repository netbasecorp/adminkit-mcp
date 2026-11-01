#!/usr/bin/env python3
"""Exercises `scan.py` (the action's entrypoint) against a local fake MCP server on
127.0.0.1 for every `fail-on` value. No real-host network access, no GitHub-hosted runner.

Run via `test_action.sh`, which sets up a venv with `adminkit-mcp` installed and points
PYTHONPATH at `mcp/tests` so this reuses `fakes.fake_mcp_server` (do not duplicate it).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from fakes.fake_mcp_server import FakeMcpConfig, _make_server  # noqa: E402

SCAN_PY = Path(__file__).resolve().parents[1] / "scan.py"


def start_server(config: FakeMcpConfig) -> tuple[ThreadingHTTPServer, str]:
    server = _make_server(config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host_raw, port = server.server_address[0], server.server_address[1]
    host = host_raw.decode() if isinstance(host_raw, (bytes, bytearray)) else host_raw
    return server, f"http://{host}:{port}"


def run_scan(url: str, fail_on: str, *, allow_private: bool = True) -> tuple[int, str, dict[str, str]]:
    with tempfile.TemporaryDirectory() as tmp:
        summary_path = Path(tmp) / "summary.md"
        output_path = Path(tmp) / "output.txt"
        summary_path.write_text("")
        output_path.write_text("")
        env = dict(os.environ)
        env["GITHUB_STEP_SUMMARY"] = str(summary_path)
        env["GITHUB_OUTPUT"] = str(output_path)
        env["ADMINKIT_API_KEY"] = "dummy-test-key"
        args = [sys.executable, str(SCAN_PY), "--url", url, "--fail-on", fail_on]
        if allow_private:
            args.append("--allow-private")
        proc = subprocess.run(  # noqa: S603 -- fixed, locally-built argv; no shell, no untrusted input
            args, env=env, capture_output=True, text=True, timeout=30
        )
        outputs: dict[str, str] = {}
        for line in output_path.read_text().splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                outputs[key] = value
        return proc.returncode, summary_path.read_text(), outputs


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def test_warn_only_target() -> None:
    """Auth required (so no `no_auth_required`/tool findings), plain HTTP -> one medium
    finding (`no_tls`) -> probe status "warn"."""
    server, base_url = start_server(FakeMcpConfig(require_auth=True, tool_names=("search",)))
    url = base_url + "/mcp"
    try:
        code, summary, outputs = run_scan(url, "none")
        check(code == 0, f"warn target, fail-on=none: expected exit 0, got {code}")

        code, summary, outputs = run_scan(url, "warning")
        check(code == 1, f"warn target, fail-on=warning: expected exit 1, got {code}")
        check("Status: **warn**" in summary, "expected warn status in summary")
        check("| Finding | Severity | Evidence | Fix |" in summary, "expected a findings table")
        check(outputs.get("score") == "85", f"expected score 85, got {outputs.get('score')}")
        check("dummy-test-key" not in summary, "api key must never be echoed into the summary")

        code, summary, outputs = run_scan(url, "critical")
        check(code == 0, f"warn target, fail-on=critical: expected exit 0, got {code}")
    finally:
        server.shutdown()
        server.server_close()


def test_critical_target() -> None:
    """No auth + a dangerous-looking tool name -> a critical finding -> probe status "fail"."""
    server, base_url = start_server(FakeMcpConfig(require_auth=False, tool_names=("shell_exec",)))
    url = base_url + "/mcp"
    try:
        code, _summary, _outputs = run_scan(url, "none")
        check(code == 0, f"critical target, fail-on=none: expected exit 0, got {code}")

        code, summary, outputs = run_scan(url, "warning")
        check(code == 1, f"critical target, fail-on=warning: expected exit 1, got {code}")

        code, summary, outputs = run_scan(url, "critical")
        check(code == 1, f"critical target, fail-on=critical: expected exit 1, got {code}")
        check("Status: **fail**" in summary, "expected fail status in summary")
        findings = json.loads(outputs["findings-json"])
        check(
            any(f["severity"] == "critical" for f in findings),
            "expected a critical-severity finding for a dangerous tool name",
        )
    finally:
        server.shutdown()
        server.server_close()


def test_unreachable_target_always_fails() -> None:
    code, summary, _outputs = run_scan("http://127.0.0.1:1/mcp", "none")
    check(code == 1, f"unreachable target must fail even with fail-on=none, got {code}")
    check("Status: **error**" in summary, "expected error status in summary")


def test_private_target_without_allow_private_is_skipped() -> None:
    server, base_url = start_server(FakeMcpConfig(require_auth=False, tool_names=()))
    url = base_url + "/mcp"
    try:
        code, summary, _outputs = run_scan(url, "critical", allow_private=False)
        check(code == 0, f"skipped (private, not allowed) target must not fail, got {code}")
        check("Status: **skipped**" in summary, "expected skipped status in summary")
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    test_warn_only_target()
    test_critical_target()
    test_unreachable_target_always_fails()
    test_private_target_without_allow_private_is_skipped()
    print("all integrations/github-action tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
