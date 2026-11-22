#!/usr/bin/env python3
"""Exercises `scan.py` (the action's entrypoint) against a local fake MCP server on
127.0.0.1 for every `fail-on` value. No real-host network access, no GitHub-hosted runner.

Run via `test_action.sh`, which sets up a venv with `adminkit-mcp` installed and points
PYTHONPATH at `mcp/tests` so this reuses `fakes.fake_mcp_server` (do not duplicate it).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from adminkit_mcp.probe.mcp_probe import McpProbeResult  # noqa: E402
from fakes.fake_mcp_server import FakeMcpConfig, _make_server  # noqa: E402

ACTION_DIR = Path(__file__).resolve().parents[1]
SCAN_PY = ACTION_DIR / "scan.py"
ACTION_YML = ACTION_DIR / "action.yml"

sys.path.insert(0, str(ACTION_DIR))
import scan  # noqa: E402


def start_server(config: FakeMcpConfig) -> tuple[ThreadingHTTPServer, str]:
    server = _make_server(config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host_raw, port = server.server_address[0], server.server_address[1]
    host = host_raw.decode() if isinstance(host_raw, (bytes, bytearray)) else host_raw
    return server, f"http://{host}:{port}"


def run_scan(
    url: str, fail_on: str, *, allow_private: bool = True, extra_args: tuple[str, ...] = ()
) -> tuple[int, str, dict[str, str]]:
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
        args.extend(extra_args)
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


def scan_step_env_and_script() -> tuple[dict[str, str], str]:
    """Extracts the `env:` mapping and the `run: |` script of the `id: scan` step from action.yml.

    Line-based on purpose (this test venv has no YAML parser): it only needs the block-scalar and
    flat-mapping shapes action.yml actually uses."""
    lines = ACTION_YML.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "id: scan")
    step_indent = len(lines[start]) - len(lines[start].lstrip())
    env: dict[str, str] = {}
    script: list[str] = []
    i = start + 1
    while i < len(lines):
        line = lines[i]
        indent = len(line) - len(line.lstrip())
        if line.strip() and indent < step_indent:
            break
        stripped = line.strip()
        if indent == step_indent and stripped in ("env:", "run: |"):
            block: list[str] = []
            i += 1
            while i < len(lines) and (
                not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent
            ):
                block.append(lines[i])
                i += 1
            if stripped == "env:":
                for entry in block:
                    if entry.strip() and not entry.strip().startswith("#"):
                        key, _, value = entry.strip().partition(":")
                        env[key] = value.strip()
            else:
                body_indent = min(len(b) - len(b.lstrip()) for b in block if b.strip())
                script = [b[body_indent:] for b in block]
            continue
        i += 1
    return env, "\n".join(script) + "\n"


def render_expressions(text: str, inputs: dict[str, str]) -> str:
    """What the Actions runner does before a step starts: textually replace every
    `${{ inputs.<name> }}` / `${{ github.action_path }}` with its value, no quoting."""

    def sub(match: re.Match[str]) -> str:
        expr = match.group(1)
        if expr.startswith("inputs."):
            return inputs[expr.removeprefix("inputs.")]
        if expr == "github.action_path":
            return str(ACTION_DIR)
        raise AssertionError(f"unexpected expression in scan step: {expr}")

    return re.sub(r"\$\{\{\s*([^}]+?)\s*\}\}", sub, text)


def test_scan_step_does_not_execute_shell_in_inputs() -> None:
    """A url input crafted to break out of a double-quoted shell string must reach scan.py as one
    literal argv entry, not run as a command. Runs the step's real `run:` script under bash with
    GitHub's expression substitution emulated and a `python` shim that only records its argv."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        marker = tmp_path / "pwned"
        payload = f'";touch {marker};"'
        inputs = {
            "url": payload,
            "fail-on": f'critical";touch {marker};"',
            "allow-private": f'true" ]; touch {marker}; [ "',
            "api-key": "dummy-test-key",
            "timeout-seconds": f'60";touch {marker};"',
        }
        env_block, script = scan_step_env_and_script()

        argv_log = tmp_path / "argv.json"
        shim_dir = tmp_path / "bin"
        shim_dir.mkdir()
        shim = shim_dir / "python"
        shim.write_text(
            f"#!{sys.executable}\nimport json, sys\n"
            f"open({str(argv_log)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
        )
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)

        env = {
            "PATH": f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "GITHUB_ACTION_PATH": str(ACTION_DIR),
        }
        env.update({k: render_expressions(v, inputs) for k, v in env_block.items()})
        bash = shutil.which("bash")
        check(bash is not None, "bash is required for this test")
        proc = subprocess.run(  # noqa: S603 -- local bash on the action's own script, shimmed python
            [str(bash), "--noprofile", "--norc", "-eo", "pipefail", "-c", render_expressions(script, inputs)],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        check(not marker.exists(), "injected shell command ran: marker file was created")
        check(proc.returncode == 0, f"scan step script failed: {proc.stderr}")
        check("${{" not in script, "scan step run: script must not interpolate ${{ }} expressions")
        argv = json.loads(argv_log.read_text())
        check(
            argv
            == [
                str(SCAN_PY),
                "--url",
                payload,
                "--fail-on",
                inputs["fail-on"],
                "--timeout-seconds",
                inputs["timeout-seconds"],
            ],
            f"inputs must reach scan.py verbatim as single arguments, got {argv}",
        )


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


def test_timeout_seconds_input_declared() -> None:
    """action.yml declares `timeout-seconds` with default "60" and passes it via env only."""
    text = ACTION_YML.read_text()
    check(
        re.search(r'^  timeout-seconds:\n(?:    .*\n|      .*\n)*?    default: "60"$', text, re.M)
        is not None,
        'action.yml must declare input timeout-seconds with default "60"',
    )
    env_block, script = scan_step_env_and_script()
    check(
        env_block.get("INPUT_TIMEOUT_SECONDS") == "${{ inputs.timeout-seconds }}",
        "timeout-seconds must go via env",
    )
    check('--timeout-seconds "$INPUT_TIMEOUT_SECONDS"' in script, "scan step must pass --timeout-seconds")


def test_timeout_seconds_validation() -> None:
    """Bounds are 5..600 (inclusive), integers only; a bad value is a usage error (exit 2)
    before any network access, and the default is 60."""
    check(scan._parse_args(["--url", "http://x"]).timeout_seconds == 60, "default timeout must be 60")
    for ok in ("5", "600", " 30 "):
        check(scan._timeout_seconds(ok) == int(ok), f"{ok!r} must be accepted")
    for bad in ("4", "601", "0", "-1", "abc", "", "1.5", "60s"):
        proc = subprocess.run(  # noqa: S603 -- fixed, locally-built argv; no shell
            [sys.executable, str(SCAN_PY), "--url", "http://127.0.0.1:1/mcp", "--timeout-seconds", bad],
            capture_output=True,
            text=True,
            timeout=30,
        )
        check(
            proc.returncode == 2,
            f"timeout-seconds={bad!r}: expected usage error exit 2, got {proc.returncode}",
        )
        check(
            "timeout-seconds" in proc.stderr,
            f"timeout-seconds={bad!r}: error must name the input: {proc.stderr}",
        )


class _PatchedProbe:
    """Replaces `scan.probe_mcp_endpoint` with a fake coroutine for the duration of a `with`."""

    def __init__(self, fake: Any) -> None:
        self.fake = fake

    def __enter__(self) -> None:
        self.original = vars(scan)["probe_mcp_endpoint"]
        vars(scan)["probe_mcp_endpoint"] = self.fake

    def __exit__(self, *exc: object) -> None:
        vars(scan)["probe_mcp_endpoint"] = self.original


def test_timeout_with_sleeping_fake_probe() -> None:
    """A probe that never finishes (patched; no network) is cut off at timeout-seconds: status
    `error`, a clear summary, exit 1 even with fail-on=none, and outputs still written."""
    cancelled: list[bool] = []

    async def sleeping_probe(url: str, **_kwargs: Any) -> McpProbeResult:
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
        raise AssertionError("unreachable")

    with _PatchedProbe(sleeping_probe):
        result, timed_out = scan._run_bounded(
            "https://slow.invalid/mcp", allow_private=False, timeout_seconds=0.2
        )
        check(timed_out and result.status == "error", f"expected timed-out error result, got {result}")
        check(cancelled == [True], "the probe task must be cancelled on timeout")

        with tempfile.TemporaryDirectory() as tmp:
            summary_path = Path(tmp) / "summary.md"
            output_path = Path(tmp) / "output.txt"
            saved = {k: os.environ.get(k) for k in ("GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT")}
            os.environ["GITHUB_STEP_SUMMARY"] = str(summary_path)
            os.environ["GITHUB_OUTPUT"] = str(output_path)
            try:
                start = time.monotonic()
                code, timed_out = scan.run(
                    ["--url", "https://slow.invalid/mcp", "--fail-on", "none", "--timeout-seconds", "5"]
                )
                elapsed = time.monotonic() - start
            finally:
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            summary = summary_path.read_text()
            outputs = output_path.read_text()
        check(timed_out, "run() must report the timeout")
        check(code == 1, f"timed-out scan must fail even with fail-on=none, got {code}")
        check(4.5 <= elapsed < 15, f"expected to stop at ~5 s, took {elapsed:.1f} s")
        check("Status: **error**" in summary, "expected error status in summary")
        check("timed out after 5 s" in summary, f"expected a clear timeout message, got: {summary}")
        check(
            "score=\n" in outputs and "findings-json=[]\n" in outputs,
            f"outputs must still be written: {outputs!r}",
        )


def test_fast_fake_probe_is_not_affected_by_timeout() -> None:
    async def fast_probe(url: str, **_kwargs: Any) -> McpProbeResult:
        return McpProbeResult(url=url, status="ok", summary="fine", score=100)

    with _PatchedProbe(fast_probe):
        result, timed_out = scan._run_bounded(
            "https://fast.invalid/mcp", allow_private=False, timeout_seconds=5
        )
    check(not timed_out and result.status == "ok", f"fast probe must pass through untouched, got {result}")


def test_timeout_against_hanging_local_server() -> None:
    """End to end via the real probe: a 127.0.0.1 socket that accepts connections (kernel backlog)
    but never answers. The probe's own per-request timeouts add up to more than 5 s, so the overall
    bound is what ends the process."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)
        port = sock.getsockname()[1]
        start = time.monotonic()
        code, summary, outputs = run_scan(
            f"http://127.0.0.1:{port}/mcp", "none", extra_args=("--timeout-seconds", "5")
        )
        elapsed = time.monotonic() - start
    check(code == 1, f"hanging target must fail with fail-on=none, got {code}")
    check("timed out after 5 s" in summary, f"expected timeout summary, got: {summary}")
    check(outputs.get("score") == "", f"expected empty score, got {outputs.get('score')!r}")
    check(elapsed < 20, f"expected exit shortly after 5 s, took {elapsed:.1f} s")


def main() -> int:
    test_scan_step_does_not_execute_shell_in_inputs()
    test_warn_only_target()
    test_critical_target()
    test_unreachable_target_always_fails()
    test_private_target_without_allow_private_is_skipped()
    test_timeout_seconds_input_declared()
    test_timeout_seconds_validation()
    test_timeout_with_sleeping_fake_probe()
    test_fast_fake_probe_is_not_affected_by_timeout()
    test_timeout_against_hanging_local_server()
    print("all integrations/github-action tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
