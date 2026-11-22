#!/usr/bin/env python3
"""Exercises `scan.py` (the action's entrypoint) against a local fake MCP server on
127.0.0.1 for every `fail-on` value. No real-host network access, no GitHub-hosted runner.

Run via `test_action.sh`, which sets up a venv with `adminkit-mcp` installed and points
PYTHONPATH at `mcp/tests` so this reuses `fakes.fake_mcp_server` (do not duplicate it).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from fakes.fake_mcp_server import FakeMcpConfig, _make_server  # noqa: E402

ACTION_DIR = Path(__file__).resolve().parents[1]
SCAN_PY = ACTION_DIR / "scan.py"
ACTION_YML = ACTION_DIR / "action.yml"


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
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
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
            argv == [str(SCAN_PY), "--url", payload, "--fail-on", inputs["fail-on"]],
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


def main() -> int:
    test_scan_step_does_not_execute_shell_in_inputs()
    test_warn_only_target()
    test_critical_target()
    test_unreachable_target_always_fails()
    test_private_target_without_allow_private_is_skipped()
    print("all integrations/github-action tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
