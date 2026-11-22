#!/usr/bin/env python3
"""GitHub Action entrypoint for the AdminKit MCP scan action.

This file holds no scanning logic of its own: it calls
`adminkit_mcp.probe.mcp_probe.probe_mcp_endpoint` (the same anonymous-only,
read-only probe shipped in `mcp/`, pinned to this action's own git ref), then
formats the result as a GitHub Actions job summary + outputs and exits
non-zero according to `--fail-on`.

The whole probe runs under an overall `--timeout-seconds` bound (default 60, 5..600): a
slow or hostile endpoint must not be able to hold a CI job until GitHub's 6 h job limit.
A timed-out scan is reported as status `error` and, like any other scan that could not
complete, fails the step regardless of `--fail-on`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from adminkit_mcp.probe.mcp_probe import McpProbeResult, probe_mcp_endpoint

_FAIL_ON_CHOICES = ("none", "warning", "critical")
TIMEOUT_DEFAULT_SECONDS = 60
TIMEOUT_MIN_SECONDS = 5
TIMEOUT_MAX_SECONDS = 600


def _timeout_seconds(value: str) -> int:
    try:
        seconds = int(value.strip())
    except ValueError:
        raise argparse.ArgumentTypeError(f"timeout-seconds must be an integer, got {value!r}") from None
    if not TIMEOUT_MIN_SECONDS <= seconds <= TIMEOUT_MAX_SECONDS:
        raise argparse.ArgumentTypeError(
            f"timeout-seconds must be between {TIMEOUT_MIN_SECONDS} and {TIMEOUT_MAX_SECONDS}, got {seconds}"
        )
    return seconds


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan an MCP endpoint for anonymous-access exposure.")
    parser.add_argument("--url", required=True, help="MCP endpoint URL to scan")
    parser.add_argument("--fail-on", choices=_FAIL_ON_CHOICES, default="critical")
    parser.add_argument("--allow-private", action="store_true")
    parser.add_argument(
        "--timeout-seconds",
        type=_timeout_seconds,
        default=TIMEOUT_DEFAULT_SECONDS,
        help=(
            f"overall scan time bound in seconds ({TIMEOUT_MIN_SECONDS}..{TIMEOUT_MAX_SECONDS}, "
            f"default {TIMEOUT_DEFAULT_SECONDS})"
        ),
    )
    return parser.parse_args(argv)


def _should_fail(result: McpProbeResult, fail_on: str) -> bool:
    """Maps `fail-on` onto the probe's own ok/warn/fail status (spec §18.8); a scan
    that could not reach the target at all always fails the step, independent of
    `fail-on`, since that is a different signal than "findings below threshold"."""
    if result.status == "error":
        return True
    if fail_on == "none":
        return False
    if fail_on == "warning":
        return result.status in ("warn", "fail")
    return result.status == "fail"  # "critical": any high/critical finding


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _summary_markdown(result: McpProbeResult, *, api_key_configured: bool) -> str:
    lines = [
        "## AdminKit MCP scan",
        "",
        f"- URL: `{result.url}`",
        f"- Status: **{result.status}**",
        f"- Score: {result.score if result.score is not None else 'n/a'}",
        f"- AdminKit API key configured: {api_key_configured} "
        "(reserved for future dashboard submission; not used by this scan)",
        f"- {result.summary}",
        "",
    ]
    if result.findings:
        lines.append("| Finding | Severity | Evidence | Fix |")
        lines.append("| --- | --- | --- | --- |")
        for finding in result.findings:
            lines.append(
                f"| {_md_escape(finding.title)} | {finding.severity} "
                f"| {_md_escape(finding.detail)} | {_md_escape(finding.fix_hint)} |"
            )
    else:
        lines.append("No findings.")
    return "\n".join(lines) + "\n"


def _write_github_output(path: str, result: McpProbeResult, findings_json: str) -> None:
    score = "" if result.score is None else str(result.score)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"score={score}\n")
        fh.write(f"findings-json={findings_json}\n")


async def _run(url: str, *, allow_private: bool, timeout_seconds: float) -> tuple[McpProbeResult, bool]:
    """Returns (result, timed_out). On timeout the probe task is cancelled and an `error`
    result is synthesised, so the summary/outputs are still written."""
    try:
        result = await asyncio.wait_for(probe_mcp_endpoint(url, allow_private=allow_private), timeout_seconds)
    except TimeoutError:
        message = (
            f"Scan timed out after {timeout_seconds:g} s (timeout-seconds) before the endpoint "
            "finished answering; the step fails regardless of fail-on."
        )
        return McpProbeResult(url=url, status="error", summary=message, score=None), True
    return result, False


def _run_bounded(url: str, *, allow_private: bool, timeout_seconds: float) -> tuple[McpProbeResult, bool]:
    # Not asyncio.run(): it joins the default executor on exit, so a resolver thread stuck in
    # getaddrinfo would keep the step alive past the timeout. loop.close() does not wait for it.
    loop = asyncio.new_event_loop()
    try:
        outcome = loop.run_until_complete(
            _run(url, allow_private=allow_private, timeout_seconds=timeout_seconds)
        )
        loop.run_until_complete(loop.shutdown_asyncgens())
        return outcome
    finally:
        loop.close()


def run(argv: list[str] | None = None) -> tuple[int, bool]:
    """Runs the scan; returns (exit code, timed_out)."""
    args = _parse_args(argv)
    result, timed_out = _run_bounded(
        args.url, allow_private=args.allow_private, timeout_seconds=args.timeout_seconds
    )

    findings_json = json.dumps([f.to_dict() for f in result.findings])
    summary = _summary_markdown(result, api_key_configured=bool(os.environ.get("ADMINKIT_API_KEY")))
    print(summary)  # noqa: T201 -- also visible as plain step output, not just the job summary

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(summary)

    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        _write_github_output(output_path, result, findings_json)

    return (1 if _should_fail(result, args.fail_on) else 0), timed_out


def main(argv: list[str] | None = None) -> int:
    return run(argv)[0]


if __name__ == "__main__":
    code, timed_out = run()
    if timed_out:
        # A cancelled probe may leave a non-daemon resolver thread blocked in getaddrinfo, which
        # the interpreter would join at exit. Summary and outputs are already written and closed.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)
    sys.exit(code)
