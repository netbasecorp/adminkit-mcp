"""The `adminkit-mcp probe` subcommand (no server, used directly by the GitHub Action)."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from adminkit_mcp.cli import main
from fakes.fake_mcp_server import FakeMcpConfig


def test_probe_subcommand_prints_json_and_exits_zero_on_clean_result(
    fake_mcp_server: Callable[[FakeMcpConfig], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = FakeMcpConfig(require_auth=True, tool_names=("search",))
    base_url = fake_mcp_server(config)
    exit_code = main(["probe", base_url + "/mcp", "--allow-private"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert exit_code == 0
    assert payload["status"] in ("ok", "warn")
    assert payload["url"] == base_url + "/mcp"


def test_probe_subcommand_refuses_private_target_without_flag(
    fake_mcp_server: Callable[[FakeMcpConfig], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = FakeMcpConfig(require_auth=False, tool_names=())
    base_url = fake_mcp_server(config)
    exit_code = main(["probe", base_url + "/mcp"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0  # skipped is not an operational error
    assert payload["status"] == "skipped"


def test_probe_subcommand_exits_nonzero_on_unreachable_target(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["probe", "http://127.0.0.1:1/mcp", "--allow-private", "--timeout", "1"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["status"] == "error"
