"""The release reads its version from several files; they must agree (no network).

In this monorepo `server.json` lives in `docs/handoff/public-mcp-release/`; in the exported
public tree (`export.sh`) it sits next to `pyproject.toml` at the root. If neither exists the
check is skipped.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

import adminkit_mcp
from adminkit_mcp.client import USER_AGENT

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_SERVER_JSON_CANDIDATES = (
    _PACKAGE_ROOT / "server.json",
    _PACKAGE_ROOT.parent / "docs" / "handoff" / "public-mcp-release" / "server.json",
)


_PUBLIC_PYPROJECT = _PACKAGE_ROOT.parent / "docs" / "handoff" / "public-mcp-release" / "pyproject.public.toml"


def _pyproject_version(path: Path = _PACKAGE_ROOT / "pyproject.toml") -> str:
    with path.open("rb") as fh:
        return str(tomllib.load(fh)["project"]["version"])


def test_package_version_matches_pyproject() -> None:
    assert adminkit_mcp.__version__ == _pyproject_version()
    assert f"adminkit-mcp/{adminkit_mcp.__version__}" == USER_AGENT


def test_version_consistent() -> None:
    server_json = next((p for p in _SERVER_JSON_CANDIDATES if p.is_file()), None)
    if server_json is None:
        pytest.skip("server.json is not shipped next to this package")
    data = json.loads(server_json.read_text(encoding="utf-8"))
    assert data["version"] == adminkit_mcp.__version__
    pypi = [p for p in data["packages"] if p["registryType"] == "pypi" and p["identifier"] == "adminkit-mcp"]
    assert pypi, "server.json has no adminkit-mcp PyPI package entry"
    assert all(p["version"] == adminkit_mcp.__version__ for p in pypi)
    if _PUBLIC_PYPROJECT.is_file():  # monorepo only; the export renames it to pyproject.toml
        assert _pyproject_version(_PUBLIC_PYPROJECT) == adminkit_mcp.__version__
