#!/usr/bin/env bash
# Runs test_action.py against scan.py, in a throwaway venv with `adminkit-mcp` installed
# editable from this repo's mcp/. No network access beyond localhost, no GitHub-hosted runner.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../.." && pwd)
mcp_dir="$repo_root"

venv=$(mktemp -d -t adminkit-gh-action-test.XXXXXX)
trap 'rm -rf "$venv"' EXIT

python3 -m venv "$venv"
"$venv/bin/pip" install -q --upgrade pip
"$venv/bin/pip" install -q -e "$mcp_dir[dev]"

"$venv/bin/python" "$script_dir/test_action.py"
