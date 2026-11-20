# AdminKit MCP server + MCP endpoint scan Action

<!-- mcp-name: io.github.netbasecorp/adminkit-mcp -->

Open-source [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI agents
(Claude, ChatGPT, Cursor, VS Code, any MCP client) real network, DNS and mail checks from
[AdminKit](https://adminkit.net), plus a read-only GitHub Action that scans your own MCP endpoint
for anonymous-access exposure.

- **Website:** <https://adminkit.net> · **MCP docs:** <https://adminkit.net/developers/mcp/>
- **Licence:** MIT · **Maintainer:** Netbase JSC

Every tool returns real data from the live AdminKit Check API (`https://api.adminkit.net`) or
pure local computation. When a check cannot be reached, the tool says so; it never invents a result.

## Tools

| Tool | What it does |
| --- | --- |
| `check_ip` | Your own public IP, ASN and a CGNAT hint (only the caller's own IP). |
| `dns_lookup` | A / AAAA / MX / TXT / NS / CAA / PTR / SOA / CNAME lookup. |
| `check_mail_auth` | SPF and DMARC posture for a domain. |
| `check_domain` | Aggregate domain health: whois, TLS certificate, HTTP security headers. |
| `check_owned_ports` | Port exposure check for targets you have verified you own. |
| `check_mcp_endpoint` | Exposure probe for an MCP server (`initialize` + `tools/list` only). |
| `explain_report` | Plain-language AI explanation of a shared AdminKit report (needs an API key). |
| `get_radar` | Aggregated honeypot / telemetry trends from AdminKit Radar. |
| `list_assets` | Your AdminKit assets and their monitored status (read-only, needs an API key). |
| `get_asset` | One of your AdminKit assets and its monitored status (read-only, needs an API key). |
| `subnet_calc`, `ip_info`, `ipv6_info`, `mac_vendor`, `user_agent` | Offline utilities: subnet math, address info, OUI vendor lookup, User-Agent parsing. |

15 tools in total.

### Account tools: `list_assets` and `get_asset`

These two tools read your own AdminKit account, so they need an AdminKit API key in
`ADMINKIT_API_KEY`. Without a key they answer "API key required" and send no request. They only
read: they never create, verify, check or delete an asset, and never return an asset's
verification token or your API key.

- `list_assets` lists your assets with `id`, `kind`, `value`, `verified`, `value_valid`,
  `last_checked_at` and the stored monitored `status` (`{passing, reason, checked_at}`, or `null`
  if not checked yet), plus the ids of failing and not-yet-checked assets. Ask: "which of my assets are failing?"
- `get_asset(asset_id)` returns the same fields for one asset. A malformed id is refused without a
  request; an unknown id and another organization's id both answer "asset not found in your
  organization".

## Install

Python 3.12+.

```bash
pip install adminkit-mcp
```

or run it without installing, with [uv](https://docs.astral.sh/uv/):

```bash
uvx adminkit-mcp
```

### Claude Desktop / Claude Code / Cursor (stdio)

```json
{
  "mcpServers": {
    "adminkit": {
      "command": "uvx",
      "args": ["adminkit-mcp"]
    }
  }
}
```

### Streamable HTTP

```bash
adminkit-mcp --http 127.0.0.1:8080
```

`--http` serves an anonymous endpoint: it never forwards `ADMINKIT_API_KEY`, refuses
private/loopback targets, limits requests per client IP and caps the request size. The account
tools therefore always answer "API key required" over `--http`; use stdio for them.

### Configuration (environment only)

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADMINKIT_API_BASE` | `https://api.adminkit.net` | Check API base URL. |
| `ADMINKIT_SITE_BASE` | `https://adminkit.net` | Site base URL (fallback for some checks). |
| `ADMINKIT_API_KEY` | unset | Optional AdminKit API key (`explain_report`, `list_assets`, `get_asset`, higher limits). Never logged. |
| `ADMINKIT_MCP_TIMEOUT_SECONDS` | `10` | Per-request timeout. |
| `ADMINKIT_MCP_RATE_LIMIT_PER_SECOND` | `5` | Client-side rate limit. |
| `ADMINKIT_MCP_ALLOW_PRIVATE` | unset (off) | `1`, `true` or `yes`: `check_mcp_endpoint` may probe private/loopback targets by default (CI fixtures only; same as `--allow-private`). Ignored over `--http`. |
| `ADMINKIT_MCP_HOSTED_RATE_LIMIT_PER_MINUTE` | `30` | `--http` only: requests per minute per client IP. |
| `ADMINKIT_MCP_HOSTED_RATE_LIMIT_BURST` | `5` | `--http` only: burst allowance per client IP. |
| `ADMINKIT_MCP_HOSTED_MAX_BODY_BYTES` | `65536` | `--http` only: maximum request body size. |

## GitHub Action: scan your MCP endpoint

Checks one MCP endpoint for: `initialize` accepted without credentials, tool list readable
anonymously, tool names that look like shell/file/network access, and no TLS. It only sends
`initialize` and `tools/list` and never calls `tools/call`, so it is safe against a live server.
Outputs a 0-100 exposure score, a job summary, and `score` / `findings-json` outputs.

```yaml
- name: Scan our MCP endpoint
  id: scan
  uses: netbasecorp/adminkit-mcp@v0.1.0
  with:
    url: https://mcp.example.com/mcp
    fail-on: critical # none | warning | critical
- run: echo "score ${{ steps.scan.outputs.score }}"
```

| Input | Default | Description |
| --- | --- | --- |
| `url` | (required) | MCP endpoint URL to scan. |
| `fail-on` | `critical` | `none`, `warning` (any finding) or `critical` (high/critical finding). |
| `api-key` | `""` | Reserved for sending results to the AdminKit dashboard; never sent to the target. |
| `allow-private` | `false` | Allow a private/loopback target (only for CI fixtures you started yourself). |

An unreachable target always fails the step. A private target refused with
`allow-private: false` is reported as `skipped`. Full workflow:
[`examples/scan-mcp-endpoint.yml`](examples/scan-mcp-endpoint.yml).

The same probe runs from the command line:

```bash
adminkit-mcp probe https://mcp.example.com/mcp
```

Scan only endpoints you own or are authorised to test.

## Development

```bash
pip install -e ".[dev]"
pytest            # every test runs against local fakes on 127.0.0.1, no network
ruff check . && ruff format --check . && mypy
bash action/test/test_action.sh
```

## Licence

MIT, see [LICENSE](LICENSE). The AdminKit website, API and platform are separate proprietary
services operated by Netbase JSC; this repository contains only the open-source client.
