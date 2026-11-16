# Changelog

## 0.2.0 - unreleased

15 tools (was 13).

### Added

- `list_assets`: read-only list of the assets in your AdminKit organization (`GET /v1/assets`) with
  `id`, `kind`, `value`, `verified`, `last_checked_at` and the stored monitored `status`
  (`{passing, reason, checked_at}`, or `null` if not checked yet), plus the ids of failing and
  not-yet-checked assets. Envelope status is `warn` when any asset is failing.
- `get_asset(asset_id)`: the same fields for one asset (`GET /v1/assets/{asset_id}`). The id is
  validated locally and a malformed id is refused without a request; an unknown id and another
  organization's id both answer "asset not found in your organization".
- Both new tools need an AdminKit API key (`ADMINKIT_API_KEY`). Without one they answer "API key
  required" and send no request. They never create, verify, check or delete anything, and never
  return an asset's `verification_token` or the API key.
- `--http` (streamable HTTP) is now a hardened anonymous endpoint: it never forwards
  `ADMINKIT_API_KEY` from the environment, always refuses private/loopback targets, limits
  requests per client IP (`ADMINKIT_MCP_HOSTED_RATE_LIMIT_PER_MINUTE`, default 30,
  `ADMINKIT_MCP_HOSTED_RATE_LIMIT_BURST`, default 5) and caps the request body
  (`ADMINKIT_MCP_HOSTED_MAX_BODY_BYTES`, default 65536). The account tools therefore always
  answer "API key required" over `--http`.

### Changed

- Every tool result's `report_url` carries `utm_source=mcp`; when the API returns no shareable
  report link, the tool links to its own adminkit.net tool page.
- `check_mail_auth`: DMARC verdict reads the API's `policy` field (`tags.p` only as a fallback),
  matching the AdminKit website. The site-function fallback now treats multiple SPF records, SPF
  permerror and `+all` as fail, and `~all`, `?all` and a missing `all` as warn, with a hint to
  merge multiple SPF records.
- The HTTP `User-Agent` and the probe's MCP `clientInfo.version` follow the package version.
- Minimum `mcp` SDK raised from 1.2 to 1.29 (`mcp>=1.29,<2`). Older releases either fail to import
  with current pydantic or lack the `max_request_body_size` setting used by `--http`.

### Fixed

- `initialize` now reports `serverInfo.version` as the adminkit-mcp version. Before, it reported the
  installed `mcp` SDK version.

## 0.1.0 - 2026-11-01

- First public release: 8 AdminKit check tools, 5 offline utility tools, stdio and streamable
  HTTP transports, `adminkit-mcp probe`, and the MCP endpoint scan GitHub Action.
