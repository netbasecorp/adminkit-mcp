# Changelog

## Unreleased

18 tools (was 15 in 0.2.0). Not published yet; the package version stays 0.2.0 until a release.

### Added

- Unreleased: added `ip_in_cidr`, `ipv6_eui64`, `spf_validate` — three more offline utility tools
  wrapping the live, no-auth `/v1/tools/*` endpoints:
  - `ip_in_cidr(ip, cidr)` (`GET /v1/tools/ip-in-cidr`): whether an IPv4/IPv6 address is inside a
    CIDR range (`contains`, normalized `network`). Links to https://adminkit.net/tools/ip-in-cidr/.
  - `ipv6_eui64(prefix, mac)` (`GET /v1/tools/ipv6-eui64`): the modified EUI-64 interface id of a
    MAC-48 and the full IPv6 address it forms in a /64-or-shorter prefix. Links to
    https://adminkit.net/tools/ipv6-info/ (the site's IPv6 tool, which also derives EUI-64 ids).
  - `spf_validate(record)` (`GET /v1/tools/spf-validate`): static SPF record syntax check, no DNS
    lookups; envelope status `ok` / `warn` / `fail` from the API's `valid` /
    `valid_with_warnings` / `invalid` verdict, `fix_hint` = the worst finding's message. Links to
    https://adminkit.net/tools/spf-validate/.
- All three refuse empty or oversized arguments locally, without a request, and report an API 422
  as an explicit `error` envelope and an API 429 as the standard "rate limited ... retry in N s"
  result (no automatic retry), like the other offline tools.

### Fixed

- `explain_report` validates `report_token` locally (non-empty, at most 128 characters, no `..`, `/`, `?`, `#`, `%`, `\`, whitespace or control characters) and refuses a bad token without any request; a valid token is percent-encoded, so a token like `../../v1/account/keys` can no longer send the configured API key to another API route.

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
- `list_assets` / `get_asset`: each asset now includes `value_valid` (from the API's
  `AssetResponse.value_valid`; `true` when an older API omits it). `false` means the stored
  value does not parse for its kind (a legacy row) and the asset must be removed and added
  again; the result is then `warn` with that hint.
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

- When the AdminKit API answers 429, every tool now returns an `error` result that says it was
  rate limited and, when the API said how long, "retry in N s" (`result.retry_after_seconds`,
  else `null`), instead of a generic tool error. The wait comes from the `Retry-After` header
  (seconds or HTTP-date), then the problem body's `retry_after_seconds`, then `RateLimit-Reset`;
  it is never guessed, and the server never sleeps or retries on its own. `--http` now also sends
  `Retry-After` (whole seconds, at least 1) and `retry_after_seconds` on its own per-client 429.
- `initialize` now reports `serverInfo.version` as the adminkit-mcp version. Before, it reported the
  installed `mcp` SDK version.

## 0.1.0 - 2026-11-01

- First public release: 8 AdminKit check tools, 5 offline utility tools, stdio and streamable
  HTTP transports, `adminkit-mcp probe`, and the MCP endpoint scan GitHub Action.
