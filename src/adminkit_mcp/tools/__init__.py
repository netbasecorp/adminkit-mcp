"""The 8 AdminKit MCP tools (spec section 18.8): thin clients over the live Check API
(`/v1/check/*`). `dnsbl` is the one check kind the API has not shipped yet. `check_ip`,
`dns_lookup`, and `check_mail_auth` additionally fall back to the live site functions if
the Check API is ever unreachable (404/501) — a resilience path, not the expected path.

Plus 5 "offline utility" tools (spec section 18.1/18.7 — `subnet_calc`, `ip_info`,
`ipv6_info`, `mac_vendor`, `user_agent`): thin clients over the live, no-auth
`/v1/tools/*` endpoints, which do pure local computation (ipaddress math, bundled OUI/UA
data) with no third-party host ever contacted and no site-function fallback. These are an
explicit, reversible enhancement on top of the original 8 and are kept in their own
modules so they can be dropped without touching the check tools."""

from __future__ import annotations
