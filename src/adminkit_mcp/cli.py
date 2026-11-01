"""`adminkit-mcp` CLI: runs the MCP server (stdio by default, or streamable HTTP), or runs
a one-shot `check_mcp_endpoint` probe for scripts/CI (used by the GitHub Action)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import replace

from adminkit_mcp.client import AdminKitClient
from adminkit_mcp.config import Settings
from adminkit_mcp.probe.mcp_probe import probe_mcp_endpoint
from adminkit_mcp.server import build_server


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="adminkit-mcp", description="AdminKit public MCP server")
    parser.add_argument(
        "--http",
        metavar="[HOST]:PORT",
        help="serve streamable HTTP on this host:port instead of stdio, e.g. --http :8080",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="allow check_mcp_endpoint to probe loopback/private targets (CI use only)",
    )
    subparsers = parser.add_subparsers(dest="command")

    probe_parser = subparsers.add_parser(
        "probe", help="run the MCP endpoint probe once and print JSON (no server, used by CI)"
    )
    probe_parser.add_argument("url", help="MCP endpoint URL to probe")
    probe_parser.add_argument("--allow-private", action="store_true", dest="probe_allow_private")
    probe_parser.add_argument("--timeout", type=float, default=8.0)

    return parser


def _parse_http_target(value: str) -> tuple[str, int]:
    host, _, port_s = value.rpartition(":")
    return (host or "127.0.0.1", int(port_s))


async def _run_probe(url: str, *, allow_private: bool, timeout: float) -> int:
    result = await probe_mcp_endpoint(url, allow_private=allow_private, timeout=timeout)
    print(json.dumps(result.to_dict(), indent=2))  # noqa: T201 -- this is the command's output
    return 0 if result.status != "error" else 1


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    if args.command == "probe":
        return asyncio.run(
            _run_probe(args.url, allow_private=args.probe_allow_private, timeout=args.timeout)
        )

    settings = Settings.from_env()
    if args.allow_private:
        settings = replace(settings, allow_private_targets=True)

    async def _serve() -> None:
        async with AdminKitClient.from_settings(settings) as client:
            mcp = build_server(client, settings=settings)
            if args.http:
                host, port = _parse_http_target(args.http)
                mcp.settings.host = host
                mcp.settings.port = port
                await mcp.run_streamable_http_async()
            else:
                await mcp.run_stdio_async()

    asyncio.run(_serve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
