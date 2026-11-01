"""Minimal Server-Sent Events line parser for the legacy MCP HTTP+SSE transport.

Only reads `event:`/`data:` fields; this is a probe, not a general SSE client. See
`mcp_probe.py` for how the legacy transport (GET an SSE stream that announces a POST
"message" endpoint, read JSON-RPC replies back over the same stream) is driven.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass


@dataclass
class SseEvent:
    event: str = "message"
    data: str = ""


async def iter_sse_events(lines: AsyncIterator[str]) -> AsyncIterator[SseEvent]:
    event_type = "message"
    data_lines: list[str] = []
    async for raw_line in lines:
        line = raw_line.rstrip("\r\n") if raw_line.endswith(("\r\n", "\n")) else raw_line
        if line == "":
            if data_lines:
                yield SseEvent(event=event_type, data="\n".join(data_lines))
            event_type = "message"
            data_lines = []
            continue
        if line.startswith(":"):
            continue  # comment / keep-alive
        if ":" in line:
            field_name, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
        else:
            field_name, value = line, ""
        if field_name == "event":
            event_type = value
        elif field_name == "data":
            data_lines.append(value)
