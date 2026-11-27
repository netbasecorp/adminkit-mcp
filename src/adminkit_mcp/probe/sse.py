"""Minimal Server-Sent Events line parser for the legacy MCP HTTP+SSE transport.

Only reads `event:`/`data:` fields; this is a probe, not a general SSE client. See
`mcp_probe.py` for how the legacy transport (GET an SSE stream that announces a POST
"message" endpoint, read JSON-RPC replies back over the same stream) is driven.

Everything read from the probed server is capped: `iter_capped_lines` bounds each line and the
whole stream, `iter_sse_events(max_event_bytes=...)` bounds each event, so an endless or
oversize stream raises `StreamLimitError` instead of growing memory.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator
from dataclasses import dataclass


class StreamLimitError(Exception):
    """A byte cap was reached while reading a stream; `limit` names which one."""

    def __init__(self, limit: str, cap: int) -> None:
        super().__init__(f"{limit} cap of {cap} bytes reached")
        self.limit = limit
        self.cap = cap


@dataclass
class SseEvent:
    event: str = "message"
    data: str = ""


async def iter_capped_lines(
    chunks: AsyncIterator[bytes], *, max_line_bytes: int, max_total_bytes: int
) -> AsyncIterator[str]:
    """Split a byte stream into lines without ever buffering more than the caps allow.

    Lines end at LF (a trailing CR is dropped); a server using bare CR line endings therefore
    produces one long line and hits `max_line_bytes`. Raises `StreamLimitError` with limit
    `sse_event_bytes` (an over-long line) or `stream_bytes`.
    """
    buf = bytearray()
    total = 0
    async for chunk in chunks:
        total += len(chunk)
        if total > max_total_bytes:
            raise StreamLimitError("stream_bytes", max_total_bytes)
        buf += chunk
        while (idx := buf.find(b"\n")) != -1:
            line = bytes(buf[:idx]).rstrip(b"\r")
            del buf[: idx + 1]
            if len(line) > max_line_bytes:
                raise StreamLimitError("sse_event_bytes", max_line_bytes)
            yield line.decode("utf-8", errors="replace")
        if len(buf) > max_line_bytes:
            raise StreamLimitError("sse_event_bytes", max_line_bytes)
    if buf:
        yield bytes(buf).rstrip(b"\r").decode("utf-8", errors="replace")


async def iter_sse_events(
    lines: AsyncIterator[str], *, max_event_bytes: int | None = None
) -> AsyncGenerator[SseEvent]:
    event_type = "message"
    data_lines: list[str] = []
    data_size = 0
    async for raw_line in lines:
        line = raw_line.rstrip("\r\n") if raw_line.endswith(("\r\n", "\n")) else raw_line
        if line == "":
            if data_lines:
                yield SseEvent(event=event_type, data="\n".join(data_lines))
            event_type = "message"
            data_lines = []
            data_size = 0
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
            data_size += len(value.encode()) + 1
            if max_event_bytes is not None and data_size > max_event_bytes:
                raise StreamLimitError("sse_event_bytes", max_event_bytes)
            data_lines.append(value)
