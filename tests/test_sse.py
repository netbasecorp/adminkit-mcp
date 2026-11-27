from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from adminkit_mcp.probe.sse import SseEvent, StreamLimitError, iter_capped_lines, iter_sse_events


async def _lines(*values: str) -> AsyncIterator[str]:
    for value in values:
        yield value


async def test_parses_a_single_event_with_event_and_data() -> None:
    events = [e async for e in iter_sse_events(_lines("event: endpoint", "data: /messages?session_id=1", ""))]
    assert events == [SseEvent(event="endpoint", data="/messages?session_id=1")]


async def test_defaults_event_type_to_message() -> None:
    events = [e async for e in iter_sse_events(_lines('data: {"id": 1}', ""))]
    assert events == [SseEvent(event="message", data='{"id": 1}')]


async def test_joins_multiple_data_lines_with_newline() -> None:
    events = [e async for e in iter_sse_events(_lines("data: line1", "data: line2", ""))]
    assert events == [SseEvent(event="message", data="line1\nline2")]


async def test_ignores_comment_lines() -> None:
    events = [e async for e in iter_sse_events(_lines(": keep-alive", "data: hello", ""))]
    assert events == [SseEvent(event="message", data="hello")]


async def test_parses_multiple_events_in_sequence() -> None:
    events = [
        e
        async for e in iter_sse_events(
            _lines("event: endpoint", "data: /messages", "", "event: message", "data: {}", "")
        )
    ]
    assert [e.event for e in events] == ["endpoint", "message"]


async def _chunks(*values: bytes) -> AsyncIterator[bytes]:
    for value in values:
        yield value


async def test_capped_lines_split_across_chunks_and_strip_cr() -> None:
    lines = iter_capped_lines(
        _chunks(b"event: end", b"point\r\ndata: /m\n", b"\n"), max_line_bytes=64, max_total_bytes=64
    )
    assert [line async for line in lines] == ["event: endpoint", "data: /m", ""]


async def test_capped_lines_refuse_an_unterminated_long_line() -> None:
    lines = iter_capped_lines(_chunks(b"data: ", b"x" * 100), max_line_bytes=64, max_total_bytes=1024)
    with pytest.raises(StreamLimitError) as exc:
        _ = [line async for line in lines]
    assert exc.value.limit == "sse_event_bytes"


async def test_capped_lines_refuse_a_long_stream() -> None:
    lines = iter_capped_lines(_chunks(*[b": ping\n"] * 100), max_line_bytes=64, max_total_bytes=256)
    with pytest.raises(StreamLimitError) as exc:
        _ = [line async for line in lines]
    assert exc.value.limit == "stream_bytes"


async def test_event_cap_counts_joined_data_lines() -> None:
    events = iter_sse_events(_lines(*["data: 0123456789"] * 10, ""), max_event_bytes=50)
    with pytest.raises(StreamLimitError) as exc:
        _ = [e async for e in events]
    assert exc.value.limit == "sse_event_bytes"
