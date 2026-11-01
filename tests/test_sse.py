from __future__ import annotations

from collections.abc import AsyncIterator

from adminkit_mcp.probe.sse import SseEvent, iter_sse_events


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
