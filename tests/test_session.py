from pathlib import Path

import pytest

from mcp_tool_pinning.connect import connect
from mcp_tool_pinning.demo_server import MARKER, THRESHOLD, make_server
from mcp_tool_pinning.session import (
    ApprovalMismatchError,
    PinnedClientSession,
    ToolWithheldError,
)
from mcp_tool_pinning.store import PinStore

pytestmark = pytest.mark.anyio


async def _approve_all(session: PinnedClientSession) -> None:
    await session.list_tools()
    for item in session.pending():
        assert item.digest is not None
        session.approve(item.name, item.digest)


async def test_new_tools_are_withheld_until_approved(tmp_path: Path) -> None:
    async with connect(make_server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        listing = await s.list_tools()
        assert listing.tools == []
        assert {p.reason for p in s.pending()} == {"new"}
        with pytest.raises(ToolWithheldError):
            await s.call_tool("format_text", {"text": "x"})
        await _approve_all(s)
        listing = await s.list_tools()
        assert sorted(t.name for t in listing.tools) == ["format_text", "summarize"]


async def test_switch_after_calls_is_withheld_refused_and_diffed(
    tmp_path: Path,
) -> None:
    async with connect(make_server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_all(s)
        await s.list_tools()
        for _ in range(THRESHOLD):
            await s.call_tool("format_text", {"text": "a  b"})
        listing = await s.list_tools()
        assert [t.name for t in listing.tools] == ["format_text"]
        [held] = s.pending()
        assert (held.name, held.reason) == ("summarize", "changed")
        assert MARKER in held.diff
        with pytest.raises(ToolWithheldError):
            await s.call_tool("summarize", {"text": "x"})


async def test_approval_binds_to_reviewed_digest(tmp_path: Path) -> None:
    async with connect(make_server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await s.list_tools()
        with pytest.raises(ApprovalMismatchError):
            s.approve("summarize", "sha256:" + "0" * 64)
        [item] = [p for p in s.pending() if p.name == "summarize"]
        assert item.digest is not None
        s.approve("summarize", item.digest)
        listing = await s.list_tools()
        assert "summarize" in [t.name for t in listing.tools]


async def test_reconnect_with_matching_pins_needs_no_approval(tmp_path: Path) -> None:
    pins = tmp_path / "p.json"
    server = make_server()
    async with connect(server, PinnedClientSession, store=PinStore(pins)) as s:
        await _approve_all(s)
    async with connect(server, PinnedClientSession, store=PinStore(pins)) as s:
        listing = await s.list_tools()
        assert sorted(t.name for t in listing.tools) == ["format_text", "summarize"]
        assert s.pending() == []
        await s.call_tool("summarize", {"text": "x"})
