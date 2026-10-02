"""Section 3 rules against a server the tests control directly."""

from pathlib import Path

import pytest
from helpers import Controlled, tool
from mcp import types

from mcp_tool_pinning.connect import connect
from mcp_tool_pinning.session import ApprovalMismatchError, PinnedClientSession, ToolWithheldError
from mcp_tool_pinning.store import PinStore

pytestmark = pytest.mark.anyio


async def _list_all(s: PinnedClientSession) -> list[str]:
    names: list[str] = []
    cursor: str | None = None
    while True:
        params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
        page = await s.list_tools(params=params)
        names += [t.name for t in page.tools]
        cursor = page.next_cursor
        if cursor is None:
            return names


async def _approve_all(s: PinnedClientSession) -> None:
    await _list_all(s)
    for item in s.pending():
        assert item.digest is not None
        s.approve(item.name, item.digest)
    await _list_all(s)


async def test_changed_definition_never_reaches_server_as_a_call(tmp_path: Path) -> None:
    srv = Controlled(pages=[[tool("a")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_all(s)
        srv.pages = [[tool("a", "changed")]]
        assert await _list_all(s) == []
        with pytest.raises(ToolWithheldError):
            await s.call_tool("a", {})
    assert srv.calls["a"] == 0


async def test_approval_of_a_superseded_digest_is_rejected(tmp_path: Path) -> None:
    srv = Controlled(pages=[[tool("a", "first")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _list_all(s)
        [reviewed] = s.pending()
        srv.pages = [[tool("a", "second")]]
        await _list_all(s)
        assert reviewed.digest is not None
        with pytest.raises(ApprovalMismatchError):
            s.approve("a", reviewed.digest)
        [current] = s.pending()
        assert "second" in current.diff
        assert current.digest is not None
        s.approve("a", current.digest)


async def test_change_on_page_two_is_withheld(tmp_path: Path) -> None:
    srv = Controlled(pages=[[tool("a")], [tool("b")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_all(s)
        assert await _list_all(s) == ["a", "b"]
        srv.pages = [[tool("a")], [tool("b", "changed")]]
        assert await _list_all(s) == ["a"]
        with pytest.raises(ToolWithheldError):
            await s.call_tool("b", {})


async def test_new_first_page_clears_approvals_from_the_old_listing(tmp_path: Path) -> None:
    srv = Controlled(pages=[[tool("a")], [tool("b")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_all(s)
        await s.list_tools()  # first page only; page two not re-checked yet
        with pytest.raises(ToolWithheldError):
            await s.call_tool("b", {})
    assert srv.calls["b"] == 0


async def test_tool_removed_from_listing_is_refused(tmp_path: Path) -> None:
    srv = Controlled(pages=[[tool("a"), tool("b")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_all(s)
        srv.pages = [[tool("a")]]
        await _list_all(s)
        assert s.pending() == []
        with pytest.raises(ToolWithheldError):
            await s.call_tool("b", {})


async def test_first_listing_on_a_new_connection_is_checked(tmp_path: Path) -> None:
    pins = tmp_path / "p.json"
    srv = Controlled(pages=[[tool("a")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(pins)) as s:
        await _approve_all(s)
    srv.pages = [[tool("a", "changed while disconnected")]]
    async with connect(srv.server(), PinnedClientSession, store=PinStore(pins)) as s:
        assert await _list_all(s) == []
        assert [p.reason for p in s.pending()] == ["changed"]


async def test_tool_without_digest_cannot_be_approved(tmp_path: Path) -> None:
    big = {"type": "object", "properties": {"n": {"type": "integer", "maximum": 2**60}}}
    srv = Controlled(pages=[[tool("a", schema=big)]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        assert await _list_all(s) == []
        [item] = s.pending()
        assert (item.reason, item.digest) == ("no-digest", None)
        with pytest.raises(ApprovalMismatchError):
            s.approve("a", "sha256:" + "0" * 64)


async def test_duplicate_names_withhold_every_copy(tmp_path: Path) -> None:
    srv = Controlled(pages=[[tool("a")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_all(s)
        srv.pages = [[tool("a"), tool("a", "second copy")]]
        assert await _list_all(s) == []
        assert [p.reason for p in s.pending()] == ["duplicate-name"]
        with pytest.raises(ToolWithheldError):
            await s.call_tool("a", {})


async def test_duplicate_name_across_pages_is_refused(tmp_path: Path) -> None:
    srv = Controlled(pages=[[tool("a")], [tool("b")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_all(s)
        srv.pages = [[tool("a")], [tool("a", "page two copy")]]
        await _list_all(s)
        with pytest.raises(ToolWithheldError):
            await s.call_tool("a", {})
