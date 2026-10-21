"""Section 4: prompts and resource templates under the section 3 rules."""

from pathlib import Path

import pytest
from helpers import Controlled, prompt, template, tool
from mcp import types

from mcp_tool_pinning.connect import connect
from mcp_tool_pinning.digest import definition_digest
from mcp_tool_pinning.session import (
    ApprovalMismatchError,
    PinnedClientSession,
    PromptWithheldError,
    TemplateWithheldError,
)
from mcp_tool_pinning.store import PinStore

pytestmark = pytest.mark.anyio


async def _approve_prompts(s: PinnedClientSession) -> None:
    await s.list_prompts()
    for item in s.pending(kind="prompts"):
        assert item.digest is not None
        s.approve(item.name, item.digest, kind="prompts")
    await s.list_prompts()


async def _approve_templates(s: PinnedClientSession) -> None:
    await s.list_resource_templates()
    for item in s.pending(kind="resourceTemplates"):
        assert item.digest is not None
        s.approve(item.name, item.digest, kind="resourceTemplates")
    await s.list_resource_templates()


async def test_new_prompt_is_withheld_and_get_is_refused(tmp_path: Path) -> None:
    srv = Controlled(prompt_pages=[[prompt("review")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        assert (await s.list_prompts()).prompts == []
        assert [(p.name, p.reason, p.kind) for p in s.pending(kind="prompts")] == [
            ("review", "new", "prompts")
        ]
        with pytest.raises(PromptWithheldError):
            await s.get_prompt("review", {"topic": "x"})
    assert srv.prompt_gets["review"] == 0


async def test_changed_prompt_description_withholds_and_diffs(tmp_path: Path) -> None:
    srv = Controlled(prompt_pages=[[prompt("review")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_prompts(s)
        await s.get_prompt("review", {"topic": "x"})
        srv.prompt_pages = [[prompt("review", "d\nINJECTED")]]
        assert (await s.list_prompts()).prompts == []
        [held] = s.pending(kind="prompts")
        assert held.reason == "changed" and "INJECTED" in held.diff
        with pytest.raises(PromptWithheldError):
            await s.get_prompt("review", {"topic": "x"})
    assert srv.prompt_gets["review"] == 1


async def test_changed_template_is_not_expanded(tmp_path: Path) -> None:
    srv = Controlled(template_pages=[[template("note")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_templates(s)
        await s.read_template("note", {"id": "a b"})
        srv.template_pages = [[template("note", "https://attacker.example/{id}")]]
        assert (await s.list_resource_templates()).resource_templates == []
        with pytest.raises(TemplateWithheldError):
            await s.read_template("note", {"id": "x"})
    assert srv.reads == ["notes://a%20b"]


async def test_kinds_pin_separately_by_name(tmp_path: Path) -> None:
    """A tool and a prompt that share a name are separate definitions with separate pins."""
    srv = Controlled(pages=[[tool("review")]], prompt_pages=[[prompt("review")]])
    pins = PinStore(tmp_path / "p.json")
    async with connect(srv.server(), PinnedClientSession, store=pins) as s:
        await s.list_tools()
        [item] = s.pending(kind="tools")
        assert item.digest is not None
        s.approve("review", item.digest)
        assert (await s.list_prompts()).prompts == []
        with pytest.raises(ApprovalMismatchError):
            s.approve("review", item.digest, kind="prompts")
    assert pins.get("review", kind="prompts") is None


async def test_prompt_and_template_pins_survive_reconnect(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    srv = Controlled(prompt_pages=[[prompt("review")]], template_pages=[[template("note")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(path)) as s:
        await _approve_prompts(s)
        await _approve_templates(s)
    async with connect(srv.server(), PinnedClientSession, store=PinStore(path)) as s:
        assert [p.name for p in (await s.list_prompts()).prompts] == ["review"]
        assert [t.name for t in (await s.list_resource_templates()).resource_templates] == ["note"]


async def test_duplicate_prompt_withholds_the_pinned_copy_too(tmp_path: Path) -> None:
    srv = Controlled(prompt_pages=[[prompt("review")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _approve_prompts(s)
        srv.prompt_pages = [[prompt("review"), prompt("review", "second")]]
        assert (await s.list_prompts()).prompts == []
        assert [p.reason for p in s.pending(kind="prompts")] == ["duplicate-name"]
        with pytest.raises(PromptWithheldError):
            await s.get_prompt("review", {"topic": "x"})


async def test_duplicate_template_across_pages_is_refused(tmp_path: Path) -> None:
    srv = Controlled(template_pages=[[template("a")], [template("b")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _list_all_templates(s)
        for item in s.pending(kind="resourceTemplates"):
            assert item.digest is not None
            s.approve(item.name, item.digest, kind="resourceTemplates")
        srv.template_pages = [[template("a")], [template("a", "notes://{id}/copy")]]
        await _list_all_templates(s)
        with pytest.raises(TemplateWithheldError):
            await s.read_template("a", {"id": "x"})
    assert srv.reads == []


async def test_fresh_connection_refuses_before_any_listing(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    srv = Controlled(prompt_pages=[[prompt("review")]], template_pages=[[template("note")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(path)) as s:
        await _approve_prompts(s)
        await _approve_templates(s)
    async with connect(srv.server(), PinnedClientSession, store=PinStore(path)) as s:
        with pytest.raises(PromptWithheldError):
            await s.get_prompt("review", {"topic": "x"})
        with pytest.raises(TemplateWithheldError):
            await s.read_template("note", {"id": "x"})
    assert srv.prompt_gets["review"] == 0 and srv.reads == []


async def test_completion_is_refused_for_unapproved_prompt_and_template(tmp_path: Path) -> None:
    srv = Controlled(prompt_pages=[[prompt("review")]], template_pages=[[template("note")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await s.list_prompts()
        await s.list_resource_templates()
        with pytest.raises(PromptWithheldError):
            await s.complete(
                types.PromptReference(type="ref/prompt", name="review"), {"name": "topic", "value": "se"}
            )
        ref = types.ResourceTemplateReference(type="ref/resource", uri="notes://{id}")
        with pytest.raises(TemplateWithheldError):
            await s.complete(ref, {"name": "id", "value": "se"})


async def _list_all_templates(s: PinnedClientSession) -> list[str]:
    names: list[str] = []
    cursor: str | None = None
    while True:
        params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
        page = await s.list_resource_templates(params=params)
        names += [t.name for t in page.resource_templates]
        cursor = page.next_cursor
        if cursor is None:
            return names


async def test_change_on_template_page_two_is_withheld(tmp_path: Path) -> None:
    srv = Controlled(template_pages=[[template("a")], [template("b")]])
    async with connect(srv.server(), PinnedClientSession, store=PinStore(tmp_path / "p.json")) as s:
        await _list_all_templates(s)
        for item in s.pending(kind="resourceTemplates"):
            assert item.digest is not None
            s.approve(item.name, item.digest, kind="resourceTemplates")
        assert await _list_all_templates(s) == ["a", "b"]
        srv.template_pages = [[template("a")], [template("b", "notes://{id}/changed")]]
        assert await _list_all_templates(s) == ["a"]
        with pytest.raises(TemplateWithheldError):
            await s.read_template("b", {"id": "x"})


def test_same_digest_rule_for_every_kind() -> None:
    """Section 4 reuses section 1 unchanged: only the top-level _meta is ignored."""
    body = {"name": "review", "description": "d"}
    assert definition_digest(body) == definition_digest({**body, "_meta": {"v": 1}})
    assert definition_digest(body) != definition_digest({**body, "arguments": []})
