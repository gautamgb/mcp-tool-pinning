"""A ClientSession that pins tool, prompt and resource template definitions.

Implements the SEP draft's section 3 for tools and section 4 for prompts and
resource templates. Each kind is screened the same way: one list response
supplies the digest and what the host is given, and a definition whose digest
does not match its pin is withheld until approved. Fetching twice would let a
server answer the digest request and the model request differently.

The SDK's own `call_tool` may issue a tools/list when it lacks an output schema
for the tool it called. That listing goes through `list_tools` below like any
other, so it is checked under the same rules and replaces the current approvals.
"""

from __future__ import annotations

import copy
import difflib
import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp import ClientSession, types
from pydantic import BaseModel, ConfigDict

from .digest import definition_digest, set_digest
from .store import KINDS, Kind, Pin, PinStore
from .uritemplate import expand

Reason = Literal["new", "changed", "no-digest", "duplicate-name"]


class RawToolList(BaseModel):
    """A tools/list result with each tool left as the raw JSON object received.

    Every other member (nextCursor, ttlMs, ...) is kept in `model_extra`.
    """

    model_config = ConfigDict(extra="allow")
    tools: list[dict[str, Any]] = []

    def rest(self) -> dict[str, Any]:
        return dict(self.model_extra or {})


class _RawList(BaseModel):
    """Any list result, kept as raw JSON so definitions can be digested as received."""

    model_config = ConfigDict(extra="allow")

    def split(self, key: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        extra = dict(self.model_extra or {})
        items = extra.pop(key, [])
        if not isinstance(items, list):
            raise TypeError(f"{key} is not a list")
        return items, extra


async def fetch_raw_tools(
    session: ClientSession, params: types.PaginatedRequestParams | None = None
) -> RawToolList:
    return await session.send_request(types.ListToolsRequest(params=params), RawToolList)


class WithheldError(Exception):
    """Raised instead of sending a request that uses an unapproved definition."""


class ToolWithheldError(WithheldError):
    """Raised instead of sending tools/call for a tool that is not approved."""


class PromptWithheldError(WithheldError):
    """Raised instead of sending prompts/get for a prompt that is not approved."""


class TemplateWithheldError(WithheldError):
    """Raised instead of expanding a resource template that is not approved."""


class ApprovalMismatchError(Exception):
    """Raised when the digest being approved is not the one currently held."""


@dataclass(frozen=True)
class Pending:
    """A withheld definition. Show `diff` and approve with `digest` from the same object."""

    name: str
    digest: str | None
    definition: dict[str, Any]
    reason: Reason
    diff: str
    kind: Kind = "tools"


@dataclass
class _Listing:
    """Screening state for one kind, rebuilt from each listing's first page."""

    pending: dict[str, Pending] = field(default_factory=dict)
    approved: dict[str, dict[str, Any]] = field(default_factory=dict)
    seen: set[str] = field(default_factory=set)  # across the pages of one listing
    set_digest: str | None = None


def _pretty(definition: dict[str, Any]) -> list[str]:
    text = json.dumps(definition, indent=2, sort_keys=True, ensure_ascii=False)
    return text.splitlines(keepends=True)


def _pages(params: types.PaginatedRequestParams | None, rest: Mapping[str, Any]) -> tuple[bool, bool]:
    first_page = params is None or params.cursor is None
    return first_page, first_page and rest.get("nextCursor") is None


class PinnedClientSession(ClientSession):
    def __init__(self, *args: Any, store: PinStore, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._store = store
        self._listings: dict[Kind, _Listing] = {kind: _Listing() for kind in KINDS}

    @property
    def last_tool_set_digest(self) -> str | None:
        return self._listings["tools"].set_digest

    def last_set_digest(self, kind: Kind) -> str | None:
        # A multi-page set digest needs every page's raw definitions; not computed here.
        return self._listings[kind].set_digest

    async def list_tools(
        self, *, params: types.PaginatedRequestParams | None = None
    ) -> types.ListToolsResult:
        raw = await fetch_raw_tools(self, params)
        first_page, complete = _pages(params, raw.rest())
        allowed = self._screen("tools", raw.tools, first_page=first_page, complete=complete)

        result = types.ListToolsResult.model_validate({**raw.rest(), "tools": allowed}, by_name=False)
        # Same hook the SDK's own Client uses. It applies the x-mcp-header rules
        # and builds the per-tool state call_tool needs; a tool it drops is not
        # visible to the model, so it is not callable either.
        absorbed = self._absorb_tool_listing(result, complete=complete)
        by_name = {tool["name"]: tool for tool in allowed}
        self._listings["tools"].approved.update({t.name: by_name[t.name] for t in absorbed.tools})
        return absorbed

    async def list_prompts(
        self, *, params: types.PaginatedRequestParams | None = None
    ) -> types.ListPromptsResult:
        raw = await self.send_request(types.ListPromptsRequest(params=params), _RawList)
        items, rest = raw.split("prompts")
        first_page, complete = _pages(params, rest)
        allowed = self._screen("prompts", items, first_page=first_page, complete=complete)
        result = types.ListPromptsResult.model_validate({**rest, "prompts": allowed}, by_name=False)
        self._listings["prompts"].approved.update({p["name"]: p for p in allowed})
        return result

    async def list_resource_templates(
        self, *, params: types.PaginatedRequestParams | None = None
    ) -> types.ListResourceTemplatesResult:
        raw = await self.send_request(types.ListResourceTemplatesRequest(params=params), _RawList)
        items, rest = raw.split("resourceTemplates")
        first_page, complete = _pages(params, rest)
        allowed = self._screen("resourceTemplates", items, first_page=first_page, complete=complete)
        result = types.ListResourceTemplatesResult.model_validate(
            {**rest, "resourceTemplates": allowed}, by_name=False
        )
        self._listings["resourceTemplates"].approved.update({t["name"]: t for t in allowed})
        return result

    def _screen(
        self, kind: Kind, items: list[dict[str, Any]], *, first_page: bool, complete: bool
    ) -> list[dict[str, Any]]:
        listing = self._listings[kind]
        if first_page:
            listing.approved.clear()
            listing.pending.clear()
            listing.seen.clear()
        listing.set_digest = set_digest(items) if complete else None

        counts = Counter(item["name"] for item in items)
        allowed = [
            item
            for item in items
            if self._check(kind, item, duplicate=counts[item["name"]] > 1 or item["name"] in listing.seen)
        ]
        listing.seen |= set(counts)
        return allowed

    def _check(self, kind: Kind, definition: dict[str, Any], *, duplicate: bool) -> bool:
        name: str = definition["name"]
        listing = self._listings[kind]
        digest = definition_digest(definition)
        pin = self._store.get(name, kind=kind)
        if not duplicate and digest is not None and pin is not None and pin.digest == digest:
            return True
        reason: Reason
        if duplicate:
            reason = "duplicate-name"
        elif digest is None:
            reason = "no-digest"
        elif pin is None:
            reason = "new"
        else:
            reason = "changed"
        before = _pretty(pin.definition) if pin else []
        diff = "".join(
            difflib.unified_diff(
                before, _pretty(definition), fromfile=f"{name} (pinned)", tofile=f"{name} (received)"
            )
        )
        listing.approved.pop(name, None)
        listing.pending[name] = Pending(
            name=name, digest=digest, definition=definition, reason=reason, diff=diff, kind=kind
        )
        return False

    def pending(self, *, kind: Kind = "tools") -> list[Pending]:
        return sorted(self._listings[kind].pending.values(), key=lambda p: p.name)

    def approve(self, name: str, digest: str, *, kind: Kind = "tools") -> None:
        """Approve exactly the definition the reviewer saw, identified by its digest."""
        held = self._listings[kind].pending.get(name)
        if held is None or held.reason == "duplicate-name" or held.digest is None or held.digest != digest:
            raise ApprovalMismatchError(f"{name}: nothing approvable pending with digest {digest}")
        self._store.put(name, Pin(digest=held.digest, definition=copy.deepcopy(held.definition)), kind=kind)
        # The definition is offered from the next listing onward.
        self._listings[kind].pending.pop(name)

    async def call_tool(  # type: ignore[override]
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> types.CallToolResult | types.InputRequiredResult | types.Result:
        if name not in self._listings["tools"].approved:
            raise ToolWithheldError(f"{name} is not approved on this connection")
        return await super().call_tool(name, arguments, *args, **kwargs)  # type: ignore[no-any-return]

    async def get_prompt(  # type: ignore[override]
        self,
        name: str,
        arguments: dict[str, str] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> types.GetPromptResult | types.InputRequiredResult:
        # Section 4: the prompt's definition is pinned. What prompts/get returns
        # is rendered per request and is not.
        if name not in self._listings["prompts"].approved:
            raise PromptWithheldError(f"{name} is not approved on this connection")
        return await super().get_prompt(name, arguments, *args, **kwargs)  # type: ignore[no-any-return]

    async def complete(
        self,
        ref: types.ResourceTemplateReference | types.PromptReference,
        argument: dict[str, str],
        context_arguments: dict[str, str] | None = None,
    ) -> types.CompleteResult:
        """Send completion/complete only for an approved prompt or template.

        Completion sends the user's partial input to the server for that prompt
        or template, which offers it as much as prompts/get does.
        """
        if isinstance(ref, types.PromptReference):
            if ref.name not in self._listings["prompts"].approved:
                raise PromptWithheldError(f"{ref.name} is not approved on this connection")
        elif not any(
            t.get("uriTemplate") == ref.uri for t in self._listings["resourceTemplates"].approved.values()
        ):
            raise TemplateWithheldError(f"{ref.uri} is not an approved template on this connection")
        return await super().complete(ref, argument, context_arguments)

    async def read_template(
        self, name: str, variables: Mapping[str, str], **kwargs: Any
    ) -> types.ReadResourceResult | types.InputRequiredResult:
        """Expand an approved template and send resources/read for the result.

        This is the only path here that expands a template. `read_resource`
        itself is not gated: a concrete resource from resources/list is not a
        pinned definition, and a URI the host built some other way never went
        through a template this session can check.
        """
        template = self._listings["resourceTemplates"].approved.get(name)
        if template is None:
            raise TemplateWithheldError(f"{name} is not approved on this connection")
        return await self.read_resource(expand(str(template["uriTemplate"]), variables), **kwargs)  # type: ignore[no-any-return]
