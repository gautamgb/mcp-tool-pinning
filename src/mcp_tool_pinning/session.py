"""A ClientSession that pins tool definitions (SEP draft, section 3).

The digest, the SDK's per-tool state and what the model sees all come from one
`tools/list` response. Fetching twice would let a server answer the digest
request and the model request differently.

The SDK's own `call_tool` may issue a tools/list when it lacks an output schema
for the tool it called. That listing goes through `list_tools` below like any
other, so it is checked under the same rules and replaces the current approvals.
"""

from __future__ import annotations

import difflib
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any, Literal

from mcp import ClientSession, types
from pydantic import BaseModel, ConfigDict

from .digest import tool_digest, tool_set_digest
from .store import Pin, PinStore

Reason = Literal["new", "changed", "no-digest", "duplicate-name"]


class RawToolList(BaseModel):
    """A tools/list result with each tool left as the raw JSON object received.

    Every other member (nextCursor, ttlMs, ...) is kept in `model_extra`.
    """

    model_config = ConfigDict(extra="allow")
    tools: list[dict[str, Any]] = []

    def rest(self) -> dict[str, Any]:
        return dict(self.model_extra or {})


async def fetch_raw_tools(
    session: ClientSession, params: types.PaginatedRequestParams | None = None
) -> RawToolList:
    return await session.send_request(types.ListToolsRequest(params=params), RawToolList)


class ToolWithheldError(Exception):
    """Raised instead of sending tools/call for a tool that is not approved."""


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


def _pretty(definition: dict[str, Any]) -> list[str]:
    text = json.dumps(definition, indent=2, sort_keys=True, ensure_ascii=False)
    return text.splitlines(keepends=True)


class PinnedClientSession(ClientSession):
    def __init__(self, *args: Any, store: PinStore, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._store = store
        self._pending: dict[str, Pending] = {}
        self._approved_names: set[str] = set()
        self._seen_names: set[str] = set()  # across the pages of one listing
        self.last_tool_set_digest: str | None = None

    async def list_tools(
        self, *, params: types.PaginatedRequestParams | None = None
    ) -> types.ListToolsResult:
        raw = await fetch_raw_tools(self, params)

        first_page = params is None or params.cursor is None
        complete = first_page and raw.rest().get("nextCursor") is None
        if first_page:
            self._approved_names.clear()
            self._pending.clear()
            self._seen_names.clear()
        # A multi-page Tool Set Digest needs every page's raw tools; not computed here.
        self.last_tool_set_digest = tool_set_digest(raw.tools) if complete else None

        counts = Counter(tool["name"] for tool in raw.tools)
        allowed: list[dict[str, Any]] = []
        for tool in raw.tools:
            name = tool["name"]
            if self._check(tool, duplicate=counts[name] > 1 or name in self._seen_names):
                allowed.append(tool)
        self._seen_names |= set(counts)

        result = types.ListToolsResult.model_validate({**raw.rest(), "tools": allowed}, by_name=False)
        # Same hook the SDK's own Client uses. It applies the x-mcp-header rules
        # and builds the per-tool state call_tool needs; a tool it drops is not
        # visible to the model, so it is not callable either.
        absorbed = self._absorb_tool_listing(result, complete=complete)
        self._approved_names |= {tool.name for tool in absorbed.tools}
        return absorbed

    def _check(self, tool: dict[str, Any], *, duplicate: bool) -> bool:
        name: str = tool["name"]
        digest = tool_digest(tool)
        pin = self._store.get(name)
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
                before, _pretty(tool), fromfile=f"{name} (pinned)", tofile=f"{name} (received)"
            )
        )
        self._approved_names.discard(name)
        self._pending[name] = Pending(name=name, digest=digest, definition=tool, reason=reason, diff=diff)
        return False

    def pending(self) -> list[Pending]:
        return sorted(self._pending.values(), key=lambda p: p.name)

    def approve(self, name: str, digest: str) -> None:
        """Approve exactly the definition the reviewer saw, identified by its digest."""
        held = self._pending.get(name)
        if held is None or held.reason == "duplicate-name" or held.digest is None or held.digest != digest:
            raise ApprovalMismatchError(f"{name}: nothing approvable pending with digest {digest}")
        self._store.put(name, Pin(digest=held.digest, definition=held.definition))
        # The model sees the tool from the next list_tools onward.
        self._pending.pop(name)

    async def call_tool(  # type: ignore[override]
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> types.CallToolResult | types.InputRequiredResult | types.Result:
        if name not in self._approved_names:
            raise ToolWithheldError(f"{name} is not approved on this connection")
        return await super().call_tool(name, arguments, *args, **kwargs)  # type: ignore[no-any-return]
