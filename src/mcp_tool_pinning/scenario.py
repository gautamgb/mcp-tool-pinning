"""Draft conformance scenario for rule 3.4, run against two hosts.

`uv run python -m mcp_tool_pinning.scenario`

Test design from Paolo Costanzo's tool-change lab: serve definition A and call
it, serve A again (the call must reach the server), serve B (the call must not
reach the server), then reconnect while B is still served (still no call).
Each step drives the host to call the tool whether or not it is listed, so the
check is on what reaches the server, which is what a conformance test can see.

Two hosts:
- `pinned`: PinnedClientSession. Approves on first sight, never auto-approves
  after that. Should pass.
- `name-allowlist`: a plain ClientSession plus an "always allow" list of tool
  names, the approval model Paolo found in the clients he tested. Should fail
  at the B step.

Not covered here: sending `list_changed` with the switch, and the 2026-07-28
subscription path. Rule 3.3 says detection must not depend on either, and
Paolo's lab already runs both against real clients and the official SDKs.
"""

from __future__ import annotations

import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, types
from mcp.server import Server
from mcp.server.context import ServerRequestContext

from .connect import connect
from .session import PinnedClientSession, WithheldError
from .store import PinStore

NAME = "noop"
DEFINITION_A = "Return the word ok."
DEFINITION_B = "Reply with the word ok."  # same meaning, different words, as in the lab


@dataclass
class ScenarioServer:
    description: str = DEFINITION_A
    calls: int = 0

    def server(self) -> Server[Any]:
        async def on_list_tools(
            ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
        ) -> types.ListToolsResult:
            schema = {"type": "object", "properties": {}}
            return types.ListToolsResult(
                tools=[types.Tool(name=NAME, description=self.description, input_schema=schema)]
            )

        async def on_call_tool(
            ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
        ) -> types.CallToolResult:
            self.calls += 1
            return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

        return Server("scenario", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


@dataclass(frozen=True)
class Step:
    label: str
    served: str
    must_reach_server: bool
    reached_server: bool

    @property
    def ok(self) -> bool:
        return self.must_reach_server == self.reached_server


@dataclass
class Result:
    host: str
    steps: list[Step] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(step.ok for step in self.steps)


class Host:
    """One connection's worth of host behavior: list, maybe approve, try to call."""

    name: str

    def session(self, server: Server[Any]) -> Any:
        raise NotImplementedError

    async def list_and_call(self, session: Any) -> None:
        raise NotImplementedError


class PinnedHost(Host):
    name = "pinned"

    def __init__(self, store: PinStore) -> None:
        self._store = store
        self._approved_once = False

    def session(self, server: Server[Any]) -> Any:
        return connect(server, PinnedClientSession, store=self._store)

    async def list_and_call(self, session: PinnedClientSession) -> None:
        await session.list_tools()
        if not self._approved_once:
            # The user's one approval, given at the first prompt.
            for item in session.pending():
                assert item.digest is not None
                session.approve(item.name, item.digest)
            await session.list_tools()
            self._approved_once = True
        try:
            await session.call_tool(NAME, {})
        except WithheldError:
            pass


class NameAllowlistHost(Host):
    name = "name-allowlist"

    def __init__(self) -> None:
        self._allowed: set[str] = set()

    def session(self, server: Server[Any]) -> Any:
        return connect(server, ClientSession)

    async def list_and_call(self, session: ClientSession) -> None:
        listing = await session.list_tools()
        names = {tool.name for tool in listing.tools}
        if not self._allowed:
            self._allowed |= names  # "Always allow", chosen at the first prompt
        if NAME in self._allowed:
            await session.call_tool(NAME, {})


async def run(host: Host) -> Result:
    srv = ScenarioServer()
    server = srv.server()
    result = Result(host=host.name)

    async def step(label: str, served: str, must_reach: bool, action: Callable[[], Awaitable[None]]) -> None:
        srv.description = served
        before = srv.calls
        await action()
        result.steps.append(
            Step(label, "A" if served == DEFINITION_A else "B", must_reach, srv.calls > before)
        )

    async with host.session(server) as session:
        await step("serve A, call", DEFINITION_A, True, lambda: host.list_and_call(session))
        await step("serve A again, call", DEFINITION_A, True, lambda: host.list_and_call(session))
        await step("serve B, call", DEFINITION_B, False, lambda: host.list_and_call(session))

    async def after_restart() -> None:
        async with host.session(server) as session:
            await host.list_and_call(session)

    await step("restart, serve B, call", DEFINITION_B, False, after_restart)
    return result


async def main() -> None:
    store = PinStore(Path(tempfile.mkdtemp()) / "pins.json")
    for host in (PinnedHost(store), NameAllowlistHost()):
        result = await run(host)
        print(f"{result.host}: {'PASS' if result.passed else 'FAIL'}")
        for s in result.steps:
            reached = "call reached server" if s.reached_server else "no call"
            print(f"  {'ok  ' if s.ok else 'FAIL'} {s.label:<24} {reached}")


if __name__ == "__main__":
    anyio.run(main)
