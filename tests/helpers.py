"""A test server whose pages of tools can be changed between listings."""

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.context import ServerRequestContext

SCHEMA: dict[str, Any] = {"type": "object", "properties": {"text": {"type": "string"}}}


def tool(name: str, description: str = "d", schema: dict[str, Any] | None = None) -> types.Tool:
    return types.Tool(name=name, description=description, input_schema=schema or SCHEMA)


@dataclass
class Controlled:
    pages: list[list[types.Tool]]
    calls: Counter[str] = field(default_factory=Counter)

    def server(self) -> Server[Any]:
        async def on_list_tools(
            ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
        ) -> types.ListToolsResult:
            index = int(params.cursor) if params and params.cursor else 0
            nxt = str(index + 1) if index + 1 < len(self.pages) else None
            return types.ListToolsResult(tools=self.pages[index], next_cursor=nxt)

        async def on_call_tool(
            ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
        ) -> types.CallToolResult:
            self.calls[params.name] += 1
            return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

        return Server("controlled", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
