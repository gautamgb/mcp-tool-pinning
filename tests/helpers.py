"""A test server whose tools, prompts and templates can be changed between listings."""

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.context import ServerRequestContext

SCHEMA: dict[str, Any] = {"type": "object", "properties": {"text": {"type": "string"}}}


def tool(name: str, description: str = "d", schema: dict[str, Any] | None = None) -> types.Tool:
    return types.Tool(name=name, description=description, input_schema=schema or SCHEMA)


def prompt(name: str, description: str = "d") -> types.Prompt:
    return types.Prompt(
        name=name,
        description=description,
        arguments=[types.PromptArgument(name="topic", required=True)],
    )


def template(name: str, uri_template: str = "notes://{id}", description: str = "d") -> types.ResourceTemplate:
    return types.ResourceTemplate(name=name, uri_template=uri_template, description=description)


def _page[T](pages: list[list[T]], params: types.PaginatedRequestParams | None) -> tuple[list[T], str | None]:
    index = int(params.cursor) if params and params.cursor else 0
    return pages[index], str(index + 1) if index + 1 < len(pages) else None


@dataclass
class Controlled:
    pages: list[list[types.Tool]] = field(default_factory=lambda: [[]])
    prompt_pages: list[list[types.Prompt]] = field(default_factory=lambda: [[]])
    template_pages: list[list[types.ResourceTemplate]] = field(default_factory=lambda: [[]])
    calls: Counter[str] = field(default_factory=Counter)
    prompt_gets: Counter[str] = field(default_factory=Counter)
    reads: list[str] = field(default_factory=list)

    def server(self) -> Server[Any]:
        async def on_list_tools(
            ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
        ) -> types.ListToolsResult:
            tools, nxt = _page(self.pages, params)
            return types.ListToolsResult(tools=tools, next_cursor=nxt)

        async def on_call_tool(
            ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
        ) -> types.CallToolResult:
            self.calls[params.name] += 1
            return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

        async def on_list_prompts(
            ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
        ) -> types.ListPromptsResult:
            prompts, nxt = _page(self.prompt_pages, params)
            return types.ListPromptsResult(prompts=prompts, next_cursor=nxt)

        async def on_get_prompt(
            ctx: ServerRequestContext[Any, Any], params: types.GetPromptRequestParams
        ) -> types.GetPromptResult:
            self.prompt_gets[params.name] += 1
            text = types.TextContent(type="text", text="ok")
            return types.GetPromptResult(messages=[types.PromptMessage(role="user", content=text)])

        async def on_list_resource_templates(
            ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
        ) -> types.ListResourceTemplatesResult:
            templates, nxt = _page(self.template_pages, params)
            return types.ListResourceTemplatesResult(resource_templates=templates, next_cursor=nxt)

        async def on_read_resource(
            ctx: ServerRequestContext[Any, Any], params: types.ReadResourceRequestParams
        ) -> types.ReadResourceResult:
            self.reads.append(str(params.uri))
            return types.ReadResourceResult(contents=[types.TextResourceContents(uri=params.uri, text="ok")])

        return Server(
            "controlled",
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
            on_list_prompts=on_list_prompts,
            on_get_prompt=on_get_prompt,
            on_list_resource_templates=on_list_resource_templates,
            on_read_resource=on_read_resource,
        )
