"""In-process connection helper for the demo and tests."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
from mcp import ClientSession
from mcp.server import Server
from mcp.shared.memory import create_client_server_memory_streams


@asynccontextmanager
async def connect[S: ClientSession](
    server: Server[Any], session_cls: type[S], **kwargs: Any
) -> AsyncIterator[S]:
    """Run `server` in-process and yield an initialized client session of `session_cls`."""
    async with create_client_server_memory_streams() as (
        client_streams,
        server_streams,
    ):
        client_read, client_write = client_streams
        server_read, server_write = server_streams
        async with anyio.create_task_group() as tg:
            tg.start_soon(
                lambda: server.run(
                    server_read,
                    server_write,
                    server.create_initialization_options(),
                    raise_exceptions=True,
                )
            )
            async with session_cls(client_read, client_write, **kwargs) as session:
                await session.initialize()
                yield session
            tg.cancel_scope.cancel()
