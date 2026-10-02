"""Side-by-side demo: `uv run python -m mcp_tool_pinning.demo`.

One demo server, three clients: a scanner that only lists, an unpinned client,
and a pinned client. The server switches a description after three tools/call
requests from the same client.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import anyio
from mcp import ClientSession

from .connect import connect
from .demo_server import THRESHOLD, make_server
from .digest import tool_set_digest
from .session import PinnedClientSession, ToolWithheldError, fetch_raw_tools
from .store import PinStore


async def main() -> None:
    server = make_server()
    pins = Path(tempfile.mkdtemp()) / "pins.json"

    print("1. Scanner: connect, list, disconnect")
    async with connect(server, ClientSession) as scanner:
        scanner_digest = tool_set_digest((await fetch_raw_tools(scanner)).tools)
    print(f"   tool set digest {scanner_digest}\n")

    print(f"2. Unpinned client: list, {THRESHOLD} calls, list again")
    async with connect(server, ClientSession) as plain:
        await plain.list_tools()
        for _ in range(THRESHOLD):
            await plain.call_tool("format_text", {"text": "a  b"})
        listing = await plain.list_tools()
        summarize = next(t for t in listing.tools if t.name == "summarize")
        print("   description the model now sees:")
        for line in (summarize.description or "").splitlines():
            print(f"     {line}")
    print()

    print(f"3. Pinned client: approve on first list, {THRESHOLD} calls, list again")
    async with connect(server, PinnedClientSession, store=PinStore(pins)) as pinned:
        await pinned.list_tools()
        for item in pinned.pending():
            assert item.digest is not None
            pinned.approve(item.name, item.digest)
        listing = await pinned.list_tools()
        print(f"   approved and visible: {[t.name for t in listing.tools]}")
        for _ in range(THRESHOLD):
            await pinned.call_tool("format_text", {"text": "a  b"})
        listing = await pinned.list_tools()
        print(f"   visible after relist: {[t.name for t in listing.tools]}")
        for item in pinned.pending():
            print(f"   withheld: {item.name} ({item.reason})")
            print("   " + item.diff.replace("\n", "\n   "))
        try:
            await pinned.call_tool("summarize", {"text": "x"})
        except ToolWithheldError as exc:
            print(f"   call refused: {exc}\n")
        client_digest = pinned.last_tool_set_digest

    print("4. Compare tool set digests (section 4)")
    print(f"   scanner        {scanner_digest}")
    print(f"   pinned client  {client_digest}")
    verdict = (
        "agree"
        if scanner_digest == client_digest
        else "DISAGREE: the server served them different definitions"
    )
    print(f"   {verdict}")


if __name__ == "__main__":
    anyio.run(main)
