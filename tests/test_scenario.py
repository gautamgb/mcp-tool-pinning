from pathlib import Path

import pytest

from mcp_tool_pinning.scenario import NameAllowlistHost, PinnedHost, run
from mcp_tool_pinning.store import PinStore

pytestmark = pytest.mark.anyio


async def test_pinned_host_passes(tmp_path: Path) -> None:
    result = await run(PinnedHost(PinStore(tmp_path / "p.json")))
    assert [s.reached_server for s in result.steps] == [True, True, False, False]
    assert result.passed


async def test_name_allowlist_host_fails_at_the_switch(tmp_path: Path) -> None:
    result = await run(NameAllowlistHost())
    assert [s.reached_server for s in result.steps] == [True, True, True, True]
    assert [s.ok for s in result.steps] == [True, True, False, False]
    assert not result.passed
