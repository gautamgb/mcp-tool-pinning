import json
from pathlib import Path
from typing import Any

import pytest

from mcp_tool_pinning.digest import tool_digest, tool_set_digest

VECTORS: list[dict[str, Any]] = json.loads(
    (Path(__file__).parent.parent / "vectors" / "tools.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector(vector: dict[str, Any]) -> None:
    assert tool_digest(vector["tool"]) == vector["expected"]


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_numbers_have_no_digest(bad: float) -> None:
    assert tool_digest({"name": "t", "inputSchema": {"type": "object", "default": bad}}) is None


def test_digest_form() -> None:
    digest = tool_digest({"name": "t", "inputSchema": {"type": "object"}})
    assert digest is not None and digest.startswith("sha256:") and len(digest) == 7 + 64


def test_tool_set_digest_ignores_order_and_fails_closed() -> None:
    a = {"name": "a", "inputSchema": {"type": "object"}}
    b = {"name": "b", "inputSchema": {"type": "object"}}
    assert tool_set_digest([a, b]) == tool_set_digest([b, a])
    assert tool_set_digest([a, {"name": "c", "inputSchema": {"default": float("nan")}}]) is None
