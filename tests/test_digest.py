import json
from pathlib import Path
from typing import Any

import pytest

from mcp_tool_pinning.digest import canonical_body, instructions_digest, tool_digest, tool_set_digest

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


@pytest.mark.parametrize(
    "tool",
    [
        {"name": "t", "inputSchema": {"type": "object", "properties": {"\ud800": {"type": "string"}}}},
        {"name": "t", "description": "a\udc00b", "inputSchema": {"type": "object"}},
        {"name": "t", "inputSchema": {"type": "object", "examples": ["x\ud83d"]}},
        {"name": "\udfff", "inputSchema": {"type": "object"}},
    ],
    ids=["key", "value", "nested-value", "name"],
)
def test_lone_surrogate_has_no_digest(tool: dict[str, Any]) -> None:
    assert tool_digest(tool) is None


def test_lone_surrogate_under_top_level_meta_is_ignored() -> None:
    base = {"name": "t", "inputSchema": {"type": "object"}}
    assert tool_digest({**base, "_meta": {"\ud800": 1}}) == tool_digest(base)


def test_surrogate_pair_from_escapes_has_digest() -> None:
    escaped = json.loads('{"name": "t", "description": "\\ud83d\\ude00", "inputSchema": {}}')
    literal = {"name": "t", "description": "\U0001f600", "inputSchema": {}}
    assert tool_digest(escaped) is not None
    assert tool_digest(escaped) == tool_digest(literal)


def test_instructions_digest() -> None:
    assert instructions_digest("Use with care.") == instructions_digest("Use with care.")
    assert instructions_digest("a") != instructions_digest("b")
    assert instructions_digest("a\ud800") is None


def test_canonical_body_hashes_to_digest() -> None:
    import hashlib

    tool = {"name": "t", "inputSchema": {"type": "object"}, "_meta": {"x": 1}}
    body = canonical_body(tool)
    assert body == b'{"inputSchema":{"type":"object"},"name":"t"}'
    assert tool_digest(tool) == "sha256:" + hashlib.sha256(body).hexdigest()
    assert canonical_body({"name": "\ud800"}) is None
