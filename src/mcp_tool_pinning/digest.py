"""Tool Definition Digest and Tool Set Digest (SEP draft, sections 1 and 2).

Both work on the raw JSON objects a server sent, not on SDK models: the SDK's
pydantic `Tool` drops members it does not know, and the digest has to cover
the object as received.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping
from typing import Any

import rfc8785

PREFIX = "sha256:"

# Numbers at or above this magnitude get no digest. Checked on the parsed value,
# so a parser that rounds large integers (JavaScript's JSON.parse) reaches the
# same answer as one that keeps them exact.
NUMBER_LIMIT = 2**53


def _numbers_in_range(value: Any) -> bool:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return True
    if isinstance(value, int):
        return abs(value) < NUMBER_LIMIT
    if isinstance(value, float):
        return math.isfinite(value) and abs(value) < NUMBER_LIMIT
    if isinstance(value, Mapping):
        return all(_numbers_in_range(v) for v in value.values())
    if isinstance(value, list):
        return all(_numbers_in_range(v) for v in value)
    return False


def _sha256(data: bytes) -> str:
    return PREFIX + hashlib.sha256(data).hexdigest()


def tool_digest(tool: Mapping[str, Any]) -> str | None:
    """Digest of one raw `Tool` object, or None when it has no digest.

    Only the top-level `_meta` is removed. A None result means a pinning host
    treats the tool as unapproved.
    """
    body = {k: v for k, v in tool.items() if k != "_meta"}
    if not _numbers_in_range(body):
        return None
    try:
        return _sha256(rfc8785.dumps(body))
    except rfc8785.CanonicalizationError:
        return None


def tool_set_digest(tools: Iterable[Mapping[str, Any]]) -> str | None:
    """Digest over every tool's digest, sorted by (name, digest).

    None if any tool has no digest, since the set cannot then be compared.
    """
    pairs: list[tuple[str, str]] = []
    for tool in tools:
        digest = tool_digest(tool)
        if digest is None:
            return None
        pairs.append((str(tool.get("name", "")), digest))
    pairs.sort()
    return _sha256(rfc8785.dumps([digest for _, digest in pairs]))
