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

# A value nested deeper than this gets no digest (lock draft 1c, section 2.1). The tool object
# is at depth 0 and each member value or array element is one deeper than its container. The
# limit keeps every implementation clear of its recursion limit and gives them one answer.
MAX_DEPTH = 512


def _lone_surrogate(text: str) -> bool:
    """True if the str holds a UTF-16 surrogate code point.

    `json.loads` joins a valid escaped pair into one code point above U+FFFF, so a surrogate
    left in a Python str is always unpaired. RFC 8785 serializes to UTF-8, which cannot encode
    one. Checked here so the rule does not depend on which exception the canonicalization
    library raises.
    """
    return any("\ud800" <= ch <= "\udfff" for ch in text)


def _digestible(value: Any, depth: int) -> bool:
    """False if anything in `value` (which sits at `depth`) rules out a digest: a number out of
    range or not finite, a lone surrogate in a member name or string, a value deeper than
    MAX_DEPTH, or something that is not JSON.

    Iterative, so a hostile listing cannot reach the interpreter's recursion limit here, and
    the depth test comes first, so rfc8785 never sees a value deep enough to exhaust it.
    """
    stack = [(value, depth)]
    while stack:
        item, level = stack.pop()
        if level > MAX_DEPTH:
            return False
        if isinstance(item, bool) or item is None:
            continue
        if isinstance(item, str):
            if _lone_surrogate(item):
                return False
        elif isinstance(item, int):
            if abs(item) >= NUMBER_LIMIT:
                return False
        elif isinstance(item, float):
            if not (math.isfinite(item) and abs(item) < NUMBER_LIMIT):
                return False
        elif isinstance(item, Mapping):
            for key, member in item.items():
                if not isinstance(key, str) or _lone_surrogate(key):
                    return False
                stack.append((member, level + 1))
        elif isinstance(item, list):
            stack.extend((member, level + 1) for member in item)
        else:
            return False
    return True


def _sha256(data: bytes) -> str:
    return PREFIX + hashlib.sha256(data).hexdigest()


def tool_digest(tool: Mapping[str, Any]) -> str | None:
    """Digest of one raw `Tool` object, or None when it has no digest.

    Only the top-level `_meta` is removed. A None result means a pinning host
    treats the tool as unapproved.
    """
    body = {k: v for k, v in tool.items() if k != "_meta"}
    if not _digestible(body, 0):
        return None
    try:
        return _sha256(rfc8785.dumps(body))
    except (rfc8785.CanonicalizationError, UnicodeEncodeError):
        return None


def canonical_body(tool: Mapping[str, Any]) -> bytes | None:
    """RFC 8785 bytes of the tool minus top-level `_meta`; sha256 of these is the digest.

    These are the bytes of a lock contract file. None when the tool has no digest.
    """
    if tool_digest(tool) is None:
        return None
    return rfc8785.dumps({k: v for k, v in tool.items() if k != "_meta"})


def meta_digest(meta: Any) -> str | None:
    """Digest of a tool's top-level `_meta` object (lock draft 1c, section 2.3), or None.

    The rules of the tool digest apply, with `_meta` at depth 1 as it sits in the tool. A
    `_meta` that is not an object has no digest.
    """
    if not isinstance(meta, Mapping):
        return None
    if not _digestible(meta, 1):
        return None
    try:
        return _sha256(rfc8785.dumps(dict(meta)))
    except (rfc8785.CanonicalizationError, UnicodeEncodeError):
        return None


def instructions_digest(instructions: str) -> str | None:
    """SHA-256 over the RFC 8785 form of the instructions as a JSON string."""
    if _lone_surrogate(instructions):
        return None
    return _sha256(rfc8785.dumps(instructions))


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
