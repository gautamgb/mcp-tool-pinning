"""RFC 6570 level 1 expansion, enough to read through an approved template.

Only simple `{var}` expressions are supported. Anything else (operators such
as `{+var}` or `{?q}`, prefix or explode modifiers, several variables in one
expression) raises ValueError, so the prototype never guesses at a URI the
template author did not mean. It is stricter than RFC 6570 in three places: a
variable missing from `variables` is an error (the RFC expands it to nothing,
which reads a different resource), a value of `.` or `..` is refused (it would
step out of the segment the template author meant), and a template with
literal characters outside printable ASCII or the RFC 6570 reserved set is
refused instead of being percent-encoded.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import quote

_EXPRESSION = re.compile(r"\{([^{}]*)\}")
_VARNAME = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*")
# RFC 6570 2.1 literals, minus pct-encoded triplets which pass through as written.
_LITERALS = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*")


def expand(template: str, variables: Mapping[str, str]) -> str:
    if not _LITERALS.fullmatch(_EXPRESSION.sub("", template)):
        raise ValueError(f"unsupported characters in URI template: {template}")

    def substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if not _VARNAME.fullmatch(name):
            raise ValueError(f"unsupported URI template expression: {{{name}}}")
        if name not in variables:
            raise ValueError(f"no value for URI template variable {name}")
        value = variables[name]
        if value in (".", ".."):
            raise ValueError(f"refusing dot segment {value!r} for URI template variable {name}")
        return quote(value, safe="-._~")

    return _EXPRESSION.sub(substitute, template)
