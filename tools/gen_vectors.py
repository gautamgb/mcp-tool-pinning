"""Build every file under vectors/ from the case definitions below.

    uv run python tools/gen_vectors.py          rewrite vectors/
    uv run python tools/gen_vectors.py --check  exit 1 if vectors/ differs from a fresh build

Digests, contract files, shard filenames and SHA256SUMS are computed here, never written by
hand. Expected outcomes are declared by hand: for digest cases the generator only checks that
the computed digest has the declared shape (present or absent, equal to or different from a
named case); for lock cases expected.json is the declaration, and tests/test_lockref.py checks
the reference checker against it.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_tool_pinning.digest import canonical_body, instructions_digest, tool_digest
from mcp_tool_pinning.lockref import (
    command_identity,
    identity_h16,
    identity_key,
    package_identity,
    remote_identity,
    shard_filename,
    slug,
)

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors"


def dump(obj: Any) -> str:
    return json.dumps(obj, indent=2) + "\n"


def strict_parse(text: str) -> Any:
    """json.loads that rejects duplicate keys and NaN/Infinity, to decide what fits tools.json."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({k for k, _ in items}) != len(items):
            raise ValueError("duplicate key")
        return dict(items)

    def constant(name: str) -> Any:
        raise ValueError(name)

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


# Digest cases

LEGACY_NOTES = {
    "base": "Reference tool; most other cases differ from it in one member.",
    "key-order": "Member order does not matter.",
    "top-level-meta-dropped": "Top-level _meta is removed before hashing.",
    "nested-meta-kept": "_meta below the top level is covered.",
    "unknown-member-covered": "An unknown top-level member is covered.",
    "unicode": "Non-ASCII text, a surrogate pair and U+2028 are hashed as UTF-8.",
    "number-1.0-equals-1": "1.0 and 1 are the same number.",
    "number-1": "Integer form of the previous case.",
    "number-formats": "RFC 8785 number serialization: 0.1, -0.0, 1e-07, large integer, 1e15.",
    "annotations-and-title": "title and annotations are covered.",
    "number-2^53-minus-1-has-digest": "Largest magnitude that gets a digest.",
    "number-2^53-no-digest": "Magnitude 2^53 gets no digest.",
    "number-2^53-plus-1-no-digest": "JSON.parse rounds this to 2^53; both sides give no digest.",
    "number-negative-2^53-no-digest": "The limit applies to magnitude.",
    "number-2^64-no-digest": "Large integer, no digest.",
    "number-1e20-exponent-no-digest": "Exponent form above the limit, no digest.",
}

SCHEMA = '{"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}'


def tool_text(*members: str, schema: str = SCHEMA, description: str = '"Summarize text."') -> str:
    parts = ['"name": "summarize"', f'"description": {description}', f'"inputSchema": {schema}']
    return "{" + ", ".join([*parts, *members]) + "}\n"


def schema_with(*members: str) -> str:
    return '{"type": "object", ' + ", ".join(members) + "}"


@dataclass(frozen=True)
class DigestCase:
    name: str
    text: str
    note: str
    has_digest: bool
    same_as: str | None = None
    differs_from: tuple[str, ...] = ()


TEXT_PROPS = '"properties": {"text": {"type": "string"}}'
REQUIRED = '"required": ["text"]'


def number_schema(member: str) -> str:
    """The base schema plus one numeric member, matching the legacy number vectors."""
    return schema_with(TEXT_PROPS, REQUIRED, member)


DIGEST_CASES = [
    DigestCase(
        "unknown-top-level-member-object",
        tool_text('"execution": {"taskSupport": "optional"}'),
        "An unknown top-level member with an object value is covered.",
        True,
        differs_from=("base",),
    ),
    DigestCase(
        "unknown-annotation-member",
        tool_text('"annotations": {"readOnlyHint": true, "x-vendorHint": "fast"}'),
        "An unknown member inside annotations is covered.",
        True,
        differs_from=("base", "annotation-known-only"),
    ),
    DigestCase(
        "annotation-known-only",
        tool_text('"annotations": {"readOnlyHint": true}'),
        "Same annotations without the unknown member.",
        True,
    ),
    DigestCase(
        "proto-key-in-properties",
        tool_text(schema=schema_with('"properties": {"__proto__": {"type": "string"}}')),
        "A property named __proto__ is an ordinary key; parsers must keep it.",
        True,
        differs_from=("proto-control-in-properties",),
    ),
    DigestCase(
        "proto-control-in-properties",
        tool_text(schema=schema_with('"properties": {"proto": {"type": "string"}}')),
        "Control for the __proto__ cases.",
        True,
    ),
    DigestCase(
        "proto-key-in-property",
        tool_text(schema=schema_with('"properties": {"q": {"type": "string", "__proto__": {"x": 1}}}')),
        "__proto__ one level deeper, inside properties.q.",
        True,
        differs_from=("proto-key-in-property-control",),
    ),
    DigestCase(
        "proto-key-in-property-control",
        tool_text(schema=schema_with('"properties": {"q": {"type": "string"}}')),
        "Control: properties.q without the __proto__ member.",
        True,
    ),
    DigestCase(
        "proto-key-in-defs",
        tool_text(schema=schema_with(TEXT_PROPS, '"$defs": {"__proto__": {"type": "string"}}')),
        "__proto__ as a $defs name.",
        True,
        differs_from=("base",),
    ),
    DigestCase(
        "lone-surrogate-key",
        tool_text(schema=schema_with('"properties": {"\\ud800": {"type": "string"}}')),
        "Unpaired high surrogate in a key: no digest.",
        False,
    ),
    DigestCase(
        "lone-surrogate-value",
        tool_text(description='"Summarize text.\\udc00"'),
        "Unpaired low surrogate in a string value: no digest.",
        False,
    ),
    DigestCase(
        "lone-surrogate-high-at-end",
        tool_text(description='"Summarize text.\\ud83d"'),
        "High surrogate with no low surrogate after it: no digest.",
        False,
    ),
    DigestCase(
        "lone-surrogate-reversed-pair",
        tool_text(description='"\\ude00\\ud83d"'),
        "Low then high is two lone surrogates: no digest.",
        False,
    ),
    DigestCase(
        "surrogate-pair-escaped",
        tool_text(description='"Summarize \\ud83d\\ude00"'),
        "A valid escaped pair is one code point and gets a digest.",
        True,
        same_as="surrogate-pair-literal",
    ),
    DigestCase(
        "surrogate-pair-literal",
        tool_text(description='"Summarize \U0001f600"'),
        "The same code point written as UTF-8 bytes.",
        True,
    ),
    DigestCase(
        "key-nfc",
        tool_text(schema=schema_with('"properties": {"caf\u00e9": {"type": "string"}}')),
        "Key in NFC (U+00E9), raw UTF-8.",
        True,
    ),
    DigestCase(
        "key-nfd",
        tool_text(schema=schema_with('"properties": {"cafe\u0301": {"type": "string"}}')),
        "Key in NFD (e + U+0301). No Unicode normalization: differs from key-nfc.",
        True,
        differs_from=("key-nfc",),
    ),
    DigestCase(
        "number-0",
        tool_text(schema=number_schema('"maximum": 0')),
        "Control for number-minus-zero.",
        True,
    ),
    DigestCase(
        "number-minus-zero",
        tool_text(schema=number_schema('"maximum": -0.0')),
        "-0.0 serializes as 0.",
        True,
        same_as="number-0",
    ),
    DigestCase(
        "number-1e21",
        tool_text(schema=number_schema('"maximum": 1e21')),
        "1e21 is above the limit: no digest.",
        False,
    ),
    DigestCase(
        "number-0.1-plus-0.2",
        tool_text(schema=number_schema('"maximum": 0.30000000000000004')),
        "The double nearest 0.1+0.2 keeps all 17 digits.",
        True,
        differs_from=("number-0.3",),
    ),
    DigestCase(
        "number-0.3",
        tool_text(schema=number_schema('"maximum": 0.3')),
        "Control for number-0.1-plus-0.2.",
        True,
    ),
    DigestCase(
        "number-float-2^53-minus-1",
        tool_text(schema=number_schema('"maximum": 9007199254740991.0')),
        "Float form of 2^53-1 equals the integer form.",
        True,
        same_as="number-2^53-minus-1-has-digest",
    ),
    DigestCase(
        "number-float-2^53-no-digest",
        tool_text(schema=number_schema('"maximum": 9007199254740992.0')),
        "Float form of 2^53: no digest.",
        False,
    ),
    DigestCase(
        "nan-text",
        tool_text(schema=number_schema('"maximum": NaN')),
        "Not JSON. Python json.loads accepts NaN, JSON.parse rejects the text; both give none.",
        False,
    ),
    DigestCase(
        "infinity-text",
        tool_text(schema=number_schema('"minimum": -Infinity')),
        "Not JSON. Python json.loads accepts -Infinity; no digest either way.",
        False,
    ),
    DigestCase(
        "annotations-meta-kept",
        tool_text('"annotations": {"readOnlyHint": true, "_meta": {"k": "v"}}'),
        "_meta inside annotations is covered.",
        True,
        differs_from=("annotation-known-only",),
    ),
    DigestCase(
        "meta-top-removed-nested-kept",
        tool_text('"annotations": {"readOnlyHint": true, "_meta": {"k": "v"}}', '"_meta": {"x": 1}'),
        "Top-level _meta removed, annotations._meta kept.",
        True,
        same_as="annotations-meta-kept",
    ),
    DigestCase(
        "duplicate-key-last-wins",
        tool_text(description='"Summarize text.", "description": "Second description."'),
        "Duplicate key in raw text. The parser's last-wins result is digested (known limit).",
        True,
        same_as="duplicate-key-last-value",
    ),
    DigestCase(
        "duplicate-key-last-value",
        tool_text(description='"Second description."'),
        "What duplicate-key-last-wins parses to.",
        True,
    ),
]


def build_digest(out: Path, legacy_source: Path) -> None:
    generated = {c.name for c in DIGEST_CASES}
    legacy = [v for v in json.loads(legacy_source.read_text(encoding="utf-8")) if v["name"] not in generated]
    digests: dict[str, str | None] = {}
    index: dict[str, dict[str, Any]] = {}
    texts: dict[str, str] = {}
    for v in legacy:
        text = json.dumps(v["tool"], indent=2, ensure_ascii=False) + "\n"
        got = tool_digest(json.loads(text))
        if got != v["expected"]:
            raise SystemExit(f"legacy vector {v['name']} no longer matches: {got}")
        digests[v["name"]] = got
        texts[v["name"]] = text
        index[v["name"]] = {"expected": got, "note": LEGACY_NOTES[v["name"]]}
    for case in DIGEST_CASES:
        got = tool_digest(json.loads(case.text))
        digests[case.name] = got
        texts[case.name] = case.text
        index[case.name] = {"expected": got, "note": case.note}
    for case in DIGEST_CASES:
        got = digests[case.name]
        if (got is not None) != case.has_digest:
            raise SystemExit(f"{case.name}: declared has_digest={case.has_digest}, got {got}")
        if case.same_as is not None and got != digests[case.same_as]:
            raise SystemExit(f"{case.name}: expected same digest as {case.same_as}")
        for other in case.differs_from:
            if got == digests[other]:
                raise SystemExit(f"{case.name}: expected a digest different from {other}")

    digest_dir = out / "digest"
    digest_dir.mkdir(parents=True)
    for name, text in texts.items():
        (digest_dir / f"{name}.json").write_bytes(text.encode("utf-8"))
    (digest_dir / "index.json").write_text(dump(index), encoding="utf-8")

    tools = list(legacy)
    for case in DIGEST_CASES:
        try:
            tool = strict_parse(case.text)
        except ValueError:
            continue  # duplicate keys or NaN/Infinity: raw form only
        tools.append(
            {"name": case.name, "tool": tool, "expected": digests[case.name], "same_as": case.same_as}
        )
    (out / "tools.json").write_text(json.dumps(tools, indent=2) + "\n", encoding="utf-8")


# Identity cases

GIT_A = "git+https://github.com/example/mcp-server-a"
GIT_B = "git+https://github.com/example/mcp-server-b"

IDENTITY_CASES: list[tuple[str, dict[str, Any], Callable[[], dict[str, Any]] | None]] = [
    (
        "remote-basic",
        {"url": "https://mcp.example.com/v1/mcp"},
        lambda: remote_identity("https://mcp.example.com/v1/mcp"),
    ),
    (
        "remote-normalized",
        {"url": "HTTPS://user:secret@MCP.Example.COM:443/v1/mcp?token=abc#frag"},
        lambda: remote_identity("HTTPS://user:secret@MCP.Example.COM:443/v1/mcp?token=abc#frag"),
    ),
    (
        "remote-trailing-slash-kept",
        {"url": "https://mcp.example.com/v1/mcp/"},
        lambda: remote_identity("https://mcp.example.com/v1/mcp/"),
    ),
    (
        "remote-empty-path-kept",
        {"url": "https://mcp.example.com"},
        lambda: remote_identity("https://mcp.example.com"),
    ),
    (
        "remote-nondefault-port",
        {"url": "http://localhost:8080/mcp"},
        lambda: remote_identity("http://localhost:8080/mcp"),
    ),
    (
        "remote-http-default-port",
        {"url": "http://Example.com:80/MCP"},
        lambda: remote_identity("http://Example.com:80/MCP"),
    ),
    ("remote-ipv6", {"url": "http://[::1]:3000/mcp"}, lambda: remote_identity("http://[::1]:3000/mcp")),
    ("remote-bad-scheme", {"url": "ftp://example.com/mcp"}, None),
    ("remote-non-ascii-host", {"url": "https://b\u00fccher.example/mcp"}, None),
    (
        "npm-scoped",
        {"registry": "npm", "name": "@modelcontextprotocol/server-filesystem"},
        lambda: package_identity("npm", "@modelcontextprotocol/server-filesystem"),
    ),
    (
        "pypi-normalized",
        {"registry": "pypi", "name": "MCP_Server.Fetch"},
        lambda: package_identity("pypi", "MCP_Server.Fetch"),
    ),
    (
        "oci-tag-dropped",
        {"registry": "oci", "name": "ghcr.io/Example/docs-server:1.4.0"},
        lambda: package_identity("oci", "ghcr.io/Example/docs-server:1.4.0"),
    ),
    (
        "oci-digest-dropped",
        {"registry": "oci", "name": "localhost:5000/docs@sha256:" + "0" * 64},
        lambda: package_identity("oci", "localhost:5000/docs@sha256:" + "0" * 64),
    ),
    ("unknown-registry", {"registry": "cargo", "name": "mcp-server"}, None),
    (
        "command-basename",
        {"command": "/usr/local/bin/my-server", "args": []},
        lambda: command_identity("/usr/local/bin/my-server", []),
    ),
    ("command-dotdot", {"command": "..", "args": []}, None),
    (
        "command-args-git-a",
        {"command": "uvx", "args": [GIT_A]},
        lambda: command_identity("uvx", [GIT_A]),
    ),
    (
        "command-args-git-b",
        {"command": "uvx", "args": [GIT_B]},
        lambda: command_identity("uvx", [GIT_B]),
    ),
    (
        "command-args-paths-verbatim",
        {"command": "/usr/local/bin/node", "args": ["/srv/mcp/server.js", "--root", "./data"]},
        lambda: command_identity("/usr/local/bin/node", ["/srv/mcp/server.js", "--root", "./data"]),
    ),
    (
        "command-args-segment-not-substring",
        {"command": "my-server", "args": ["--author", "docs-team", "--keyword=search"]},
        lambda: command_identity("my-server", ["--author", "docs-team", "--keyword=search"]),
    ),
    ("command-args-secret-flag", {"command": "my-server", "args": ["--api-key", "abc123"]}, None),
    ("command-args-secret-flag-inline", {"command": "my-server", "args": ["--token=abc123"]}, None),
    ("command-args-secret-env", {"command": "my-server", "args": ["GITHUB_TOKEN=abc123"]}, None),
    ("command-args-secret-shape", {"command": "my-server", "args": ["ghp_" + "A" * 36]}, None),
    (
        "command-args-url-userinfo",
        {"command": "uvx", "args": ["git+https://user:pw@git.example.com/mcp-server"]},
        None,
    ),
    (
        "command-args-url-user-only",
        {"command": "uvx", "args": ["git+ssh://git@github.com/example/mcp-server-a"]},
        lambda: command_identity("uvx", ["git+ssh://git@github.com/example/mcp-server-a"]),
    ),
    ("command-args-url-query", {"command": "my-server", "args": ["https://example.com/sse?token=abc123"]}, None),
    (
        "slug-long",
        {"url": "https://" + "a" * 30 + ".example.com/" + "b" * 30},
        lambda: remote_identity("https://" + "a" * 30 + ".example.com/" + "b" * 30),
    ),
    ("slug-empty", {"command": "___", "args": []}, lambda: command_identity("___", [])),
]

# Two identities that must differ: the case named first, then the case it must not equal.
IDENTITY_DISTINCT = [("command-args-git-a", "command-args-git-b")]

IDENTITY_NOTES = {
    "remote-basic": "Already normalized.",
    "remote-normalized": "Scheme and host lower-cased; userinfo, default port, query and fragment removed.",
    "remote-trailing-slash-kept": "A trailing slash is kept, so this differs from remote-basic.",
    "remote-empty-path-kept": "An empty path stays empty; no slash is added.",
    "remote-nondefault-port": "A non-default port is kept.",
    "remote-http-default-port": "Port 80 removed for http; path case kept.",
    "remote-ipv6": "IPv6 literal keeps its brackets.",
    "remote-bad-scheme": "Only http and https.",
    "remote-non-ascii-host": "The URL must be ASCII; the writer converts the host to an A-label first.",
    "npm-scoped": "npm name as published; slug drops the scope punctuation.",
    "pypi-normalized": "PyPI name normalized as in PEP 503.",
    "oci-tag-dropped": "OCI: registry and repository, lower case, tag removed (the version is an attribute).",
    "oci-digest-dropped": "OCI digest removed; a registry port stays in the name.",
    "unknown-registry": "Registry must be npm, pypi or oci.",
    "command-basename": "Command identity keeps only the basename of the command; no args gives [].",
    "command-dotdot": "'..' is not a basename.",
    "command-args-git-a": "Command form carries the args, so this launch ...",
    "command-args-git-b": "... and this one, naming another repository, are two identities.",
    "command-args-paths-verbatim": "Only the command is cut to its basename; paths in args are kept as given.",
    "command-args-segment-not-substring": "Flag names match secret words by whole segment: --author and --keyword pass.",
    "command-args-secret-flag": "A flag named for a credential, with its value in the next argument: no identity.",
    "command-args-secret-flag-inline": "A flag named for a credential with an inline value: no identity.",
    "command-args-secret-env": "NAME=value whose name marks a credential: no identity.",
    "command-args-secret-shape": "A value with a known token shape: no identity.",
    "command-args-url-userinfo": "A URL with a password in its userinfo: no identity.",
    "command-args-url-user-only": "A user name without a password, as in git+ssh://git@..., is not a secret.",
    "command-args-url-query": "A URL whose query names a credential: no identity.",
    "slug-long": "Slug truncated to 48 characters, then trailing '-' trimmed.",
    "slug-empty": "Nothing left after collapsing: slug is 'server'.",
}


def derive(given: dict[str, Any]) -> dict[str, Any]:
    if "url" in given:
        return remote_identity(given["url"])
    if "registry" in given:
        return package_identity(given["registry"], given["name"])
    return command_identity(given["command"], given["args"])


def build_identity(out: Path) -> None:
    cases = []
    for name, given, make in IDENTITY_CASES:
        entry: dict[str, Any] = {"name": name, "input": given, "note": IDENTITY_NOTES[name]}
        if make is None:
            try:
                derive(given)
            except ValueError:
                entry["error"] = True
            else:
                raise SystemExit(f"identity {name}: declared an error, but derivation succeeded")
        else:
            identity = make()
            entry |= {
                "identity": identity,
                "key": identity_key(identity).decode("utf-8"),
                "h16": identity_h16(identity),
                "slug": slug(identity),
                "filename": shard_filename(identity),
            }
        cases.append(entry)
    by_name = {c["name"]: c for c in cases}
    for a, b in IDENTITY_DISTINCT:
        if by_name[a]["h16"] == by_name[b]["h16"]:
            raise SystemExit(f"identity {a} and {b} must differ")
    (out / "identity.json").write_text(dump(cases), encoding="utf-8")


# Lock cases

REMOTE = {"kind": "remote", "url": "https://mcp.example.com/v1/mcp"}
OTHER = {"kind": "remote", "url": "https://other.example.net/mcp"}
PACKAGE = {"kind": "stdio", "package": "npm:@example/docs-server"}
COMMAND_A = {"kind": "stdio", "command": "uvx", "args": ["git+https://github.com/example/mcp-server-a"]}
COMMAND_B = {"kind": "stdio", "command": "uvx", "args": ["git+https://github.com/example/mcp-server-b"]}

SEARCH = {
    "name": "search",
    "description": "Search the docs.",
    "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
}
FETCH = {
    "name": "fetch",
    "description": "Fetch one page.",
    "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
}
FETCH_CHANGED = {**FETCH, "description": "Fetch one page. MARKER: definition changed."}
DELETE = {
    "name": "delete_page",
    "description": "Delete a page.",
    "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]},
    "annotations": {"destructiveHint": True},
}
COUNT_BIG = {
    "name": "count",
    "description": "Count items.",
    "inputSchema": {"type": "object", "properties": {"n": {"type": "integer", "maximum": 2**53}}},
}
SEARCH_COPY = {**SEARCH, "description": "Search the docs, second copy."}
INSTRUCTIONS = "Docs server. Call search before fetch."
INSTRUCTIONS_CHANGED = INSTRUCTIONS + " MARKER: instructions changed."

APPROVAL = {"subject": "github:docs-owner", "at": "2026-10-19T17:00:00Z", "via": "pr", "ref": "pr-42"}


def _hex(tool: dict[str, Any]) -> str:
    digest = tool_digest(tool)
    assert digest is not None, tool["name"]
    return digest.removeprefix("sha256:")


@dataclass
class Builder:
    root: Path
    note: str
    expected: dict[str, Any] = field(default_factory=dict)
    setup: dict[str, list[dict[str, str]]] = field(default_factory=dict)

    def write(self, rel: str, data: bytes | str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path

    def contract(self, tool: dict[str, Any]) -> str:
        body = canonical_body(tool)
        assert body is not None
        name = f"sha256-{_hex(tool)}.json"
        self.write(f".mcp/contracts/{name}", body)
        return name

    def shard(
        self,
        identity: dict[str, Any],
        tools: list[dict[str, Any]],
        instructions: str | None = None,
        filename: str | None = None,
        edit: Callable[[dict[str, Any]], None] | None = None,
        directory: str = ".mcp/lock",
    ) -> str:
        doc: dict[str, Any] = {"lockVersion": "1-draft", "identity": identity}
        doc["attributes"] = {"version": "1.4.0", "env": ["DOCS_TOKEN"]}
        if instructions is not None:
            digest = instructions_digest(instructions)
            doc["instructions"] = {"digest": digest}
        doc["tools"] = {
            t["name"]: {
                "digest": "sha256:" + _hex(t),
                "contract": self.contract(t),
                "approval": dict(APPROVAL),
            }
            for t in tools
        }
        if edit is not None:
            edit(doc)
        name = filename or shard_filename(identity)
        self.write(f"{directory}/{name}", dump(doc))
        return name

    def listing(self, tools: list[dict[str, Any]], instructions: str | None = None) -> None:
        doc: dict[str, Any] = {"tools": tools}
        if instructions is not None:
            doc["instructions"] = instructions
        self.write("listing.json", dump(doc))

    def server(self, identity: dict[str, Any]) -> None:
        self.write("server.json", dump(identity))

    def config(self, posture: str = "guard", **extra: Any) -> None:
        self.write("config.json", dump({"posture": posture, **extra}))

    def manifest(self, sequence: int = 1, extra: tuple[str, ...] = ()) -> None:
        lock = self.root / ".mcp/lock"
        files = {
            p.name: "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(lock.iterdir())
            if p.name not in ("MANIFEST.json", "MANIFEST.json.sigstore")
        }
        for name in extra:
            files[name] = "sha256:" + "0" * 64
        self.write(
            ".mcp/lock/MANIFEST.json", dump({"lockVersion": "1-draft", "sequence": sequence, "files": files})
        )

    def expect(
        self,
        shown: list[str] | None = None,
        withheld: dict[str, str] | None = None,
        flagged: dict[str, str] | None = None,
        removed: list[str] | None = None,
        instructions: str | None = None,
        strip: bool = False,
        lock_error: str | None = None,
        calls: dict[str, str] | None = None,
    ) -> None:
        self.expected = {
            "lockError": lock_error,
            "shown": shown or [],
            "withheld": withheld or {},
            "flagged": flagged or {},
            "removed": removed or [],
            "instructions": instructions,
            "stripInstructions": strip,
            "calls": calls or {},
        }


def standard(b: Builder, posture: str = "guard", **config: Any) -> None:
    """Approved: search and fetch on REMOTE, with instructions. Listing serves the same."""
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.listing([SEARCH, FETCH], INSTRUCTIONS)
    b.server(REMOTE)
    b.config(posture, **config)


def lock_failure(b: Builder, reason: str, strip: bool = True) -> None:
    b.expect(
        withheld={"search": reason, "fetch": reason},
        lock_error=reason,
        strip=strip,
        calls={"search": reason, "fetch": reason},
    )


def all_shown(b: Builder, **extra: Any) -> None:
    """Expectation for a listing where search and fetch are both approved."""
    b.expect(shown=["search", "fetch"], calls={"search": "allow", "fetch": "allow"}, **extra)


def case_all_approved(b: Builder) -> None:
    standard(b)
    all_shown(b)


def case_stdio_package_approved(b: Builder) -> None:
    b.shard(PACKAGE, [SEARCH, FETCH])
    b.listing([SEARCH, FETCH])
    b.server(PACKAGE)
    b.config()
    all_shown(b)


def case_command_args_approved(b: Builder) -> None:
    b.shard(COMMAND_A, [SEARCH, FETCH])
    b.listing([SEARCH, FETCH])
    b.server(COMMAND_A)
    b.config()
    all_shown(b)


def case_command_args_differ(b: Builder) -> None:
    b.shard(COMMAND_A, [SEARCH, FETCH])
    b.listing([SEARCH, FETCH])
    b.server(COMMAND_B)
    b.config()
    b.expect(
        withheld={"search": "unlocked-server", "fetch": "unlocked-server"},
        calls={"search": "unlocked-server", "fetch": "unlocked-server"},
    )


def case_identity_command_without_args(b: Builder) -> None:
    standard(b)
    b.shard({"kind": "stdio", "command": "my-server"}, [SEARCH])
    lock_failure(b, "lock-unsupported")


def case_identity_args_secret(b: Builder) -> None:
    standard(b)
    b.shard({"kind": "stdio", "command": "my-server", "args": ["--token", "abc123"]}, [SEARCH])
    lock_failure(b, "lock-unreadable")


def _edit_text(b: Builder, rel: str, old: str, new: str) -> None:
    path = b.root / rel
    text = path.read_text(encoding="utf-8")
    assert old in text, (rel, old)
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def case_digest_non_ascii_digit(b: Builder) -> None:
    standard(b)
    # U+0663 ARABIC-INDIC DIGIT THREE in place of the last hex character.
    b.shard(
        REMOTE,
        [SEARCH, FETCH],
        INSTRUCTIONS,
        edit=lambda d: d["tools"]["fetch"].update(digest="sha256:" + _hex(FETCH)[:63] + "\u0663"),
    )
    lock_failure(b, "lock-unreadable")


def case_digest_trailing_newline(b: Builder) -> None:
    standard(b)
    b.shard(
        REMOTE,
        [SEARCH, FETCH],
        INSTRUCTIONS,
        edit=lambda d: d["tools"]["fetch"].update(digest="sha256:" + _hex(FETCH) + "\n"),
    )
    lock_failure(b, "lock-unreadable")


def case_time_non_ascii_digit(b: Builder) -> None:
    standard(b)
    # U+0660 ARABIC-INDIC DIGIT ZERO in the seconds.
    b.shard(
        REMOTE,
        [SEARCH, FETCH],
        INSTRUCTIONS,
        edit=lambda d: d["tools"]["fetch"]["approval"].update(at="2026-10-19T17:00:0\u0660Z"),
    )
    lock_failure(b, "lock-unreadable")


def case_sequence_fraction(b: Builder) -> None:
    standard(b)
    b.manifest()
    _edit_text(b, ".mcp/lock/MANIFEST.json", '"sequence": 1,', '"sequence": 1.0,')
    lock_failure(b, "lock-unreadable")


def case_sequence_exponent(b: Builder) -> None:
    standard(b)
    b.manifest()
    _edit_text(b, ".mcp/lock/MANIFEST.json", '"sequence": 1,', '"sequence": 1e0,')
    lock_failure(b, "lock-unreadable")


def case_new_tool(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.listing([SEARCH, FETCH, DELETE], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    b.expect(
        shown=["search", "fetch"],
        withheld={"delete_page": "new-tool"},
        calls={"search": "allow", "fetch": "allow", "delete_page": "new-tool"},
    )


def case_changed_tool(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.listing([SEARCH, FETCH_CHANGED], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    b.expect(
        shown=["search"],
        withheld={"fetch": "upstream-changed"},
        calls={"search": "allow", "fetch": "upstream-changed"},
    )


def case_no_digest_tool(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.listing([SEARCH, FETCH, COUNT_BIG], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    b.expect(
        shown=["search", "fetch"],
        withheld={"count": "no-digest"},
        calls={"search": "allow", "fetch": "allow", "count": "no-digest"},
    )


def case_duplicate_name(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.listing([SEARCH, FETCH, SEARCH_COPY], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    b.expect(
        shown=["fetch"],
        withheld={"search": "duplicate-name"},
        calls={"search": "duplicate-name", "fetch": "allow"},
    )


def case_unlocked_server(b: Builder) -> None:
    b.shard(OTHER, [SEARCH])
    b.listing([SEARCH, FETCH], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    b.expect(
        withheld={"search": "unlocked-server", "fetch": "unlocked-server"},
        instructions="instructions-changed",
        strip=True,
        calls={"search": "unlocked-server", "fetch": "unlocked-server"},
    )


def case_removed_tool(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH, DELETE], INSTRUCTIONS)
    b.listing([SEARCH, FETCH], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    all_shown(b, removed=["delete_page"])


def case_instructions_changed_guard(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.listing([SEARCH, FETCH], INSTRUCTIONS_CHANGED)
    b.server(REMOTE)
    b.config()
    all_shown(b, instructions="instructions-changed", strip=True)


def case_instructions_changed_monitor(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.listing([SEARCH, FETCH], INSTRUCTIONS_CHANGED)
    b.server(REMOTE)
    b.config("monitor")
    all_shown(b, instructions="instructions-changed", strip=False)


def case_instructions_not_locked(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH])
    b.listing([SEARCH, FETCH], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    all_shown(b, instructions="instructions-changed", strip=True)


def case_monitor_shows_all(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH, DELETE], INSTRUCTIONS)
    b.listing([SEARCH, FETCH_CHANGED, COUNT_BIG, SEARCH_COPY, {**DELETE, "name": "archive"}], INSTRUCTIONS)
    b.server(REMOTE)
    b.config("monitor")
    b.expect(
        shown=["search", "fetch", "count", "search", "archive"],
        flagged={
            "search": "duplicate-name",
            "fetch": "upstream-changed",
            "count": "no-digest",
            "archive": "new-tool",
        },
        removed=["delete_page"],
        calls={"search": "allow", "fetch": "allow", "count": "allow", "archive": "allow"},
    )


def case_monitor_unlocked_server(b: Builder) -> None:
    b.shard(OTHER, [SEARCH])
    b.listing([SEARCH], INSTRUCTIONS)
    b.server(REMOTE)
    b.config("monitor")
    b.expect(
        shown=["search"],
        flagged={"search": "unlocked-server"},
        instructions="instructions-changed",
        calls={"search": "allow"},
    )


def case_strict_is_guard(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.listing([SEARCH, FETCH_CHANGED], INSTRUCTIONS_CHANGED)
    b.server(REMOTE)
    b.config("strict")
    b.expect(
        shown=["search"],
        withheld={"fetch": "upstream-changed"},
        instructions="instructions-changed",
        strip=True,
        calls={"search": "allow", "fetch": "upstream-changed"},
    )


def case_unknown_lock_version(b: Builder) -> None:
    standard(b)
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS, edit=lambda d: d.update(lockVersion="1"))
    lock_failure(b, "lock-unsupported")


def case_unknown_top_level_key(b: Builder) -> None:
    standard(b)
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS, edit=lambda d: d.update(policy={"posture": "monitor"}))
    lock_failure(b, "lock-unsupported")


def case_unknown_tool_entry_field(b: Builder) -> None:
    standard(b)
    b.shard(
        REMOTE, [SEARCH, FETCH], INSTRUCTIONS, edit=lambda d: d["tools"]["search"].update(autoApprove=True)
    )
    lock_failure(b, "lock-unsupported")


def case_duplicate_key_in_shard(b: Builder) -> None:
    standard(b)
    path = b.root / ".mcp/lock" / shard_filename(REMOTE)
    text = path.read_text(encoding="utf-8").replace(
        '"lockVersion": "1-draft",', '"lockVersion": "1-draft", "lockVersion": "1-draft",', 1
    )
    path.write_text(text, encoding="utf-8")
    lock_failure(b, "lock-unreadable")


def case_contract_tampered(b: Builder) -> None:
    standard(b)
    body = canonical_body(FETCH_CHANGED)
    assert body is not None
    b.write(f".mcp/contracts/sha256-{_hex(FETCH)}.json", body)
    lock_failure(b, "contract-mismatch")


def case_contract_filename_mismatch(b: Builder) -> None:
    standard(b)
    other = b.contract(SEARCH)
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS, edit=lambda d: d["tools"]["fetch"].update(contract=other))
    lock_failure(b, "contract-mismatch")


def case_contract_missing(b: Builder) -> None:
    standard(b)
    (b.root / f".mcp/contracts/sha256-{_hex(FETCH)}.json").unlink()
    lock_failure(b, "contract-mismatch")


def case_contract_path_traversal(b: Builder) -> None:
    standard(b)
    b.write(f"outside/sha256-{_hex(FETCH)}.json", canonical_body(FETCH) or b"")
    b.shard(
        REMOTE,
        [SEARCH, FETCH],
        INSTRUCTIONS,
        edit=lambda d: d["tools"]["fetch"].update(contract=f"../../outside/sha256-{_hex(FETCH)}.json"),
    )
    lock_failure(b, "lock-unreadable")


def case_shard_h16_mismatch(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS, filename=f"{slug(REMOTE)}--{identity_h16(OTHER)}.json")
    b.listing([SEARCH, FETCH], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    lock_failure(b, "lock-unreadable")


def case_symlinked_shard(b: Builder) -> None:
    name = b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS, directory="shadow")
    b.listing([SEARCH, FETCH], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    b.setup["symlinks"] = [{"path": f".mcp/lock/{name}", "target": f"../../shadow/{name}"}]
    lock_failure(b, "lock-unreadable")


def case_alias_command_traversal(b: Builder) -> None:
    standard(b)
    aliases = {"docs": REMOTE, "evil": {"kind": "stdio", "command": "../../bin/sh", "args": []}}
    b.write(".mcp/lock/aliases.json", dump({"lockVersion": "1-draft", "aliases": aliases}))
    lock_failure(b, "lock-unreadable")


def case_aliases_ok(b: Builder) -> None:
    standard(b)
    aliases = {"docs": REMOTE, "docs-local": PACKAGE}
    b.write(".mcp/lock/aliases.json", dump({"lockVersion": "1-draft", "aliases": aliases}))
    all_shown(b)


def case_unexpected_file(b: Builder) -> None:
    standard(b)
    b.write(".mcp/lock/README.md", "Lock files for this repository.\n")
    lock_failure(b, "lock-unreadable")


def case_non_ascii_filename(b: Builder) -> None:
    standard(b)
    b.setup["files"] = [{"path": ".mcp/lock/caf\u00e9--0123456789abcdef.json", "text": "{}\n"}]
    lock_failure(b, "lock-unreadable")


def case_manifest_ok(b: Builder) -> None:
    standard(b, requireManifest=True)
    b.manifest()
    all_shown(b)


def case_manifest_extra_file(b: Builder) -> None:
    standard(b)
    b.manifest()
    b.shard(OTHER, [SEARCH])
    lock_failure(b, "lock-unreadable")


def case_manifest_missing_file(b: Builder) -> None:
    standard(b)
    b.manifest(extra=("aliases.json",))
    lock_failure(b, "lock-unreadable")


def case_manifest_hash_mismatch(b: Builder) -> None:
    standard(b)
    b.manifest()
    b.shard(
        REMOTE,
        [SEARCH, FETCH],
        INSTRUCTIONS,
        edit=lambda d: d["tools"]["fetch"]["approval"].update(ref="pr-43"),
    )
    lock_failure(b, "lock-unreadable")


def case_manifest_required_missing(b: Builder) -> None:
    standard(b, requireManifest=True)
    lock_failure(b, "lock-unreadable")


SIGNER = {
    "issuer": "https://token.actions.githubusercontent.com",
    "san": "https://github.com/example/lock/.github/workflows/sign.yml@refs/heads/main",
}


def case_signature_missing(b: Builder) -> None:
    standard(b, signer=SIGNER)
    b.manifest()
    lock_failure(b, "lock-signature-invalid")


def case_sequence_rollback(b: Builder) -> None:
    standard(b, signer=SIGNER, lastSequence=5)
    b.manifest(sequence=3)
    b.write(".mcp/lock/MANIFEST.json.sigstore", dump({"note": "placeholder; not a valid bundle"}))
    lock_failure(b, "lock-signature-invalid")


def case_call_before_listing(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    b.expect(calls={"search": "no-listing", "fetch": "no-listing"})


def case_calls(b: Builder) -> None:
    b.shard(REMOTE, [SEARCH, FETCH], INSTRUCTIONS)
    b.listing([SEARCH, FETCH_CHANGED], INSTRUCTIONS)
    b.server(REMOTE)
    b.config()
    b.expect(
        shown=["search"],
        withheld={"fetch": "upstream-changed"},
        calls={"search": "allow", "fetch": "upstream-changed", "delete_page": "not-listed"},
    )


LOCK_CASES: dict[str, tuple[Callable[[Builder], None], str]] = {
    "all-approved": (case_all_approved, "Every served tool and the instructions match the lock."),
    "stdio-package-approved": (case_stdio_package_approved, "Stdio server identified by its npm coordinate."),
    "command-args-approved": (case_command_args_approved, "Stdio server in the command form, args included."),
    "command-args-differ": (
        case_command_args_differ,
        "Same command, other args: another identity, so the server is unlocked.",
    ),
    "identity-command-without-args": (
        case_identity_command_without_args,
        "Command identity in the earlier two-member form.",
    ),
    "identity-args-secret": (case_identity_args_secret, "Shard identity whose args hold a credential."),
    "digest-non-ascii-digit": (case_digest_non_ascii_digit, "Approved digest ends in a non-ASCII digit."),
    "digest-trailing-newline": (case_digest_trailing_newline, "Approved digest ends in a newline."),
    "time-non-ascii-digit": (case_time_non_ascii_digit, "Approval time has a non-ASCII digit."),
    "sequence-fraction": (case_sequence_fraction, "MANIFEST.json sequence written as 1.0."),
    "sequence-exponent": (case_sequence_exponent, "MANIFEST.json sequence written as 1e0."),
    "new-tool": (case_new_tool, "A served tool has no entry in the shard."),
    "changed-tool": (case_changed_tool, "A served tool's digest differs from the approved one."),
    "no-digest-tool": (case_no_digest_tool, "A served tool contains 2^53 and has no digest."),
    "duplicate-name": (case_duplicate_name, "Two served tools share a name; every copy is withheld."),
    "unlocked-server": (case_unlocked_server, "No shard for this identity; everything withheld."),
    "monitor-unlocked-server": (
        case_monitor_unlocked_server,
        "Unlocked server under monitor: shown, flagged.",
    ),
    "removed-tool": (case_removed_tool, "An approved tool is absent from the listing; reported only."),
    "instructions-changed-guard": (
        case_instructions_changed_guard,
        "Instructions differ; guard strips them.",
    ),
    "instructions-changed-monitor": (
        case_instructions_changed_monitor,
        "Instructions differ; monitor keeps them.",
    ),
    "instructions-not-locked": (case_instructions_not_locked, "Instructions served, none locked."),
    "monitor-shows-all": (case_monitor_shows_all, "Monitor shows every tool and flags each reason."),
    "strict-is-guard": (case_strict_is_guard, "strict behaves as guard in draft 1."),
    "unknown-lock-version": (case_unknown_lock_version, "lockVersion other than 1-draft."),
    "unknown-top-level-key": (case_unknown_top_level_key, "Shard carries a member draft 1 does not define."),
    "unknown-tool-entry-field": (case_unknown_tool_entry_field, "Tool entry carries an unknown member."),
    "duplicate-key-in-shard": (
        case_duplicate_key_in_shard,
        "Lock files with duplicate member names are unreadable.",
    ),
    "contract-tampered": (case_contract_tampered, "Contract bytes no longer hash to their filename."),
    "contract-filename-mismatch": (
        case_contract_filename_mismatch,
        "Entry points at a valid contract for another digest.",
    ),
    "contract-missing": (case_contract_missing, "Referenced contract file is absent."),
    "contract-path-traversal": (case_contract_path_traversal, "Contract reference escapes .mcp/contracts."),
    "shard-h16-mismatch": (case_shard_h16_mismatch, "Shard identity does not hash to the filename's h16."),
    "symlinked-shard": (case_symlinked_shard, "Shard is a symlink (created from setup.json)."),
    "alias-command-traversal": (
        case_alias_command_traversal,
        "aliases.json maps a name to a command path, not a basename.",
    ),
    "aliases-ok": (case_aliases_ok, "A well-formed aliases.json does not change the check."),
    "unexpected-file": (case_unexpected_file, "A file in .mcp/lock that the layout does not define."),
    "non-ascii-filename": (
        case_non_ascii_filename,
        "Non-ASCII filename in .mcp/lock (created from setup.json).",
    ),
    "manifest-ok": (case_manifest_ok, "Manifest present, required by host config, and correct."),
    "manifest-extra-file": (case_manifest_extra_file, "A shard on disk is not listed in MANIFEST.json."),
    "manifest-missing-file": (case_manifest_missing_file, "MANIFEST.json lists a file that is not on disk."),
    "manifest-hash-mismatch": (
        case_manifest_hash_mismatch,
        "A shard changed after MANIFEST.json was written.",
    ),
    "manifest-required-missing": (case_manifest_required_missing, "Host requires a manifest; none present."),
    "signature-missing": (case_signature_missing, "Signer configured; no MANIFEST.json.sigstore."),
    "sequence-rollback": (
        case_sequence_rollback,
        "Signer configured; sequence below the last accepted value.",
    ),
    "call-before-listing": (case_call_before_listing, "Calls before any listing are refused."),
    "calls": (case_calls, "Calls to an approved, a withheld and an unlisted tool."),
}


def build_lock(out: Path) -> None:
    index = {}
    for name, (fn, note) in LOCK_CASES.items():
        b = Builder(root=out / "lock" / name, note=note)
        fn(b)
        if not b.expected:
            raise SystemExit(f"{name}: no expectation declared")
        b.write("expected.json", dump(b.expected))
        if b.setup:
            b.write("setup.json", dump(b.setup))
        index[name] = note
    (out / "lock" / "index.json").write_text(dump(index), encoding="utf-8")


def build_sums(out: Path) -> None:
    lines = []
    for path in sorted(p for p in out.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = path.relative_to(out).as_posix()
        if rel != "SHA256SUMS":
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {rel}\n")
    (out / "SHA256SUMS").write_text("".join(sorted(lines, key=lambda line: line[66:])), encoding="utf-8")


def build(out: Path, legacy_source: Path) -> None:
    build_digest(out, legacy_source)
    build_identity(out)
    build_lock(out)
    build_sums(out)


def same_tree(a: Path, b: Path) -> bool:
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.funny_files:
        print("differs:", a, cmp.left_only, cmp.right_only, cmp.funny_files, file=sys.stderr)
        return False
    _, mismatch, errors = filecmp.cmpfiles(a, b, cmp.common_files, shallow=False)
    if mismatch or errors:
        print("differs:", a, mismatch, errors, file=sys.stderr)
        return False
    return all(same_tree(a / d, b / d) for d in cmp.common_dirs)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "vectors"
        fresh.mkdir()
        build(fresh, VECTORS / "tools.json")
        if args.check:
            return 0 if same_tree(fresh, VECTORS) else 1
        shutil.rmtree(VECTORS)
        shutil.copytree(fresh, VECTORS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
