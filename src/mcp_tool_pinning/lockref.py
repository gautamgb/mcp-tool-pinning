"""Reference checker for the lock format, draft 1 revision 1d (spec/mcp-lock-draft-1.md).

It exists to pin the spec down against the vectors in vectors/. It reads a lock, checks
listings against it, builds the listing event, decides calls, classifies upstream frames,
checks host configuration paths and runs the session steps of section 12. It does not write
locks or verify Sigstore bundles; a host does those.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import rfc8785

from mcp_tool_pinning.digest import instructions_digest, meta_digest, tool_digest

LOCK_VERSION = "1-draft"
REFUSAL_CODE = -32011
POSTURES = ("monitor", "guard", "strict")
REGISTRIES = ("npm", "pypi", "oci")
DEFAULT_PORTS = {"http": 80, "https": 443}
DEFAULT_MAX_STALENESS = 60.0
META_CHANGED = "meta-changed"
META_UNAPPROVED = "meta-unapproved"
EVENT_SCHEMA = "mcpindex.lock.event/1"
# Section 9.2.2: the requests whose response may carry instructions.
HANDSHAKE_METHODS = ("initialize", "server/discover")

# Section 4.4: every pattern is ASCII-only and matched with fullmatch. `\d` would accept other
# scripts' digits and `$` would accept a trailing newline, so neither is used.
SHARD_NAME = re.compile(r"([a-z0-9]+(?:-[a-z0-9]+)*)--([0-9a-f]{16})\.json")
CONTRACT_NAME = re.compile(r"sha256-([0-9a-f]{64})\.json")
DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
RFC3339 = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SLUG_MAX = 48
SEQUENCE_MAX = 2**53 - 1

# Section 3.2.1: secret-looking launch arguments. ASCII-only, case-insensitive.
SECRET_SEGMENTS = frozenset(
    {
        "token", "secret", "password", "passwd", "pwd", "apikey", "auth", "authorization",
        "credential", "credentials", "bearer", "cookie", "key", "pat", "privatekey", "session",
    }
)
SECRET_VALUE = re.compile(
    r"^(bearer|basic|token)[ \t]+[^ \t]"
    r"|\bsk-[A-Za-z0-9_-]{16,}"
    r"|\bsk_(live|test)_[A-Za-z0-9]{10,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\bglpat-[A-Za-z0-9_-]{16,}"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bAIza[0-9A-Za-z_-]{30,}"
    r"|\bnpm_[A-Za-z0-9]{30,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.",
    re.ASCII | re.IGNORECASE,
)

MANIFEST = "MANIFEST.json"
SIGNATURE = "MANIFEST.json.sigstore"
ALIASES = "aliases.json"

SHARD_KEYS = {"lockVersion", "identity", "attributes", "instructions", "tools"}
ATTRIBUTE_KEYS = {"version", "audience", "command", "args", "env"}
ENTRY_KEYS = {"digest", "contract", "approval"}
ENTRY_OPTIONAL = {"metaDigest"}
APPROVAL_KEYS = {"subject", "at", "via", "ref"}
VIA = {"pr", "runtime", "api", "migrated"}


class LockError(Exception):
    """A whole-lock failure. `reason` is one of the spec's reason codes."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


def _unreadable(detail: str) -> LockError:
    return LockError("lock-unreadable", detail)


def _unsupported(detail: str) -> LockError:
    return LockError("lock-unsupported", detail)


# Identity


def normalize_url(url: str) -> str:
    """Section 3.1: lower-case scheme and host, drop default port, userinfo, query, fragment."""
    if not url.isascii():
        raise ValueError("URL must be ASCII; convert the host to its A-label first")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ValueError(f"unsupported scheme {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise ValueError("URL has no host")
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    netloc = host if port is None or port == DEFAULT_PORTS[scheme] else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path}"


def remote_identity(url: str) -> dict[str, str]:
    return {"kind": "remote", "url": normalize_url(url)}


def package_identity(registry: str, name: str) -> dict[str, str]:
    if registry not in REGISTRIES:
        raise ValueError(f"unknown registry {registry!r}")
    if registry == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif registry == "oci":
        name = name.split("@", 1)[0]
        head, _, last = name.rpartition("/")
        name = (f"{head}/" if head else "") + last.split(":", 1)[0]
        name = name.lower()
    if not _valid_package_name(name):
        raise ValueError(f"invalid package name {name!r}")
    return {"kind": "stdio", "package": f"{registry}:{name}"}


def command_identity(command: str, args: Sequence[str] = ()) -> dict[str, Any]:
    """Section 3.2 command form: the command's basename and its arguments verbatim.

    Raises ValueError for a command that is not a basename after trimming the path, and for
    secret-looking arguments (section 3.2.1), which an identity can neither keep nor strip.
    """
    base = command.replace("\\", "/").rsplit("/", 1)[-1]
    if not _valid_command(base):
        raise ValueError(f"invalid command {command!r}")
    kept = list(args)
    if not all(isinstance(a, str) and _well_formed(a) for a in kept):
        raise ValueError("args must be strings without unpaired surrogates")
    problem = secret_arg_problem(kept)
    if problem is not None:
        raise ValueError(f"cannot form an identity: {problem}; pass the secret in an env var or use an alias")
    return {"kind": "stdio", "command": base, "args": kept}


def _well_formed(text: str) -> bool:
    return not any("\ud800" <= ch <= "\udfff" for ch in text)


def _secret_name(name: str) -> bool:
    segments = re.split(r"[-_.]+", name.lstrip("-").lower())
    return any(s in SECRET_SEGMENTS for s in segments) or "".join(segments) in SECRET_SEGMENTS


def _url_problem(arg: str) -> str | None:
    if "://" not in arg:
        return None
    rest = arg.split("://", 1)[1]
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if ":" in authority.rpartition("@")[0]:
        return "a URL argument carries a password in its userinfo"
    if "?" in rest:
        query = rest.split("?", 1)[1].split("#", 1)[0]
        for part in query.split("&"):
            if _secret_name(part.split("=", 1)[0]):
                return "a URL argument carries a credential in its query"
    return None


def secret_arg_problem(args: Sequence[str]) -> str | None:
    """None if no argument is secret-looking (section 3.2.1), else what was found."""
    value_of: str | None = None
    for arg in args:
        if value_of is not None and not arg.startswith("-"):
            return f"the value of {value_of} looks like a credential"
        value_of = None
        if SECRET_VALUE.search(arg):
            return "an argument matches a credential pattern"
        if (problem := _url_problem(arg)) is not None:
            return problem
        head, eq, tail = arg.partition("=")
        if arg.startswith("-"):
            if _secret_name(head):
                if eq and tail:
                    return f"{head} carries a credential"
                if not eq:
                    value_of = head
            continue
        if eq and ENV_NAME.fullmatch(head) and _secret_name(head):
            return f"{head}= carries a credential"
    return None


def _valid_package_name(name: str) -> bool:
    return bool(name) and name.isascii() and all(0x21 <= ord(c) <= 0x7E for c in name)


def _valid_command(name: str) -> bool:
    return _valid_package_name(name) and "/" not in name and "\\" not in name and name not in (".", "..")


def validate_identity(identity: Any) -> dict[str, Any]:
    """Return the identity if it is well formed, else raise LockError."""
    if not isinstance(identity, dict) or not all(
        isinstance(v, str) or k == "args" for k, v in identity.items()
    ):
        raise _unreadable("identity members must be strings, args an array of strings")
    kind = identity.get("kind")
    if kind == "remote":
        if set(identity) != {"kind", "url"}:
            raise _unsupported(f"remote identity members {sorted(identity)}")
        try:
            ok = normalize_url(identity["url"]) == identity["url"]
        except ValueError:
            ok = False
        if not ok:
            raise _unreadable(f"identity url is not normalized: {identity['url']!r}")
    elif kind == "stdio":
        if set(identity) == {"kind", "package"}:
            registry, _, name = identity["package"].partition(":")
            if registry not in REGISTRIES or not _valid_package_name(name):
                raise _unreadable(f"invalid package {identity['package']!r}")
        elif set(identity) == {"kind", "command", "args"}:
            args = identity["args"]
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                raise _unreadable("identity args must be an array of strings")
            try:
                ok = command_identity(identity["command"], args) == identity
            except ValueError:
                ok = False
            if not ok:
                raise _unreadable("identity command is not a basename, or its args cannot form an identity")
        else:
            raise _unsupported(f"stdio identity members {sorted(identity)}")
    else:
        raise _unsupported(f"identity kind {kind!r}")
    return identity


def identity_key(identity: Mapping[str, Any]) -> bytes:
    return rfc8785.dumps(dict(identity))


def identity_h16(identity: Mapping[str, Any]) -> str:
    return hashlib.sha256(identity_key(identity)).hexdigest()[:16]


def slug(identity: Mapping[str, Any]) -> str:
    if identity["kind"] == "remote":
        parts = urlsplit(identity["url"])
        source = (parts.hostname or "") + parts.path
    elif "package" in identity:
        source = identity["package"].partition(":")[2]
    else:
        source = identity["command"]
    text = re.sub(r"[^a-z0-9]+", "-", source.lower())
    text = text.strip("-")[:SLUG_MAX].strip("-")
    return text or "server"


def shard_filename(identity: Mapping[str, Any]) -> str:
    return f"{slug(identity)}--{identity_h16(identity)}.json"


# Reading


@dataclass(frozen=True)
class Shard:
    identity: dict[str, Any]
    tools: dict[str, str]
    instructions: str | None
    # Tool name -> approved metaDigest, for the entries that carry one.
    meta: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Lock:
    shards: dict[bytes, Shard]
    aliases: dict[str, dict[str, Any]]
    sequence: int | None


@dataclass(frozen=True)
class ReaderConfig:
    """Host configuration. Never read from the lock repository itself."""

    require_manifest: bool = False
    signer: Mapping[str, Any] | None = None
    # Section 8.2: a host with a signer must name a sequence store. The vectors model the
    # store as present or absent; `last_sequence` is the value it holds.
    sequence_store: bool = False
    last_sequence: int | None = None
    verify_signature: Callable[[bytes, bytes, Mapping[str, Any]], bool] | None = None


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate member name")
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-JSON constant {name}")


def _reject_float(token: str) -> Any:
    # Section 4.3: numbers in lock files are integer tokens. json hands any token with a
    # fraction or an exponent here, including 1.0 and 1e0.
    raise ValueError(f"number {token} is not an integer token")


def strict_json(data: bytes, what: str) -> Any:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise _unreadable(f"{what}: {exc}") from exc


def _check_dir(path: Path, required: bool) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if required:
            raise _unreadable(f"{path.name} is missing") from None
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise _unreadable(f"{path.name} is not a plain directory")
    return True


def _read_regular(path: Path) -> bytes:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise _unreadable(f"{path.name} is not a regular file")
    return path.read_bytes()


def _read_lock_dir(lock_dir: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for entry in sorted(os.scandir(lock_dir), key=lambda e: e.name):
        name = entry.name
        if not name.isascii():
            raise _unreadable(f"non-ASCII filename {name!r}")
        shard = SHARD_NAME.fullmatch(name)
        if not (name in (MANIFEST, SIGNATURE, ALIASES) or (shard and len(shard.group(1)) <= SLUG_MAX)):
            raise _unreadable(f"unexpected file {name!r}")
        files[name] = _read_regular(lock_dir / name)
    return files


def _check_manifest(files: dict[str, bytes], config: ReaderConfig) -> int | None:
    signed = config.signer is not None
    if signed and not config.sequence_store:
        raise LockError("lock-signature-invalid", "signer configured without a sequence store")
    if MANIFEST not in files:
        if signed:
            raise LockError("lock-signature-invalid", "signer configured but no MANIFEST.json")
        if config.require_manifest:
            raise _unreadable("MANIFEST.json required by host configuration")
        return None
    raw = files[MANIFEST]
    if signed:
        bundle = files.get(SIGNATURE)
        verify = config.verify_signature
        assert config.signer is not None
        if bundle is None or verify is None or not verify(raw, bundle, config.signer):
            raise LockError("lock-signature-invalid", "MANIFEST.json signature missing or invalid")
    manifest = strict_json(raw, MANIFEST)
    if not isinstance(manifest, dict):
        raise _unreadable("MANIFEST.json is not an object")
    if manifest.get("lockVersion") != LOCK_VERSION:
        raise _unsupported(f"MANIFEST.json lockVersion {manifest.get('lockVersion')!r}")
    if set(manifest) - {"lockVersion", "sequence", "files"}:
        raise _unsupported(f"MANIFEST.json members {sorted(manifest)}")
    sequence = manifest.get("sequence")
    listed = manifest.get("files")
    if type(sequence) is not int or not 0 <= sequence <= SEQUENCE_MAX or not isinstance(listed, dict):
        raise _unreadable("MANIFEST.json sequence or files malformed")
    if signed and config.last_sequence is not None and sequence < config.last_sequence:
        raise LockError("lock-signature-invalid", f"sequence {sequence} < {config.last_sequence}")
    on_disk = set(files) - {MANIFEST, SIGNATURE}
    if set(listed) != on_disk:
        raise _unreadable(f"file set differs from MANIFEST.json: {sorted(set(listed) ^ on_disk)}")
    for name in sorted(on_disk):
        if listed[name] != "sha256:" + hashlib.sha256(files[name]).hexdigest():
            raise _unreadable(f"{name} does not match MANIFEST.json")
    return sequence


def _check_aliases(raw: bytes) -> dict[str, dict[str, Any]]:
    doc = strict_json(raw, ALIASES)
    if not isinstance(doc, dict):
        raise _unreadable("aliases.json is not an object")
    if doc.get("lockVersion") != LOCK_VERSION:
        raise _unsupported(f"aliases.json lockVersion {doc.get('lockVersion')!r}")
    if set(doc) != {"lockVersion", "aliases"}:
        raise _unsupported(f"aliases.json members {sorted(doc)}")
    aliases = doc["aliases"]
    if not isinstance(aliases, dict):
        raise _unreadable("aliases must be an object")
    return {name: validate_identity(identity) for name, identity in aliases.items()}


def _check_attributes(attributes: Any) -> None:
    if not isinstance(attributes, dict):
        raise _unreadable("attributes must be an object")
    if set(attributes) - ATTRIBUTE_KEYS:
        raise _unsupported(f"attributes members {sorted(attributes)}")
    for key in ("version", "audience", "command"):
        if key in attributes and not isinstance(attributes[key], str):
            raise _unreadable(f"attributes.{key} must be a string")
    for key in ("args", "env"):
        value = attributes.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise _unreadable(f"attributes.{key} must be an array of strings")
    if not all(ENV_NAME.fullmatch(v) for v in attributes.get("env", [])):
        raise _unreadable("attributes.env holds names only")


def _check_entry(name: str, entry: Any, contracts: Path) -> tuple[str, str | None]:
    if not isinstance(entry, dict):
        raise _unreadable(f"tool {name!r} entry is not an object")
    if set(entry) - ENTRY_KEYS - ENTRY_OPTIONAL:
        raise _unsupported(f"tool {name!r} members {sorted(entry)}")
    if set(entry) & ENTRY_KEYS != ENTRY_KEYS:
        raise _unreadable(f"tool {name!r} lacks {sorted(ENTRY_KEYS - set(entry))}")
    approval = entry["approval"]
    if not isinstance(approval, dict):
        raise _unreadable(f"tool {name!r} approval is not an object")
    if set(approval) - APPROVAL_KEYS:
        raise _unsupported(f"tool {name!r} approval members {sorted(approval)}")
    if not all(isinstance(approval.get(k), str) for k in ("subject", "at", "via")):
        raise _unreadable(f"tool {name!r} approval lacks subject, at or via")
    if "ref" in approval and not isinstance(approval["ref"], str):
        raise _unreadable(f"tool {name!r} approval ref must be a string")
    if not RFC3339.fullmatch(approval["at"]):
        raise _unreadable(f"tool {name!r} approval time is not RFC 3339")
    if approval["via"] not in VIA:
        raise _unsupported(f"tool {name!r} approval via {approval['via']!r}")
    digest, contract = entry["digest"], entry["contract"]
    if not isinstance(digest, str) or not (match := DIGEST.fullmatch(digest)):
        raise _unreadable(f"tool {name!r} digest malformed")
    if not isinstance(contract, str) or not CONTRACT_NAME.fullmatch(contract):
        raise _unreadable(f"tool {name!r} contract is not a contract filename: {contract!r}")
    if contract != f"sha256-{match.group(1)}.json":
        raise LockError("contract-mismatch", f"tool {name!r} contract filename differs from digest")
    try:
        data = _read_regular(contracts / contract)
    except FileNotFoundError:
        raise LockError("contract-mismatch", f"tool {name!r} contract file missing") from None
    if hashlib.sha256(data).hexdigest() != match.group(1):
        raise LockError("contract-mismatch", f"tool {name!r} contract bytes differ from digest")
    meta = entry.get("metaDigest")
    if "metaDigest" in entry and not (isinstance(meta, str) and DIGEST.fullmatch(meta)):
        raise _unreadable(f"tool {name!r} metaDigest malformed")
    return digest, meta


def _check_shard(filename: str, raw: bytes, contracts: Path) -> Shard:
    doc = strict_json(raw, filename)
    if not isinstance(doc, dict):
        raise _unreadable(f"{filename} is not an object")
    if "lockVersion" not in doc:
        raise _unreadable(f"{filename} has no lockVersion")
    if doc["lockVersion"] != LOCK_VERSION:
        raise _unsupported(f"{filename} lockVersion {doc['lockVersion']!r}")
    if set(doc) - SHARD_KEYS:
        raise _unsupported(f"{filename} members {sorted(set(doc) - SHARD_KEYS)}")
    if "identity" not in doc or "tools" not in doc:
        raise _unreadable(f"{filename} lacks identity or tools")
    identity = validate_identity(doc["identity"])
    match = SHARD_NAME.fullmatch(filename)
    assert match is not None
    if identity_h16(identity) != match.group(2):
        raise _unreadable(f"{filename} identity does not hash to its filename")
    if "attributes" in doc:
        _check_attributes(doc["attributes"])
    instructions = None
    if "instructions" in doc:
        block = doc["instructions"]
        if not isinstance(block, dict):
            raise _unreadable(f"{filename} instructions is not an object")
        if set(block) - {"digest"}:
            raise _unsupported(f"{filename} instructions members {sorted(block)}")
        instructions = block.get("digest")
        if not isinstance(instructions, str) or not DIGEST.fullmatch(instructions):
            raise _unreadable(f"{filename} instructions digest malformed")
    tools = doc["tools"]
    if not isinstance(tools, dict):
        raise _unreadable(f"{filename} tools is not an object")
    entries = {name: _check_entry(name, entry, contracts) for name, entry in tools.items()}
    return Shard(
        identity=identity,
        tools={name: digest for name, (digest, _) in entries.items()},
        instructions=instructions,
        meta={name: meta for name, (_, meta) in entries.items() if meta is not None},
    )


def load_lock(root: Path, config: ReaderConfig | None = None) -> Lock:
    """Read and verify the whole lock under `root`. Any failure fails the load."""
    config = config or ReaderConfig()
    mcp = root / ".mcp"
    _check_dir(mcp, required=True)
    lock_dir = mcp / "lock"
    _check_dir(lock_dir, required=True)
    contracts = mcp / "contracts"
    _check_dir(contracts, required=False)
    files = _read_lock_dir(lock_dir)
    sequence = _check_manifest(files, config)
    aliases = _check_aliases(files[ALIASES]) if ALIASES in files else {}
    shards: dict[bytes, Shard] = {}
    for name in sorted(files):
        if not SHARD_NAME.fullmatch(name):
            continue
        shard = _check_shard(name, files[name], contracts)
        key = identity_key(shard.identity)
        if key in shards:
            raise _unreadable(f"two shards for one identity: {name}")
        shards[key] = shard
    return Lock(shards=shards, aliases=aliases, sequence=sequence)


def reader_config_for(config: Mapping[str, Any]) -> ReaderConfig:
    """A vector's config.json as a ReaderConfig. testVerifier "accept-any" is a test-runner
    stub that accepts every bundle, so a case can reach the checks after verification."""
    stub = config.get("testVerifier")
    if stub not in (None, "accept-any"):
        raise ValueError(f"unknown testVerifier {stub!r}")
    return ReaderConfig(
        require_manifest=config.get("requireManifest", False),
        signer=config.get("signer"),
        sequence_store=config.get("sequenceStore", False),
        last_sequence=config.get("lastSequence"),
        verify_signature=(lambda manifest, bundle, signer: True) if stub else None,
    )


def apply_setup(root: Path) -> None:
    """Create the symlinks and files a lock case's setup.json lists (git cannot carry them)."""
    setup_path = root / "setup.json"
    if not setup_path.exists():
        return
    setup = json.loads(setup_path.read_text(encoding="utf-8"))
    for link in setup.get("symlinks", []):
        (root / link["path"]).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(link["target"], root / link["path"])
    for item in setup.get("files", []):
        (root / item["path"]).parent.mkdir(parents=True, exist_ok=True)
        (root / item["path"]).write_text(item["text"], encoding="utf-8")


# Checking


@dataclass
class Decision:
    """Outcome of one listing. `callable` is the allow-list for calls on this connection."""

    shown: list[str] = field(default_factory=list)
    withheld: dict[str, str] = field(default_factory=dict)
    flagged: dict[str, str] = field(default_factory=dict)
    removed: list[str] = field(default_factory=list)
    instructions: str | None = None
    strip_instructions: bool = False
    lock_error: str | None = None
    callable: set[str] = field(default_factory=set)
    # Section 9.2.3, for each shown tool that has a top-level _meta: whether the host relays
    # it, and the flag (meta-changed, meta-unapproved or None).
    meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Section 10: one row per listing entry with a string name, in listing order.
    tools: list[dict[str, Any]] = field(default_factory=list)
    # Entries in the listing's tools array, named or not.
    served: int = 0


def check_listing(
    lock: Lock | LockError, identity: Mapping[str, Any], listing: Mapping[str, Any], posture: str
) -> Decision:
    if posture not in POSTURES:
        raise ValueError(f"unknown posture {posture!r}")
    guard = posture != "monitor"
    raw_tools = listing.get("tools")
    if not isinstance(raw_tools, list):
        raise TypeError("listing has no tools array")
    served_instructions = listing.get("instructions")
    has_instructions = served_instructions is not None
    decision = Decision(served=len(raw_tools))

    def row(name: str, served: str | None, approved: str | None, reason: str | None, meta: str | None,
            shown: bool) -> None:
        decision.tools.append(
            {"name": name, "served": served, "approved": approved,
             "decision": "shown" if shown else "withheld", "reason": reason, "meta": meta}
        )

    def name_of(tool: Any) -> str | None:
        name = tool.get("name") if isinstance(tool, dict) else None
        return name if isinstance(name, str) else None

    if isinstance(lock, LockError):
        decision.lock_error = lock.reason
        for tool in raw_tools:
            if (name := name_of(tool)) is not None:
                decision.withheld[name] = lock.reason
                row(name, tool_digest(tool), None, lock.reason, None, shown=False)
        decision.strip_instructions = has_instructions
        return decision

    shard = lock.shards.get(identity_key(identity))
    counts = Counter(n for n in map(name_of, raw_tools) if n is not None)
    for tool in raw_tools:
        name = name_of(tool)
        if name is None:
            continue  # cannot be shown or called; a host reports it as no-digest
        digest = tool_digest(tool)
        if shard is None:
            reason: str | None = "unlocked-server"
        elif counts[name] > 1:
            reason = "duplicate-name"
        elif digest is None:
            reason = "no-digest"
        elif name not in shard.tools:
            reason = "new-tool"
        elif shard.tools[name] != digest:
            reason = "upstream-changed"
        else:
            reason = None
        approved = shard.tools.get(name) if shard is not None else None
        if reason is not None and guard:
            decision.withheld[name] = reason
            row(name, digest, approved, reason, None, shown=False)
            continue
        if reason is not None:
            decision.flagged[name] = reason
        decision.shown.append(name)
        decision.callable.add(name)
        flag: str | None = None
        if "_meta" in tool:
            approved_meta = shard.meta.get(name) if shard is not None else None
            if approved_meta is None:
                flag = META_UNAPPROVED
            elif meta_digest(tool["_meta"]) != approved_meta:
                flag = META_CHANGED
            decision.meta[name] = {"relay": flag is None or not guard, "flag": flag}
        row(name, digest, approved, reason, flag, shown=True)

    if shard is not None:
        decision.removed = sorted(set(shard.tools) - set(counts))
    if has_instructions:
        locked = shard.instructions if shard is not None else None
        served = instructions_digest(served_instructions) if isinstance(served_instructions, str) else None
        if locked is None or served != locked:
            decision.instructions = "instructions-changed"
            decision.strip_instructions = guard
    return decision


def listing_event(decision: Decision, identity: Mapping[str, Any], posture: str, host: str) -> dict[str, Any]:
    """Section 10 listing event, without `id`, `time` and the optional `snapshotId`.

    Every served entry that is not shown counts as withheld, entries without a string name
    included. Under a whole-lock failure `instructions` is null: the instructions are withheld
    with everything else and the lock error says why.
    """
    return {
        "schema": EVENT_SCHEMA,
        "type": "listing",
        "host": host,
        "server": {"h16": identity_h16(identity), "slug": slug(identity)},
        "posture": posture,
        "lockError": decision.lock_error,
        "counts": {
            "served": decision.served,
            "shown": len(decision.shown),
            "withheld": decision.served - len(decision.shown),
            "removed": len(decision.removed),
        },
        "tools": [dict(r) for r in decision.tools],
        "removed": list(decision.removed),
        "instructions": None if decision.lock_error is not None else decision.instructions,
    }


def check_call(decision: Decision | None, name: str) -> str:
    """'allow', or the reason sent in `data.reason` of a -32011 error."""
    if decision is None:
        return "no-listing"
    if decision.lock_error is not None:
        return decision.lock_error
    if name in decision.callable:
        return "allow"
    return decision.withheld.get(name, "not-listed")


# Upstream frames (section 9.2.2)


def _id_matches(rid: Any, ids: Sequence[Any]) -> bool:
    """Exact JSON type and value: a string matches only an equal string, a number only an
    equal number. Booleans, null, objects and arrays never match, so `true` is not 1 and
    `"1"` is not 1."""
    if isinstance(rid, str):
        return any(isinstance(i, str) and i == rid for i in ids)
    if isinstance(rid, (int, float)) and not isinstance(rid, bool):
        return any(isinstance(i, (int, float)) and not isinstance(i, bool) and i == rid for i in ids)
    return False


def classify_frame(frame: Any, inflight: Sequence[Any], handshake: Sequence[Any] = ()) -> str:
    """What a host does with one frame from the server.

    `inflight` holds the ids of the host's tools/list requests still unanswered, `handshake`
    the id of its initialize request if that is unanswered. Returns `listing` (check it as a
    page of a listing), `handshake` (check its instructions), `drop` (never reaches the
    client) or `relay` (pass it on unchanged).
    """
    if not isinstance(frame, dict):
        return "drop"
    result = frame.get("result")
    carries_tools = isinstance(result, dict) and "tools" in result
    carries_instructions = isinstance(result, dict) and "instructions" in result
    if "method" in frame:
        return "drop" if "result" in frame or "error" in frame else "relay"
    if "id" not in frame:
        return "drop" if carries_tools or carries_instructions else "relay"
    rid = frame["id"]
    if _id_matches(rid, inflight):
        return "listing"
    if carries_tools:
        return "drop"
    if _id_matches(rid, handshake):
        return "handshake"
    if carries_instructions:
        return "drop"
    return "relay"


def split_pending(pending: Sequence[Mapping[str, Any]]) -> tuple[list[Any], list[Any]]:
    """Ids of the unanswered tools/list requests, and of the unanswered handshake requests
    (initialize or server/discover), from a list of {"id", "method"} records."""
    inflight = [p["id"] for p in pending if p["method"] == "tools/list"]
    handshake = [p["id"] for p in pending if p["method"] in HANDSHAKE_METHODS]
    return inflight, handshake


# Host configuration paths (section 8.2)


def repository_root(lock_root: Path) -> Path:
    """The repository that holds the lock: the nearest directory at or above the lock root
    that has a `.git` entry (a directory, or a file as in a worktree), else the lock root."""
    start = Path(os.path.realpath(lock_root))
    for candidate in (start, *start.parents):
        if os.path.lexists(candidate / ".git"):
            return candidate
    return start


def _resolved(path: Path) -> Path:
    """realpath of the nearest existing ancestor, with the rest of the path appended."""
    path = Path(os.path.abspath(path))
    rest: list[str] = []
    probe = path
    while not os.path.lexists(probe) and probe != probe.parent:
        rest.append(probe.name)
        probe = probe.parent
    return Path(os.path.realpath(probe)).joinpath(*reversed(rest))


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def host_path_problem(lock_root: Path, paths: Mapping[str, str | Path | None]) -> str | None:
    """None if every named host path (sequencePath, trustedRoot) lies outside the repository
    that holds the lock, else what is wrong. Both the path as given, made absolute, and its
    resolved form are checked, against the repository root as given and resolved."""
    repo = repository_root(lock_root)
    roots = {repo, Path(os.path.abspath(lock_root))}
    for key, value in paths.items():
        if value is None:
            continue
        given = Path(os.path.abspath(value))
        for candidate in (given, _resolved(given)):
            if any(_within(candidate, root) for root in roots):
                return f"{key} lies inside the repository that holds the lock ({repo})"
    return None


# Sessions (sections 9.2.1, 9.2.2, 9.5 and 9.8)


class Session:
    """One connection's call gate, driven by the steps of a session.json vector.

    The lock is loaded for every listing. Calls are decided in the order of section 9.5. A call
    checked against a snapshot older than `max_staleness` seconds reloads the lock first; the
    reload re-checks the latest listing and can only remove names from the allow-list, and a
    failed reload refuses the call with lock-stale. Server frames are classified as section
    9.2.2 says; a dropped frame that answers a pending request ends it with an error, and a
    dropped answer to the listing's tools/list fails the listing.
    """

    def __init__(
        self,
        root: Path,
        identity: Mapping[str, Any],
        posture: str,
        config: ReaderConfig,
        max_staleness: float = DEFAULT_MAX_STALENESS,
    ) -> None:
        self.root = root
        self.identity = identity
        self.posture = posture
        self.config = config
        self.max_staleness = max_staleness
        self.now = 0.0
        # The latest completed listing: its decision, its tools and when its snapshot loaded.
        self.decision: Decision | None = None
        self.listing: Mapping[str, Any] | None = None
        self.loaded_at = 0.0
        # The latest listing failed (section 9.5).
        self.failed = False
        self.due = False
        # Unanswered host requests, in order: {"id", "method"}.
        self.pending: list[dict[str, Any]] = []
        # Id of the tools/list request of the listing in progress, if any.
        self.listing_id: Any = None
        self.in_progress = False
        self._seq = 0

    def _load(self) -> Lock | LockError:
        try:
            return load_lock(self.root, self.config)
        except LockError as exc:
            return exc

    def _take(self, rid: Any) -> dict[str, Any] | None:
        for index, request in enumerate(self.pending):
            if _id_matches(rid, [request["id"]]):
                return self.pending.pop(index)
        return None

    def request(self, rid: Any, method: str) -> None:
        self.pending.append({"id": rid, "method": method})

    def list_start(self, rid: Any = None) -> Any:
        """Send a cursorless tools/list. An earlier listing in progress is abandoned and its
        request answered with an error. Returns the request id."""
        if rid is None:
            self._seq += 1
            rid = f"list-{self._seq}"
        if self.in_progress:
            self._take(self.listing_id)
        self.request(rid, "tools/list")
        self.listing_id = rid
        self.in_progress = True
        return rid

    def list_complete(self, listing: Mapping[str, Any]) -> Decision:
        self._take(self.listing_id)
        self.decision = check_listing(self._load(), self.identity, listing, self.posture)
        self.listing = listing
        self.loaded_at = self.now
        self.in_progress = self.failed = self.due = False
        self.listing_id = None
        return self.decision

    def list_fail(self) -> None:
        self._take(self.listing_id)
        self.in_progress = False
        self.failed = True
        self.listing_id = None

    def list_changed(self) -> None:
        self.due = True

    def frame(self, frame: Any) -> tuple[str, Any]:
        """Classify one server frame other than a listing page. Returns the kind and the id
        of the host request answered with a JSON-RPC error because of it, or None."""
        inflight, handshake = split_pending(self.pending)
        kind = classify_frame(frame, inflight, handshake)
        if kind == "listing":
            raise ValueError("listing pages are list-complete or list-fail steps")
        if not isinstance(frame, dict) or "id" not in frame:
            return kind, None
        if kind == "relay" and "method" in frame:
            return kind, None  # a request from the server; its id is the server's
        request = self._take(frame["id"])
        if kind != "drop" or request is None:
            return kind, None
        if self.in_progress and _id_matches(request["id"], [self.listing_id]):
            self.in_progress = False
            self.failed = True
            self.listing_id = None
        return kind, request["id"]

    def call(self, name: str) -> str:
        # 1. no-listing: a listing is in progress, or none has ended on this connection.
        if self.in_progress or (self.decision is None and not self.failed):
            return "no-listing"
        decision = self.decision
        # 2. The lock failure, when the latest completed listing was decided under 9.4.
        if decision is not None and decision.lock_error is not None:
            return decision.lock_error
        # 3. unreachable, when the latest listing failed.
        if self.failed or decision is None or self.listing is None:
            return "unreachable"
        # 4. lock-stale (section 9.8).
        if self.now - self.loaded_at > self.max_staleness:
            lock = self._load()
            if isinstance(lock, LockError):
                return "lock-stale"
            fresh = check_listing(lock, self.identity, self.listing, self.posture)
            for dropped in decision.callable - fresh.callable:
                decision.withheld[dropped] = fresh.withheld.get(dropped, "not-listed")
            decision.callable &= fresh.callable
            self.loaded_at = self.now
        # 5 and 6.
        return check_call(decision, name)


def run_session(root: Path, steps: Sequence[Mapping[str, Any]], session: Session) -> list[str]:
    """Run session.json steps. Returns a description of every step whose outcome differs."""
    mismatches: list[str] = []
    for index, step in enumerate(steps):
        op = step["op"]
        if op == "list-start":
            session.list_start(step.get("id"))
        elif op == "list-complete":
            session.list_complete(json.loads((root / step["listing"]).read_text(encoding="utf-8")))
        elif op == "list-fail":
            session.list_fail()
        elif op == "list-changed":
            session.list_changed()
        elif op == "request":
            session.request(step["id"], step["method"])
        elif op == "frame":
            got = session.frame(step["frame"])
            want = (step["expect"], step["errorTo"])
            if got != want or (got[1] is not None and type(got[1]) is not type(want[1])):
                mismatches.append(f"step {index}: frame gave {got!r}, expected {want!r}")
        elif op == "clock":
            session.now += float(step["advance"])
        elif op == "write":
            (root / step["path"]).write_bytes(step["text"].encode("utf-8"))
        elif op == "call":
            got_call = session.call(step["tool"])
            if got_call != step["expect"]:
                mismatches.append(
                    f"step {index}: call {step['tool']!r} gave {got_call!r}, expected {step['expect']!r}"
                )
        else:
            raise ValueError(f"unknown session op {op!r}")
    return mismatches
