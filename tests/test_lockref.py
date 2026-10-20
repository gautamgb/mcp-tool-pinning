import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from mcp_tool_pinning.lockref import (
    Lock,
    LockError,
    ReaderConfig,
    Session,
    check_call,
    check_listing,
    classify_frame,
    command_identity,
    identity_h16,
    identity_key,
    load_lock,
    package_identity,
    remote_identity,
    run_session,
    shard_filename,
    slug,
)

REPO = Path(__file__).parent.parent
VECTORS = REPO / "vectors"
LOCK_CASES = sorted(p.name for p in (VECTORS / "lock").iterdir() if p.is_dir())
IDENTITY_CASES: list[dict[str, Any]] = json.loads((VECTORS / "identity.json").read_text(encoding="utf-8"))
FRAME_CASES: list[dict[str, Any]] = json.loads((VECTORS / "frames.json").read_text(encoding="utf-8"))


def materialize(case: str, tmp: Path) -> Path:
    """Copy a lock case and apply its setup.json (symlinks and odd filenames git cannot carry)."""
    root = tmp / case
    shutil.copytree(VECTORS / "lock" / case, root)
    setup_path = root / "setup.json"
    if setup_path.exists():
        setup = json.loads(setup_path.read_text(encoding="utf-8"))
        for link in setup.get("symlinks", []):
            (root / link["path"]).parent.mkdir(parents=True, exist_ok=True)
            os.symlink(link["target"], root / link["path"])
        for item in setup.get("files", []):
            (root / item["path"]).parent.mkdir(parents=True, exist_ok=True)
            (root / item["path"]).write_text(item["text"], encoding="utf-8")
    return root


def reader_config(config: dict[str, Any]) -> ReaderConfig:
    """config.json to ReaderConfig. testVerifier "accept-any" is a test-runner stub that
    accepts every bundle, so the vectors can reach the checks after signature verification."""
    stub = config.get("testVerifier")
    assert stub in (None, "accept-any")
    return ReaderConfig(
        require_manifest=config.get("requireManifest", False),
        signer=config.get("signer"),
        sequence_store=config.get("sequenceStore", False),
        last_sequence=config.get("lastSequence"),
        verify_signature=(lambda manifest, bundle, signer: True) if stub else None,
    )


def run_case(root: Path) -> dict[str, Any]:
    config = json.loads((root / "config.json").read_text(encoding="utf-8"))
    identity = json.loads((root / "server.json").read_text(encoding="utf-8"))
    reader = reader_config(config)
    lock: Lock | LockError
    try:
        lock = load_lock(root, reader)
    except LockError as exc:
        lock = exc
    expected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
    listing_path = root / "listing.json"
    decision = None
    if listing_path.exists():
        listing = json.loads(listing_path.read_text(encoding="utf-8"))
        decision = check_listing(lock, identity, listing, config["posture"])
    return {
        "lockError": lock.reason if isinstance(lock, LockError) else None,
        "shown": decision.shown if decision else [],
        "withheld": decision.withheld if decision else {},
        "flagged": decision.flagged if decision else {},
        "removed": decision.removed if decision else [],
        "instructions": decision.instructions if decision else None,
        "stripInstructions": decision.strip_instructions if decision else False,
        "calls": {name: check_call(decision, name) for name in expected["calls"]},
        "meta": decision.meta if decision else {},
    }


@pytest.mark.parametrize("case", LOCK_CASES)
def test_lock_vector(case: str, tmp_path: Path) -> None:
    root = materialize(case, tmp_path)
    expected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
    assert run_case(root) == expected
    session_path = root / "session.json"
    if session_path.exists():
        config = json.loads((root / "config.json").read_text(encoding="utf-8"))
        identity = json.loads((root / "server.json").read_text(encoding="utf-8"))
        session = Session(
            root, identity, config["posture"], reader_config(config), config.get("maxStaleness", 60)
        )
        steps = json.loads(session_path.read_text(encoding="utf-8"))["steps"]
        assert run_session(root, steps, session) == []


@pytest.mark.parametrize("case", FRAME_CASES, ids=[c["name"] for c in FRAME_CASES])
def test_frame_vector(case: dict[str, Any]) -> None:
    handshake = [case["handshake"]] if "handshake" in case else []
    assert classify_frame(case["frame"], case["inflight"], handshake) == case["expect"]


@pytest.mark.parametrize("case", IDENTITY_CASES, ids=[c["name"] for c in IDENTITY_CASES])
def test_identity_vector(case: dict[str, Any]) -> None:
    given = case["input"]

    def make() -> dict[str, Any]:
        if "url" in given:
            return remote_identity(given["url"])
        if "registry" in given:
            return package_identity(given["registry"], given["name"])
        return command_identity(given["command"], given["args"])

    if case.get("error"):
        with pytest.raises(ValueError):
            make()
        return
    identity = make()
    assert identity == case["identity"]
    assert identity_key(identity).decode() == case["key"]
    assert identity_h16(identity) == case["h16"]
    assert slug(identity) == case["slug"]
    assert len(case["slug"]) <= 48
    assert shard_filename(identity) == case["filename"]


def test_unknown_posture_is_refused() -> None:
    with pytest.raises(ValueError):
        check_listing(
            LockError("lock-unreadable", "x"), {"kind": "remote", "url": "https://a/"}, {"tools": []}, "x"
        )


def test_generated_vectors_are_current() -> None:
    result = subprocess.run(
        [sys.executable, str(REPO / "tools" / "gen_vectors.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_sha256sums_cover_every_vector_file() -> None:
    import hashlib

    listed = {}
    for line in (VECTORS / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, rel = line.split("  ", 1)
        listed[rel] = digest
    on_disk = {p.relative_to(VECTORS).as_posix(): p for p in VECTORS.rglob("*") if p.is_file()}
    on_disk.pop("SHA256SUMS")
    assert set(listed) == set(on_disk)
    for rel, path in on_disk.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == listed[rel], rel
