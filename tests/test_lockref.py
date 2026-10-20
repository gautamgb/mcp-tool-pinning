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
    Session,
    apply_setup,
    check_call,
    check_listing,
    classify_frame,
    command_identity,
    host_path_problem,
    identity_h16,
    identity_key,
    listing_event,
    load_lock,
    package_identity,
    reader_config_for,
    remote_identity,
    run_session,
    shard_filename,
    slug,
    split_pending,
)

REPO = Path(__file__).parent.parent
VECTORS = REPO / "vectors"
LOCK_CASES = sorted(p.name for p in (VECTORS / "lock").iterdir() if p.is_dir())
IDENTITY_CASES: list[dict[str, Any]] = json.loads((VECTORS / "identity.json").read_text(encoding="utf-8"))
FRAME_CASES: list[dict[str, Any]] = json.loads((VECTORS / "frames.json").read_text(encoding="utf-8"))
HOST_CASES: list[dict[str, Any]] = json.loads((VECTORS / "host-config.json").read_text(encoding="utf-8"))


def build_host_layout(case: dict[str, Any], base: Path) -> Path:
    """Create a host-config case's directories, files and symlinks under `base`."""
    for rel in case.get("dirs", []):
        (base / rel).mkdir(parents=True, exist_ok=True)
    for rel in case.get("files", []):
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text("", encoding="utf-8")
    for item in case.get("texts", []):
        (base / item["path"]).parent.mkdir(parents=True, exist_ok=True)
        (base / item["path"]).write_text(item["text"], encoding="utf-8")
    for link in case.get("symlinks", []):
        (base / link["path"]).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(link["target"], base / link["path"])
    return base / case["lockRoot"]


def materialize(case: str, tmp: Path) -> Path:
    """Copy a lock case and apply its setup.json (symlinks and odd filenames git cannot carry)."""
    root = tmp / case
    shutil.copytree(VECTORS / "lock" / case, root)
    apply_setup(root)
    return root


def run_case(root: Path) -> dict[str, Any]:
    config = json.loads((root / "config.json").read_text(encoding="utf-8"))
    identity = json.loads((root / "server.json").read_text(encoding="utf-8"))
    reader = reader_config_for(config)
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
    event = listing_event(decision, identity, config["posture"], config["host"]) if decision else None
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
        "event": event,
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
            root, identity, config["posture"], reader_config_for(config), config.get("maxStaleness", 60)
        )
        steps = json.loads(session_path.read_text(encoding="utf-8"))["steps"]
        assert run_session(root, steps, session) == []


@pytest.mark.parametrize("case", FRAME_CASES, ids=[c["name"] for c in FRAME_CASES])
def test_frame_vector(case: dict[str, Any]) -> None:
    inflight, handshake = split_pending(case["pending"])
    assert classify_frame(case["frame"], inflight, handshake) == case["expect"]


@pytest.mark.parametrize("case", HOST_CASES, ids=[c["name"] for c in HOST_CASES])
def test_host_config_vector(case: dict[str, Any], tmp_path: Path) -> None:
    lock_root = build_host_layout(case, tmp_path)
    problem = host_path_problem(
        lock_root,
        {key: (tmp_path / case[key]) if case.get(key) is not None else None for key in ("sequencePath", "trustedRoot")},
    )
    assert ("refuse" if problem else "accept") == case["expect"], problem


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
