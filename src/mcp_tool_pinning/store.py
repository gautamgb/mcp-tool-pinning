"""Pin store: one JSON file, written atomically.

Pins are kept per kind (tools, prompts, resource templates), each keyed by
name, so a prompt and a tool with the same name do not share a pin. A file
written before prompts and templates were pinned has only "tools" and loads
unchanged.

The host picks one path per server identity; nothing here binds a file to a
server, so two servers sharing a path share approvals.

POC limits: no locking for concurrent hosts and no tamper protection. Anyone
who can write this file can approve a definition (see the SEP's Security
Implications).
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

Kind = Literal["tools", "prompts", "resourceTemplates"]
KINDS: tuple[Kind, ...] = ("tools", "prompts", "resourceTemplates")


@dataclass(frozen=True)
class Pin:
    digest: str
    definition: dict[str, Any]


class PinStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._pins: dict[Kind, dict[str, Pin]] = {kind: {} for kind in KINDS}
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            for kind in KINDS:
                self._pins[kind] = {
                    name: Pin(digest=entry["digest"], definition=entry["definition"])
                    for name, entry in raw.get(kind, {}).items()
                }

    def get(self, name: str, *, kind: Kind = "tools") -> Pin | None:
        return self._pins[kind].get(name)

    def put(self, name: str, pin: Pin, *, kind: Kind = "tools") -> None:
        # Write first: if the write fails, memory still matches the file.
        updated = {**self._pins, kind: {**self._pins[kind], name: pin}}
        self._save(updated)
        self._pins = updated

    def _save(self, pins: dict[Kind, dict[str, Pin]]) -> None:
        payload = {
            kind: {
                name: {"digest": pin.digest, "definition": pin.definition}
                for name, pin in sorted(pins[kind].items())
            }
            for kind in KINDS
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".pins-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            os.unlink(tmp)
            raise
