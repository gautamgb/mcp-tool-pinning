from pathlib import Path

from mcp_tool_pinning.store import Pin, PinStore


def test_round_trip_and_no_temp_files_left(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    PinStore(path).put(
        "t",
        Pin(digest="sha256:" + "a" * 64, definition={"name": "t", "description": "é"}),
    )
    reloaded = PinStore(path).get("t")
    assert reloaded is not None and reloaded.definition["description"] == "é"
    assert [p.name for p in tmp_path.iterdir()] == ["pins.json"]


def test_tools_only_file_from_before_section_4_still_loads(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    path.write_text('{"tools": {"t": {"digest": "sha256:' + "b" * 64 + '", "definition": {"name": "t"}}}}')
    store = PinStore(path)
    assert store.get("t") is not None
    assert store.get("t", kind="prompts") is None
    store.put("p", Pin(digest="sha256:" + "c" * 64, definition={"name": "p"}), kind="prompts")
    reloaded = PinStore(path)
    assert reloaded.get("t") is not None and reloaded.get("p", kind="prompts") is not None
