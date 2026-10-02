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
