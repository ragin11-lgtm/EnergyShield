"""Tests for valid, missing, malformed, and empty event input."""

import json

import pytest

from src.log_loader import LogLoadError, load_event_file


def test_valid_event_loading(tmp_path) -> None:
    event_file = tmp_path / "events.json"
    event_file.write_text(
        json.dumps(
            [
                {
                    "event_id": "TEST-001",
                    "timestamp": "2026-06-15T12:00:00+00:00",
                    "event_type": "failed_login",
                    "failed_logins": "12",
                }
            ]
        ),
        encoding="utf-8",
    )

    events, warnings = load_event_file(event_file)

    assert len(events) == 1
    assert events[0]["failed_logins"] == 12
    assert events[0]["username"] == "Unknown"
    assert warnings == []


def test_invalid_numeric_value_uses_safe_default(tmp_path) -> None:
    event_file = tmp_path / "events.json"
    event_file.write_text(
        json.dumps(
            [
                {
                    "event_id": "TEST-002",
                    "timestamp": "2026-06-15T12:00:00+00:00",
                    "event_type": "failed_login",
                    "failed_logins": "many",
                    "destination_port": "not-a-port",
                }
            ]
        ),
        encoding="utf-8",
    )

    events, warnings = load_event_file(event_file)

    assert events[0]["failed_logins"] == 0
    assert events[0]["destination_port"] is None
    assert len(warnings) == 2


def test_invalid_json_has_clear_error(tmp_path) -> None:
    event_file = tmp_path / "invalid.json"
    event_file.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(LogLoadError, match="Invalid JSON"):
        load_event_file(event_file)


def test_empty_file_has_clear_error(tmp_path) -> None:
    event_file = tmp_path / "empty.json"
    event_file.write_text("", encoding="utf-8")

    with pytest.raises(LogLoadError, match="empty"):
        load_event_file(event_file)


def test_non_object_items_are_skipped(tmp_path) -> None:
    event_file = tmp_path / "mixed.json"
    event_file.write_text(
        json.dumps(
            [
                "bad item",
                {
                    "event_id": "TEST-003",
                    "timestamp": "2026-06-15T12:00:00+00:00",
                    "event_type": "successful_login",
                },
            ]
        ),
        encoding="utf-8",
    )

    events, warnings = load_event_file(event_file)

    assert len(events) == 1
    assert "skipped" in warnings[0]

