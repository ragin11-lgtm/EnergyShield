"""Load and validate fictional EnergyShield JSON security events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.models import SecurityEvent


class LogLoadError(ValueError):
    """An understandable error raised when an event file cannot be used."""


def _safe_integer(value: Any, field_name: str, event_id: str) -> tuple[int, str | None]:
    """Convert a value to an integer without crashing on malformed data."""

    if value in (None, ""):
        return 0, None
    try:
        return int(value), None
    except (TypeError, ValueError):
        warning = f"{event_id}: invalid {field_name!r} value {value!r}; using 0"
        return 0, warning


def normalize_event(raw_event: dict[str, Any], position: int) -> tuple[dict[str, Any], list[str]]:
    """Apply safe defaults and basic type conversion to one event dictionary."""

    warnings: list[str] = []
    event_id = str(raw_event.get("event_id") or f"MISSING-ID-{position}")

    failed_logins, failed_warning = _safe_integer(
        raw_event.get("failed_logins", 0), "failed_logins", event_id
    )
    if failed_warning:
        warnings.append(failed_warning)

    raw_port = raw_event.get("destination_port")
    destination_port: int | None = None
    if raw_port not in (None, ""):
        try:
            destination_port = int(raw_port)
        except (TypeError, ValueError):
            warnings.append(
                f"{event_id}: invalid 'destination_port' value {raw_port!r}; using null"
            )

    privileged_value = raw_event.get("privileged_account", False)
    if isinstance(privileged_value, str):
        privileged_account = privileged_value.strip().lower() in {"true", "1", "yes"}
    else:
        privileged_account = bool(privileged_value)

    event = SecurityEvent(
        event_id=event_id,
        timestamp=str(raw_event.get("timestamp") or "Unknown"),
        event_type=str(raw_event.get("event_type") or "unknown"),
        username=str(raw_event.get("username") or "Unknown"),
        source_ip=str(raw_event.get("source_ip") or "Unknown"),
        destination_ip=str(raw_event.get("destination_ip") or "Unknown"),
        hostname=str(raw_event.get("hostname") or "Unknown"),
        system_type=str(raw_event.get("system_type") or "Unknown"),
        failed_logins=max(failed_logins, 0),
        destination_port=destination_port,
        action=str(raw_event.get("action") or "unknown"),
        privileged_account=privileged_account,
        severity=str(raw_event.get("severity") or "INFO").upper(),
        message=str(raw_event.get("message") or "No event message supplied."),
    )
    return event.to_dict(), warnings


def load_event_file(file_path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load one JSON array and return normalized events plus non-fatal warnings."""

    path = Path(file_path)
    if not path.exists():
        raise LogLoadError(f"Event file was not found: {path}")
    if path.stat().st_size == 0:
        raise LogLoadError(f"Event file is empty: {path}")

    try:
        with path.open("r", encoding="utf-8") as event_file:
            raw_data = json.load(event_file)
    except json.JSONDecodeError as error:
        raise LogLoadError(
            f"Invalid JSON in {path.name} near line {error.lineno}: {error.msg}"
        ) from error
    except OSError as error:
        raise LogLoadError(f"Could not read {path}: {error}") from error

    if not isinstance(raw_data, list):
        raise LogLoadError(f"{path.name} must contain a JSON list of event objects.")
    if not raw_data:
        raise LogLoadError(f"Event file contains no events: {path}")

    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    for position, raw_event in enumerate(raw_data, start=1):
        if not isinstance(raw_event, dict):
            warnings.append(f"{path.name} item {position}: skipped because it is not an object")
            continue
        normalized_event, event_warnings = normalize_event(raw_event, position)
        events.append(normalized_event)
        warnings.extend(event_warnings)

    if not events:
        raise LogLoadError(f"{path.name} did not contain any valid event objects.")
    return events, warnings


def load_all_events(data_directory: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load the three sample log files used by the CLI and dashboard."""

    directory = Path(data_directory)
    expected_files = (
        "sample_logins.json",
        "sample_network_events.json",
        "sample_security_events.json",
    )
    all_events: list[dict[str, Any]] = []
    all_warnings: list[str] = []
    for file_name in expected_files:
        events, warnings = load_event_file(directory / file_name)
        all_events.extend(events)
        all_warnings.extend(warnings)

    all_events.sort(key=lambda event: event["timestamp"])
    return all_events, all_warnings

