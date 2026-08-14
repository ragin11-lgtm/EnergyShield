"""Tests for EnergyShield's understandable rule logic."""

from datetime import datetime, timedelta, timezone

from src.detection_engine import (
    classify_failed_login_count,
    detect_login_activity,
    detect_network_activity,
)


def login_event(failed_logins: int, privileged: bool = False) -> dict:
    """Return the smallest realistic event needed by login tests."""

    return {
        "event_id": "TEST-LOGIN-001",
        "timestamp": "2026-06-15T12:00:00+00:00",
        "event_type": "failed_login",
        "username": "test.admin" if privileged else "student.user",
        "source_ip": "192.0.2.10",
        "hostname": "CORP-SERVER-01",
        "system_type": "corporate_server",
        "failed_logins": failed_logins,
        "privileged_account": privileged,
    }


def test_failed_login_below_threshold_is_normal() -> None:
    assert detect_login_activity([login_event(9)]) == []
    assert classify_failed_login_count(9) == "NORMAL"


def test_failed_login_warning_threshold() -> None:
    detections = detect_login_activity([login_event(10)])

    assert len(detections) == 1
    assert detections[0]["rule_id"] == "AUTH-001"
    assert detections[0]["severity"] == "WARNING"
    assert classify_failed_login_count(10) == "WARNING"


def test_failed_login_critical_threshold() -> None:
    detections = detect_login_activity([login_event(20)])

    assert len(detections) == 1
    assert detections[0]["rule_name"] == "Possible Brute-Force Attack"
    assert detections[0]["severity"] == "CRITICAL"
    assert classify_failed_login_count(20) == "CRITICAL"


def test_privileged_account_generates_extra_alert() -> None:
    detections = detect_login_activity([login_event(10, privileged=True)])
    rule_ids = {detection["rule_id"] for detection in detections}

    assert rule_ids == {"AUTH-001", "AUTH-002"}


def test_port_scan_detection() -> None:
    start = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)
    events = []
    for index in range(10):
        events.append(
            {
                "event_id": f"TEST-NET-{index:03d}",
                "timestamp": (start + timedelta(seconds=index * 10)).isoformat(),
                "event_type": "network_connection",
                "source_ip": "198.51.100.12",
                "destination_ip": "10.30.10.10",
                "destination_port": 1000 + index,
                "hostname": "SOLAR-SCADA-01",
                "system_type": "solar_scada",
                "username": "Unknown",
                "privileged_account": False,
            }
        )

    detections = detect_network_activity(events)

    assert any(detection["rule_id"] == "NET-001" for detection in detections)


def test_multi_host_contact_detection() -> None:
    start = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)
    events = [
        {
            "event_id": f"TEST-HOST-{index:03d}",
            "timestamp": (start + timedelta(seconds=index * 15)).isoformat(),
            "event_type": "network_connection",
            "source_ip": "203.0.113.20",
            "destination_port": 443,
            "hostname": f"LAB-SYSTEM-{index}",
            "system_type": "lab_system",
            "username": "test.user",
            "privileged_account": False,
        }
        for index in range(5)
    ]

    detections = detect_network_activity(events)

    assert any(detection["rule_id"] == "NET-003" for detection in detections)
