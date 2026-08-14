"""Generate EnergyShield's deterministic, entirely fictional sample events.

Run this script after changing fixture design:

    python scripts/generate_sample_data.py

All addresses are private or documentation-only ranges. The script never opens a
network connection and never interacts with a real system.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIRECTORY = PROJECT_ROOT / "data"
BASE_TIME = datetime(2026, 6, 15, 8, 0, tzinfo=timezone.utc)

SYSTEMS = [
    ("CORP-LAPTOP-01", "corporate_workstation", "10.20.10.11"),
    ("CORP-SERVER-01", "corporate_server", "10.20.20.10"),
    ("SOLAR-SCADA-01", "solar_scada", "10.30.10.10"),
    ("WIND-SCADA-01", "wind_scada", "10.30.20.10"),
    ("BESS-CONTROLLER-01", "bess_controller", "10.30.30.10"),
    ("SUBSTATION-HMI-01", "substation_hmi", "10.30.40.10"),
    ("OPERATIONS-SERVER-01", "operations_server", "10.30.50.10"),
]


def iso(minutes: int = 0, seconds: int = 0, hours: int = 0) -> str:
    """Return a stable ISO-8601 timestamp for the fixture."""

    return (BASE_TIME + timedelta(hours=hours, minutes=minutes, seconds=seconds)).isoformat()


def base_event(
    event_id: str,
    timestamp: str,
    event_type: str,
    hostname: str,
    system_type: str,
    destination_ip: str,
    message: str,
    **extra_fields: Any,
) -> dict[str, Any]:
    """Create the common fields shared by every sample event."""

    event = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "hostname": hostname,
        "system_type": system_type,
        "destination_ip": destination_ip,
        "severity": "INFO",
        "message": message,
    }
    event.update(extra_fields)
    return event


def build_login_events() -> list[dict[str, Any]]:
    """Create 30 authentication events with both normal and suspicious behavior."""

    events: list[dict[str, Any]] = []
    users = ["alex.chen", "maria.santos", "jordan.lee", "priya.patel"]

    for index in range(12):
        hostname, system_type, destination_ip = SYSTEMS[index % len(SYSTEMS)]
        events.append(
            base_event(
                f"LOGIN-{index + 1:03d}",
                iso(minutes=index * 11),
                "successful_login",
                hostname,
                system_type,
                destination_ip,
                "User successfully authenticated from an expected private address.",
                username=users[index % len(users)],
                source_ip=f"10.20.10.{30 + index}",
                failed_logins=0,
                action="allowed",
                privileged_account=False,
            )
        )

    for index in range(8):
        hostname, system_type, destination_ip = SYSTEMS[index % 2]
        failed_count = (index % 9) + 1
        events.append(
            base_event(
                f"LOGIN-{index + 13:03d}",
                iso(hours=3, minutes=index * 7),
                "failed_login",
                hostname,
                system_type,
                destination_ip,
                "A small number of failed logins was recorded.",
                username=users[index % len(users)],
                source_ip=f"10.20.10.{60 + index}",
                failed_logins=failed_count,
                action="denied",
                privileged_account=False,
            )
        )

    suspicious_events = [
        base_event(
            "LOGIN-021", iso(hours=5), "repeated_failed_logins",
            "CORP-SERVER-01", "corporate_server", "10.20.20.10",
            "Repeated failures targeted a corporate user.",
            username="jordan.lee", source_ip="192.0.2.20", failed_logins=12,
            action="denied", privileged_account=False, severity="WARNING",
        ),
        base_event(
            "LOGIN-022", iso(hours=5, minutes=10), "privileged_login_failure",
            "SOLAR-SCADA-01", "solar_scada", "10.30.10.10",
            "Many failures targeted a fictional privileged solar monitoring account.",
            username="admin", source_ip="192.0.2.25", failed_logins=27,
            action="denied", privileged_account=True, severity="CRITICAL",
        ),
        base_event(
            "LOGIN-023", iso(hours=5, minutes=20), "privileged_login_failure",
            "SUBSTATION-HMI-01", "substation_hmi", "10.30.40.10",
            "Failures targeted a privileged HMI monitoring account.",
            username="scada_admin", source_ip="198.51.100.44", failed_logins=14,
            action="denied", privileged_account=True, severity="CRITICAL",
        ),
        base_event(
            "LOGIN-024", iso(hours=5, minutes=30), "account_lockout",
            "CORP-LAPTOP-01", "corporate_workstation", "10.20.10.11",
            "The identity service locked a user after repeated failures.",
            username="kevin.tan", source_ip="192.0.2.55", failed_logins=9,
            action="account_locked", privileged_account=False, severity="WARNING",
        ),
        base_event(
            "LOGIN-025", iso(hours=18, minutes=12), "suspicious_login_outside_hours",
            "WIND-SCADA-01", "wind_scada", "10.30.20.10",
            "A fictional operator login occurred outside normal lab hours.",
            username="wind.operator", source_ip="10.20.10.77", failed_logins=0,
            action="allowed", privileged_account=False, severity="WARNING",
        ),
        base_event(
            "LOGIN-026", iso(hours=6), "successful_login",
            "OPERATIONS-SERVER-01", "operations_server", "10.30.50.10",
            "An approved administrator login succeeded.",
            username="ot_engineer", source_ip="10.20.20.25", failed_logins=0,
            action="allowed", privileged_account=True,
        ),
        base_event(
            "LOGIN-027", iso(hours=6, minutes=10), "failed_login",
            "CORP-SERVER-01", "corporate_server", "10.20.20.10",
            "Two accidental password failures were recorded.",
            username="maria.santos", source_ip="10.20.10.42", failed_logins=2,
            action="denied", privileged_account=False,
        ),
        base_event(
            "LOGIN-028", iso(hours=6, minutes=20), "failed_login",
            "CORP-LAPTOP-01", "corporate_workstation", "10.20.10.11",
            "Nine failures remain below the warning threshold.",
            username="alex.chen", source_ip="10.20.10.43", failed_logins=9,
            action="denied", privileged_account=False,
        ),
        base_event(
            "LOGIN-029", iso(hours=6, minutes=30), "repeated_failed_logins",
            "BESS-CONTROLLER-01", "bess_controller", "10.30.30.10",
            "Twenty failures targeted a non-privileged monitoring account.",
            username="bess.viewer", source_ip="203.0.113.29", failed_logins=20,
            action="denied", privileged_account=False, severity="CRITICAL",
        ),
        base_event(
            "LOGIN-030", iso(hours=19, minutes=40), "suspicious_login_outside_hours",
            "CORP-SERVER-01", "corporate_server", "10.20.20.10",
            "A late-night corporate login requires contextual review.",
            username="priya.patel", source_ip="10.20.10.88", failed_logins=0,
            action="allowed", privileged_account=False, severity="WARNING",
        ),
    ]
    events.extend(suspicious_events)
    return events


def build_network_events() -> list[dict[str, Any]]:
    """Create 30 network events, including local scan and multi-host simulations."""

    events: list[dict[str, Any]] = []

    # Twenty port attempts from one documentation address occur within one minute.
    # No packets are sent; these are JSON records only.
    for index, port in enumerate(range(1000, 1020), start=1):
        events.append(
            base_event(
                f"NET-{index:03d}",
                iso(hours=8, seconds=index * 2),
                "port_scan",
                "SOLAR-SCADA-01",
                "solar_scada",
                "10.30.10.10",
                "Simulated connection attempt used for the port-scan rule.",
                username="Unknown",
                source_ip="192.0.2.25",
                destination_port=port,
                action="blocked",
                privileged_account=False,
                severity="WARNING",
            )
        )

    # A second documentation address rapidly contacts six fictional systems.
    for offset, (hostname, system_type, destination_ip) in enumerate(SYSTEMS[:6], start=21):
        events.append(
            base_event(
                f"NET-{offset:03d}",
                iso(hours=9, seconds=(offset - 20) * 20),
                "network_connection",
                hostname,
                system_type,
                destination_ip,
                "One source rapidly contacted several lab systems.",
                username="service_account",
                source_ip="198.51.100.77",
                destination_port=445,
                action="blocked",
                privileged_account=False,
                severity="WARNING",
            )
        )

    events.extend(
        [
            base_event(
                "NET-027", iso(hours=10), "network_connection",
                "CORP-LAPTOP-01", "corporate_workstation", "10.20.10.11",
                "A connection to a lab-designated unusual port requires review.",
                username="alex.chen", source_ip="10.20.10.44", destination_port=4444,
                action="blocked", privileged_account=False, severity="WARNING",
            ),
            base_event(
                "NET-028", iso(hours=10, minutes=15), "network_connection",
                "BESS-CONTROLLER-01", "bess_controller", "10.30.30.10",
                "Remote desktop traffic to an OT-labeled system requires validation.",
                username="vendor.support", source_ip="172.16.50.25", destination_port=3389,
                action="blocked", privileged_account=False, severity="WARNING",
            ),
            base_event(
                "NET-029", iso(hours=10, minutes=30), "network_connection",
                "CORP-SERVER-01", "corporate_server", "10.20.20.10",
                "Expected HTTPS connection from a corporate workstation.",
                username="maria.santos", source_ip="10.20.10.41", destination_port=443,
                action="allowed", privileged_account=False,
            ),
            base_event(
                "NET-030", iso(hours=10, minutes=45), "network_connection",
                "OPERATIONS-SERVER-01", "operations_server", "10.30.50.10",
                "Expected secure monitoring connection from the SOC subnet.",
                username="soc.analyst", source_ip="10.20.30.15", destination_port=443,
                action="allowed", privileged_account=False,
            ),
        ]
    )
    return events


def build_security_events() -> list[dict[str, Any]]:
    """Create 15 endpoint and access events."""

    events: list[dict[str, Any]] = []
    normal_types = [
        "endpoint_health",
        "antivirus_update",
        "configuration_check",
        "file_integrity_check",
        "backup_complete",
        "endpoint_health",
        "security_policy_sync",
        "asset_inventory",
    ]
    for index, event_type in enumerate(normal_types, start=1):
        hostname, system_type, destination_ip = SYSTEMS[index % len(SYSTEMS)]
        events.append(
            base_event(
                f"SEC-{index:03d}",
                iso(hours=11, minutes=index * 6),
                event_type,
                hostname,
                system_type,
                destination_ip,
                "Routine fictional security control activity completed successfully.",
                username="system",
                source_ip=destination_ip,
                action="allowed",
                privileged_account=False,
            )
        )

    suspicious_events = [
        (
            "unauthorized_access_attempt",
            "CORP-SERVER-01",
            "corporate_server",
            "10.20.20.10",
            "guest.user",
            "192.0.2.90",
            "Access to a restricted share was denied.",
        ),
        (
            "unauthorized_access_attempt",
            "SUBSTATION-HMI-01",
            "substation_hmi",
            "10.30.40.10",
            "contractor.temp",
            "198.51.100.91",
            "HMI monitoring access was denied.",
        ),
        (
            "unauthorized_access_attempt",
            "OPERATIONS-SERVER-01",
            "operations_server",
            "10.30.50.10",
            "service_account",
            "203.0.113.92",
            "Operations console access was denied.",
        ),
        (
            "new_admin_privilege",
            "CORP-SERVER-01",
            "corporate_server",
            "10.20.20.10",
            "contractor.temp",
            "10.20.10.99",
            "A new administrator role assignment was recorded.",
        ),
        (
            "new_admin_privilege",
            "SOLAR-SCADA-01",
            "solar_scada",
            "10.30.10.10",
            "solar.viewer",
            "10.20.10.98",
            "An unapproved elevated-role assignment was simulated.",
        ),
        (
            "malware_detection",
            "CORP-LAPTOP-01",
            "corporate_workstation",
            "10.20.10.11",
            "alex.chen",
            "10.20.10.11",
            "The fictional endpoint agent detected a test malware signature.",
        ),
        (
            "malware_detection",
            "WIND-SCADA-01",
            "wind_scada",
            "10.30.20.10",
            "wind.operator",
            "10.30.20.10",
            "A simulated malware alert was created for training.",
        ),
    ]
    for offset, event_fields in enumerate(suspicious_events, start=9):
        (
            event_type,
            hostname,
            system_type,
            destination_ip,
            username,
            source_ip,
            message,
        ) = event_fields
        events.append(
            base_event(
                f"SEC-{offset:03d}",
                iso(hours=12, minutes=offset * 5),
                event_type,
                hostname,
                system_type,
                destination_ip,
                message,
                username=username,
                source_ip=source_ip,
                action="blocked" if event_type != "new_admin_privilege" else "created",
                privileged_account=event_type == "new_admin_privilege",
                severity="CRITICAL" if event_type != "unauthorized_access_attempt" else "HIGH",
            )
        )
    return events


def write_events(file_name: str, events: list[dict[str, Any]]) -> None:
    """Write one pretty-printed sample JSON file."""

    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    output_path = DATA_DIRECTORY / file_name
    output_path.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(events):2d} events to {output_path.relative_to(PROJECT_ROOT)}")


def main() -> None:
    """Generate all three fixture files."""

    write_events("sample_logins.json", build_login_events())
    write_events("sample_network_events.json", build_network_events())
    write_events("sample_security_events.json", build_security_events())
    print("Generated 75 fictional events. No network activity occurred.")


if __name__ == "__main__":
    main()
