"""Command-line entry point for the EnergyShield monitoring lab."""

from __future__ import annotations

import sys
from typing import Any

from src.config import DATA_DIRECTORY
from src.log_loader import LogLoadError, load_all_events
from src.utils import analyze_security_events, build_summary


DIVIDER = "=" * 65


def print_alert(detection: dict[str, Any]) -> None:
    """Print one SOC-style alert using beginner-friendly string formatting."""

    event = detection.get("event_data", {})
    print(f"\n[{detection['severity']}] {detection['rule_name']}")
    print(f"Alert ID: {detection['alert_id']}")
    print(f"User: {detection['affected_user']}")
    print(f"Source IP: {detection['source_ip']}")
    print(f"System: {detection['affected_host']}")
    if event.get("failed_logins"):
        print(f"Failed Logins: {event['failed_logins']}")
    print(f"Risk Score: {detection['risk_score']}/100 ({detection['risk_level']})")
    print(
        "MITRE ATT&CK: "
        f"{detection['mitre_technique']} ({detection['mitre_technique_id']})"
    )
    print(f"Why: {detection['why_triggered']}")
    print("\nRecommended Action:")
    print(detection["recommended_action"])
    print("-" * 65)


def main() -> int:
    """Load events, analyze them, and display a readable security summary."""

    print(DIVIDER)
    print("ENERGYSHIELD SECURITY MONITOR")
    print("Fictional energy infrastructure — defensive simulation only")
    print(DIVIDER)

    try:
        events, warnings = load_all_events(DATA_DIRECTORY)
    except LogLoadError as error:
        print(f"\nCould not start monitoring: {error}", file=sys.stderr)
        return 1

    for warning in warnings:
        print(f"Data warning: {warning}", file=sys.stderr)

    detections = analyze_security_events(events)
    summary = build_summary(events, detections)
    print(f"\nEvents analyzed: {summary['total_events']}")
    print(f"Alerts generated: {summary['active_alerts']}")
    print(f"Critical alerts: {summary['critical_alerts']}")
    print(f"High-risk systems: {summary['high_risk_systems']}")

    for detection in detections:
        print_alert(detection)

    print("\nSimulation complete. No real systems were contacted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

