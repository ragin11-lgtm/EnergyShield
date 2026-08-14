"""Readable, rule-based detections for fictional EnergyShield events."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable

from src import config
from src.models import Detection


def _is_privileged(event: dict[str, Any]) -> bool:
    """Check both the event flag and the configurable username list."""

    username = str(event.get("username", "")).lower()
    return bool(event.get("privileged_account")) or username in config.PRIVILEGED_USERNAMES


def classify_failed_login_count(failed_logins: int) -> str:
    """Classify a failed-login count without necessarily creating an alert.

    Normal activity stays available for analysis but does not become an active
    SOC alert. This prevents the dashboard from treating every harmless typo as
    an incident.
    """

    if failed_logins >= config.CRITICAL_FAILED_LOGINS:
        return "CRITICAL"
    if failed_logins >= config.WARNING_FAILED_LOGINS:
        return "WARNING"
    return "NORMAL"


def _parse_timestamp(timestamp: str) -> datetime | None:
    """Parse an ISO timestamp, returning None instead of crashing."""

    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None


def _new_detection(
    event: dict[str, Any],
    alert_number: int,
    rule_id: str,
    rule_name: str,
    severity: str,
    description: str,
    why_triggered: str,
    related_event_ids: list[str] | None = None,
    event_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one consistently shaped detection dictionary."""

    detection = Detection(
        alert_id=f"ES-ALERT-{alert_number:04d}",
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        description=description,
        affected_user=str(event.get("username", "Unknown")),
        affected_host=str(event.get("hostname", "Unknown")),
        source_ip=str(event.get("source_ip", "Unknown")),
        timestamp=str(event.get("timestamp", "Unknown")),
        event_type=str(event.get("event_type", "unknown")),
        why_triggered=why_triggered,
        related_event_ids=related_event_ids or [str(event.get("event_id", "Unknown"))],
        event_data=event_data or dict(event),
    )
    return detection.to_dict()


def detect_login_activity(
    events: list[dict[str, Any]], start_number: int = 1
) -> list[dict[str, Any]]:
    """Detect failed-login thresholds and suspicious authentication activity."""

    detections: list[dict[str, Any]] = []
    alert_number = start_number

    for event in events:
        event_type = str(event.get("event_type", "")).lower()
        failed_logins = int(event.get("failed_logins", 0) or 0)
        is_login_event = event_type in {
            "failed_login",
            "repeated_failed_logins",
            "privileged_login_failure",
        }

        login_classification = classify_failed_login_count(failed_logins)

        if is_login_event and login_classification == "CRITICAL":
            detections.append(
                _new_detection(
                    event,
                    alert_number,
                    "AUTH-001",
                    "Possible Brute-Force Attack",
                    "CRITICAL",
                    "A large number of failed logins may indicate password guessing.",
                    f"Failed login count ({failed_logins}) met or exceeded the critical "
                    f"threshold ({config.CRITICAL_FAILED_LOGINS}).",
                )
            )
            alert_number += 1
        elif is_login_event and login_classification == "WARNING":
            detections.append(
                _new_detection(
                    event,
                    alert_number,
                    "AUTH-001",
                    "Repeated Failed Logins",
                    "WARNING",
                    "Repeated authentication failures require analyst review.",
                    f"Failed login count ({failed_logins}) met or exceeded the warning "
                    f"threshold ({config.WARNING_FAILED_LOGINS}).",
                )
            )
            alert_number += 1

        if (
            is_login_event
            and failed_logins >= config.WARNING_FAILED_LOGINS
            and _is_privileged(event)
        ):
            detections.append(
                _new_detection(
                    event,
                    alert_number,
                    "AUTH-002",
                    "Privileged Account Under Possible Attack",
                    "CRITICAL",
                    "Repeated failures targeted an account with elevated access.",
                    f"The account is privileged and recorded {failed_logins} failed logins; "
                    f"the privileged-account threshold is {config.WARNING_FAILED_LOGINS}.",
                )
            )
            alert_number += 1

        if event_type == "suspicious_login_outside_hours":
            detections.append(
                _new_detection(
                    event,
                    alert_number,
                    "AUTH-003",
                    "Login Outside Normal Hours",
                    "WARNING",
                    "A successful login occurred outside the fictional normal work schedule.",
                    "The event generator labeled this login as outside normal hours. This is "
                    "context for review, not proof of compromise.",
                )
            )
            alert_number += 1

        if event_type == "account_lockout":
            detections.append(
                _new_detection(
                    event,
                    alert_number,
                    "AUTH-004",
                    "Account Lockout",
                    "WARNING",
                    "An account was locked after repeated authentication failures.",
                    "The source event recorded an account_lockout action.",
                )
            )
            alert_number += 1

    return detections


def _best_source_window(
    source_events: list[dict[str, Any]],
    value_getter: Callable[[dict[str, Any]], Any],
) -> tuple[list[dict[str, Any]], set[Any]]:
    """Find the five-minute window with the most distinct ports or hosts."""

    timed_events = [
        (parsed, event)
        for event in source_events
        if (parsed := _parse_timestamp(str(event.get("timestamp", "")))) is not None
    ]
    timed_events.sort(key=lambda item: item[0])
    best_events: list[dict[str, Any]] = []
    best_values: set[Any] = set()

    for start_index, (start_time, _) in enumerate(timed_events):
        end_time = start_time + timedelta(minutes=config.NETWORK_TIME_WINDOW_MINUTES)
        window_events = [
            event
            for event_time, event in timed_events[start_index:]
            if event_time <= end_time
        ]
        values = {
            value_getter(event)
            for event in window_events
            if value_getter(event) not in (None, "", "Unknown")
        }
        if len(values) > len(best_values):
            best_events = window_events
            best_values = values

    return best_events, best_values


def detect_network_activity(
    events: list[dict[str, Any]], start_number: int = 1
) -> list[dict[str, Any]]:
    """Detect unusual ports, port scans, and rapid contact with many hosts."""

    detections: list[dict[str, Any]] = []
    alert_number = start_number
    network_events = [
        event
        for event in events
        if event.get("destination_port") is not None
        or event.get("event_type") in {"network_connection", "port_scan"}
    ]

    for event in network_events:
        port = event.get("destination_port")
        if port in config.UNUSUAL_PORTS:
            detections.append(
                _new_detection(
                    event,
                    alert_number,
                    "NET-002",
                    "Connection to Unusual Port",
                    "WARNING",
                    "A connection used a port designated for review in this lab.",
                    f"Destination port {port} is in the configurable unusual-port set. "
                    "The port alone does not prove malicious activity.",
                )
            )
            alert_number += 1

    events_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in network_events:
        source_ip = str(event.get("source_ip", "Unknown"))
        if source_ip != "Unknown":
            events_by_source[source_ip].append(event)

    for source_ip, source_events in events_by_source.items():
        port_window, distinct_ports = _best_source_window(
            source_events, lambda event: event.get("destination_port")
        )
        if len(distinct_ports) >= config.PORT_SCAN_THRESHOLD:
            representative = port_window[0]
            severity = (
                "CRITICAL"
                if len(distinct_ports) >= config.CRITICAL_PORT_SCAN_THRESHOLD
                else "WARNING"
            )
            evidence = dict(representative)
            evidence["distinct_ports"] = len(distinct_ports)
            detections.append(
                _new_detection(
                    representative,
                    alert_number,
                    "NET-001",
                    "Possible Port Scan Detected",
                    severity,
                    "One source contacted many destination ports in a short window.",
                    f"Source {source_ip} contacted {len(distinct_ports)} distinct ports within "
                    f"{config.NETWORK_TIME_WINDOW_MINUTES} minutes; the threshold is "
                    f"{config.PORT_SCAN_THRESHOLD}.",
                    [str(event.get("event_id", "Unknown")) for event in port_window],
                    evidence,
                )
            )
            alert_number += 1

        host_window, distinct_hosts = _best_source_window(
            source_events, lambda event: event.get("hostname")
        )
        if len(distinct_hosts) >= config.MULTI_HOST_THRESHOLD:
            representative = host_window[0]
            evidence = dict(representative)
            evidence["distinct_hosts"] = len(distinct_hosts)
            detections.append(
                _new_detection(
                    representative,
                    alert_number,
                    "NET-003",
                    "Possible Reconnaissance or Lateral Movement",
                    "HIGH",
                    "One source rapidly contacted several fictional systems.",
                    f"Source {source_ip} contacted {len(distinct_hosts)} distinct systems within "
                    f"{config.NETWORK_TIME_WINDOW_MINUTES} minutes; the threshold is "
                    f"{config.MULTI_HOST_THRESHOLD}.",
                    [str(event.get("event_id", "Unknown")) for event in host_window],
                    evidence,
                )
            )
            alert_number += 1

    return detections


def detect_security_activity(
    events: list[dict[str, Any]], start_number: int = 1
) -> list[dict[str, Any]]:
    """Detect malware, unauthorized access, and privilege changes."""

    detections: list[dict[str, Any]] = []
    alert_number = start_number
    rules = {
        "unauthorized_access_attempt": (
            "ACCESS-001",
            "Unauthorized Access Attempt",
            "HIGH",
            "An access attempt was denied by the fictional system.",
        ),
        "new_admin_privilege": (
            "PRIV-001",
            "Unauthorized Administrator Privilege Change",
            "CRITICAL",
            "A new administrator privilege assignment requires authorization review.",
        ),
        "malware_detection": (
            "MAL-001",
            "Simulated Malware Detection",
            "CRITICAL",
            "A fictional endpoint control reported a malware signature.",
        ),
    }

    for event in events:
        event_type = str(event.get("event_type", "")).lower()
        if event_type not in rules:
            continue
        rule_id, rule_name, severity, description = rules[event_type]
        detections.append(
            _new_detection(
                event,
                alert_number,
                rule_id,
                rule_name,
                severity,
                description,
                f"The event type was {event_type!r}, which matches rule {rule_id}.",
            )
        )
        alert_number += 1

    return detections


def run_detections(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run every rule family and return alerts ordered by timestamp."""

    login_detections = detect_login_activity(events)
    network_detections = detect_network_activity(
        events, start_number=len(login_detections) + 1
    )
    security_detections = detect_security_activity(
        events, start_number=len(login_detections) + len(network_detections) + 1
    )
    detections = login_detections + network_detections + security_detections
    detections.sort(key=lambda detection: detection["timestamp"], reverse=True)
    return detections
