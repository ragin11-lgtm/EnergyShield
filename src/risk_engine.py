"""Deterministic and interview-friendly EnergyShield risk scoring."""

from __future__ import annotations

from typing import Any

from src.config import CRITICAL_SYSTEM_LABELS, PRIVILEGED_USERNAMES, RISK_BANDS


SEVERITY_BASE_SCORES = {
    "INFO": 10,
    "LOW": 25,
    "WARNING": 45,
    "MEDIUM": 45,
    "HIGH": 65,
    "CRITICAL": 80,
}


def is_critical_system(hostname: str, system_type: str = "") -> bool:
    """Return True when an event concerns a fictional OT/critical system."""

    searchable_text = f"{hostname} {system_type}".upper()
    return any(label in searchable_text for label in CRITICAL_SYSTEM_LABELS)


def risk_level_for_score(score: int) -> str:
    """Translate a 0-100 score to its documented risk band."""

    for maximum_score, label in RISK_BANDS:
        if score <= maximum_score:
            return label
    return "CRITICAL"


def calculate_risk_score(detection: dict[str, Any]) -> tuple[int, str, list[str]]:
    """Calculate risk using visible additive factors, capped at 100."""

    event = detection.get("event_data", {})
    severity = str(detection.get("severity", "INFO")).upper()
    score = SEVERITY_BASE_SCORES.get(severity, 10)
    factors = [f"{severity} alert base score: +{score}"]

    username = str(detection.get("affected_user", "")).lower()
    if event.get("privileged_account") or username in PRIVILEGED_USERNAMES:
        score += 10
        factors.append("Privileged account involved: +10")

    if is_critical_system(
        str(detection.get("affected_host", "")), str(event.get("system_type", ""))
    ):
        score += 10
        factors.append("Fictional critical/OT system involved: +10")

    failed_logins = int(event.get("failed_logins", 0) or 0)
    if failed_logins >= 20:
        score += 10
        factors.append("20 or more failed logins: +10")
    elif failed_logins >= 10:
        score += 5
        factors.append("10-19 failed logins: +5")

    if detection.get("rule_id") == "MAL-001":
        score += 10
        factors.append("Simulated malware alert: +10")

    if detection.get("rule_id") == "PRIV-001":
        score += 10
        factors.append("Administrator privilege change: +10")

    related_events = detection.get("related_event_ids", [])
    if len(related_events) >= 3:
        score += 5
        factors.append("Three or more related events from the source: +5")

    final_score = min(score, 100)
    if final_score < score:
        factors.append("Score capped at 100")
    return final_score, risk_level_for_score(final_score), factors


def add_risk_scores(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add risk score, risk band, and explanation to each alert."""

    for detection in detections:
        score, level, factors = calculate_risk_score(detection)
        detection["risk_score"] = score
        detection["risk_level"] = level
        detection["risk_factors"] = factors
    return detections
