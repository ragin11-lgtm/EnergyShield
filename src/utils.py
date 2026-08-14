"""Shared orchestration and display helpers for the CLI and dashboard."""

from __future__ import annotations

from collections import Counter
from typing import Any

from src.detection_engine import run_detections
from src.incident_response import add_response_guidance
from src.mitre_mapping import add_mitre_mappings
from src.risk_engine import add_risk_scores


def analyze_security_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run detection, risk, ATT&CK, and response enrichment in order."""

    detections = run_detections(events)
    add_risk_scores(detections)
    add_mitre_mappings(detections)
    add_response_guidance(detections)
    return detections


def build_summary(
    events: list[dict[str, Any]], detections: list[dict[str, Any]]
) -> dict[str, int]:
    """Calculate the headline SOC metrics used by both interfaces."""

    severity_counts = Counter(detection["severity"] for detection in detections)
    high_risk_hosts = {
        detection["affected_host"]
        for detection in detections
        if detection["risk_score"] >= 61
    }
    privileged_alerts = sum(
        1
        for detection in detections
        if detection.get("event_data", {}).get("privileged_account")
        or detection.get("rule_id") in {"AUTH-002", "PRIV-001"}
    )
    return {
        "total_events": len(events),
        "active_alerts": len(detections),
        "critical_alerts": severity_counts["CRITICAL"],
        "high_risk_systems": len(high_risk_hosts),
        "privileged_alerts": privileged_alerts,
    }
