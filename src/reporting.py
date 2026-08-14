"""Generate readable Markdown incident reports from selected alerts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.config import REPORTS_DIRECTORY


def _numbered_lines(items: list[str]) -> str:
    """Format response steps as a Markdown numbered list."""

    return "\n".join(f"{number}. {item}" for number, item in enumerate(items, start=1))


def build_incident_report(detection: dict[str, Any]) -> str:
    """Build report text without writing a file (useful for tests and downloads)."""

    response = detection.get("response_playbook", {})
    risk_factors = detection.get("risk_factors", [])
    risk_explanation = "\n".join(f"- {factor}" for factor in risk_factors)
    mitre_mapping = (
        f"{detection.get('mitre_tactic', 'Needs verification')} — "
        f"{detection.get('mitre_technique', 'Needs verification')} "
        f"({detection.get('mitre_technique_id', 'Needs verification')})"
    )

    return f"""# ENERGYSHIELD SECURITY INCIDENT REPORT

> **Simulation notice:** This report contains fictional events for defensive
> cybersecurity education. Follow approved organizational procedures in a real incident.

## Incident Summary

| Field | Value |
|---|---|
| Incident ID | {detection.get("alert_id", "Unknown")} |
| Timestamp | {detection.get("timestamp", "Unknown")} |
| Severity | {detection.get("severity", "Unknown")} |
| Risk Score | {detection.get("risk_score", 0)}/100 ({detection.get("risk_level", "Unknown")}) |
| Detection Name | {detection.get("rule_name", "Unknown")} |
| Affected User | {detection.get("affected_user", "Unknown")} |
| Affected System | {detection.get("affected_host", "Unknown")} |
| Source IP | {detection.get("source_ip", "Unknown")} |

## Event Description

{detection.get("description", "No description available.")}

## Why the Alert Triggered

{detection.get("why_triggered", "No rule explanation available.")}

## Risk-Score Explanation

{risk_explanation or "- No factors recorded."}

## MITRE ATT&CK Mapping

{mitre_mapping}

## Recommended Investigation Steps

{_numbered_lines(response.get("investigation", ["Review the alert evidence."]))}

## Recommended Containment Actions

{_numbered_lines(response.get("containment", ["Follow approved incident procedures."]))}

---

{response.get("safety_note", "This project is a simulated learning environment.")}
"""


def save_incident_report(
    detection: dict[str, Any], output_directory: str | Path = REPORTS_DIRECTORY
) -> Path:
    """Save a selected alert as Markdown and return its path."""

    directory = Path(output_directory)
    directory.mkdir(parents=True, exist_ok=True)
    safe_incident_id = "".join(
        character
        for character in str(detection.get("alert_id", "UNKNOWN"))
        if character.isalnum() or character in {"-", "_"}
    )
    report_path = directory / f"{safe_incident_id}_incident_report.md"
    report_path.write_text(build_incident_report(detection), encoding="utf-8")
    return report_path

