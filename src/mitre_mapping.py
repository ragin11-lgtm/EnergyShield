"""Conservative MITRE ATT&CK mappings for analyst education.

Mappings here use official Enterprise ATT&CK technique identifiers. Generic
events that do not justify a specific mapping are explicitly marked for review.
"""

from __future__ import annotations

from typing import Any


MITRE_MAPPINGS: dict[str, dict[str, str]] = {
    "AUTH-001": {
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "mitre_technique_id": "T1110",
    },
    "AUTH-002": {
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "mitre_technique_id": "T1110",
    },
    "AUTH-003": {
        "mitre_tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "mitre_technique": "Valid Accounts",
        "mitre_technique_id": "T1078",
    },
    "AUTH-004": {
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "mitre_technique_id": "T1110",
    },
    "NET-001": {
        "mitre_tactic": "Discovery",
        "mitre_technique": "Network Service Scanning",
        "mitre_technique_id": "T1046",
    },
    "NET-003": {
        "mitre_tactic": "Discovery",
        "mitre_technique": "Network Service Scanning",
        "mitre_technique_id": "T1046",
    },
    "PRIV-001": {
        "mitre_tactic": "Persistence / Privilege Escalation",
        "mitre_technique": "Account Manipulation",
        "mitre_technique_id": "T1098",
    },
}

UNVERIFIED_MAPPING = {
    "mitre_tactic": "Needs verification",
    "mitre_technique": "Needs verification",
    "mitre_technique_id": "Needs verification",
}


def add_mitre_mappings(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach a verified mapping or an honest verification placeholder."""

    for detection in detections:
        mapping = MITRE_MAPPINGS.get(detection.get("rule_id"), UNVERIFIED_MAPPING)
        detection.update(mapping)
    return detections

