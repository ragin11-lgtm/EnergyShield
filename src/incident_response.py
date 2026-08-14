"""Defensive response guidance for simulated EnergyShield alerts."""

from __future__ import annotations

from typing import Any

from src.risk_engine import is_critical_system


SAFETY_NOTE = (
    "This guidance is for a simulated learning environment. Real organizations "
    "must follow their approved incident-response, safety, and change-control procedures."
)

PLAYBOOKS: dict[str, dict[str, list[str]]] = {
    "brute_force": {
        "investigation": [
            "Review authentication logs for the user and source IP.",
            "Confirm whether the targeted account and source are expected.",
            "Check MFA status and look for a successful login after the failures.",
            "Search for related authentication activity on other systems.",
        ],
        "containment": [
            "Temporarily restrict the source if approved policy allows.",
            "Reset credentials if account compromise is suspected.",
            "Escalate immediately when a privileged or OT account is involved.",
        ],
    },
    "privileged_attack": {
        "investigation": [
            "Validate the account owner and intended administrative activity.",
            "Review recent privileged sessions, MFA records, and access changes.",
            "Search the source IP across authentication and network logs.",
        ],
        "containment": [
            "Disable or restrict the account through the approved identity process.",
            "Revoke active sessions and rotate credentials if compromise is suspected.",
            "Notify the security and operations owners for affected critical systems.",
        ],
    },
    "port_scan": {
        "investigation": [
            "Confirm the number of ports, targets, and time window.",
            "Determine whether the source belongs to an approved scanner.",
            "Review firewall and endpoint logs for follow-on connections.",
        ],
        "containment": [
            "Block or rate-limit the source only if policy and evidence support it.",
            "Increase monitoring around the targeted network segment.",
        ],
    },
    "lateral_movement": {
        "investigation": [
            "List every system contacted by the source during the alert window.",
            "Check whether the activity matches approved administration or inventory work.",
            "Look for new logins, remote-service use, or access failures on each target.",
        ],
        "containment": [
            "Isolate the source endpoint if malicious activity is confirmed and policy permits.",
            "Restrict unnecessary east-west traffic using approved segmentation controls.",
        ],
    },
    "malware": {
        "investigation": [
            "Validate the simulated malware alert and identify the affected file or process.",
            "Review process, network, and user activity around the detection time.",
            "Search other fictional hosts for the same indicators.",
        ],
        "containment": [
            "Isolate the endpoint using the organization's approved process.",
            "Quarantine the artifact and preserve evidence.",
            "Do not disrupt an OT asset without coordination with operations and safety teams.",
        ],
    },
    "privilege_change": {
        "investigation": [
            "Identify who requested and performed the administrator assignment.",
            "Compare the change with tickets, approvals, and identity audit logs.",
            "Review actions performed by the account after privileges changed.",
        ],
        "containment": [
            "Remove unauthorized privileges using the approved identity process.",
            "Suspend affected sessions and rotate credentials if needed.",
        ],
    },
    "unauthorized_access": {
        "investigation": [
            "Review the denied resource, account, source, and authentication context.",
            "Determine whether the attempt was user error or suspicious behavior.",
            "Search for similar attempts against other resources.",
        ],
        "containment": [
            "Restrict the source or account if risk is confirmed and policy allows.",
            "Preserve relevant logs and escalate repeated attempts.",
        ],
    },
    "suspicious_login": {
        "investigation": [
            "Confirm the user's schedule, location, device, and MFA result.",
            "Compare the source with the user's normal authentication history.",
            "Review actions taken during the session.",
        ],
        "containment": [
            "Revoke the session and reset credentials if the login is unauthorized.",
            "Increase monitoring for the user and source.",
        ],
    },
}

OT_ADDITIONAL_STEPS = {
    "investigation": [
        "Coordinate with the fictional operations owner before taking action.",
        "Assess safety and availability impact before changing or isolating the system.",
        "Check monitoring and network-segmentation records around the OT boundary.",
    ],
    "containment": [
        "Use approved OT incident procedures; avoid unplanned shutdowns or restarts.",
        "Prefer controlled network containment coordinated with operations personnel.",
    ],
}


def _playbook_name(rule_id: str) -> str:
    """Choose the closest defensive playbook for a rule."""

    return {
        "AUTH-001": "brute_force",
        "AUTH-002": "privileged_attack",
        "AUTH-003": "suspicious_login",
        "AUTH-004": "brute_force",
        "NET-001": "port_scan",
        "NET-002": "port_scan",
        "NET-003": "lateral_movement",
        "MAL-001": "malware",
        "PRIV-001": "privilege_change",
        "ACCESS-001": "unauthorized_access",
    }.get(rule_id, "unauthorized_access")


def get_response_steps(detection: dict[str, Any]) -> dict[str, Any]:
    """Return investigation and containment steps, adding OT cautions when needed."""

    name = _playbook_name(str(detection.get("rule_id", "")))
    base = PLAYBOOKS[name]
    investigation = list(base["investigation"])
    containment = list(base["containment"])
    event = detection.get("event_data", {})

    if is_critical_system(
        str(detection.get("affected_host", "")), str(event.get("system_type", ""))
    ):
        investigation.extend(OT_ADDITIONAL_STEPS["investigation"])
        containment.extend(OT_ADDITIONAL_STEPS["containment"])

    return {
        "playbook": name.replace("_", " ").title(),
        "investigation": investigation,
        "containment": containment,
        "safety_note": SAFETY_NOTE,
    }


def add_response_guidance(
    detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach response steps and a short recommended action to each alert."""

    for detection in detections:
        response = get_response_steps(detection)
        detection["response_playbook"] = response
        detection["recommended_action"] = response["investigation"][0]
    return detections

