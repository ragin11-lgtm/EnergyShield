"""Small data models shared by EnergyShield modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class SecurityEvent:
    """A normalized cybersecurity event loaded from a JSON file."""

    event_id: str
    timestamp: str
    event_type: str
    username: str = "Unknown"
    source_ip: str = "Unknown"
    destination_ip: str = "Unknown"
    hostname: str = "Unknown"
    system_type: str = "Unknown"
    failed_logins: int = 0
    destination_port: int | None = None
    action: str = "unknown"
    privileged_account: bool = False
    severity: str = "INFO"
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a normal dictionary for rule processing and pandas."""

        return asdict(self)


@dataclass
class Detection:
    """An alert produced by a detection rule."""

    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    description: str
    affected_user: str
    affected_host: str
    source_ip: str
    timestamp: str
    event_type: str
    why_triggered: str
    recommended_action: str = ""
    risk_score: int = 0
    risk_level: str = "NORMAL"
    risk_factors: list[str] = field(default_factory=list)
    mitre_tactic: str = "Needs verification"
    mitre_technique: str = "Needs verification"
    mitre_technique_id: str = "Needs verification"
    related_event_ids: list[str] = field(default_factory=list)
    event_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable alert dictionary."""

        return asdict(self)

