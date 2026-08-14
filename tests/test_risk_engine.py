"""Tests for transparent EnergyShield risk scoring."""

from src.risk_engine import calculate_risk_score, risk_level_for_score


def test_risk_bands_include_documented_boundaries() -> None:
    assert risk_level_for_score(20) == "NORMAL"
    assert risk_level_for_score(21) == "LOW"
    assert risk_level_for_score(41) == "MEDIUM"
    assert risk_level_for_score(61) == "HIGH"
    assert risk_level_for_score(81) == "CRITICAL"


def test_privileged_ot_brute_force_scores_critical() -> None:
    detection = {
        "severity": "CRITICAL",
        "rule_id": "AUTH-002",
        "affected_user": "scada_admin",
        "affected_host": "SOLAR-SCADA-01",
        "related_event_ids": ["LOGIN-1"],
        "event_data": {
            "system_type": "solar_scada",
            "privileged_account": True,
            "failed_logins": 24,
        },
    }

    score, level, factors = calculate_risk_score(detection)

    assert score == 100
    assert level == "CRITICAL"
    assert "Privileged account involved: +10" in factors
    assert "Fictional critical/OT system involved: +10" in factors


def test_warning_event_has_medium_risk_base() -> None:
    detection = {
        "severity": "WARNING",
        "rule_id": "NET-002",
        "affected_user": "student.user",
        "affected_host": "CORP-LAPTOP-01",
        "related_event_ids": ["NET-1"],
        "event_data": {"failed_logins": 0, "privileged_account": False},
    }

    score, level, _ = calculate_risk_score(detection)

    assert score == 45
    assert level == "MEDIUM"

