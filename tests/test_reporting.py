"""Tests for building and saving EnergyShield incident reports."""

from src.reporting import build_incident_report, save_incident_report


def sample_detection() -> dict:
    """Return one fully enriched alert for report tests."""

    return {
        "alert_id": "ES-ALERT-TEST",
        "timestamp": "2026-06-15T12:00:00+00:00",
        "severity": "CRITICAL",
        "risk_score": 95,
        "risk_level": "CRITICAL",
        "rule_name": "Possible Brute-Force Attack",
        "affected_user": "test.admin",
        "affected_host": "SOLAR-SCADA-01",
        "source_ip": "192.0.2.25",
        "description": "A test description.",
        "why_triggered": "The test threshold was reached.",
        "risk_factors": ["CRITICAL alert base score: +80"],
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "mitre_technique_id": "T1110",
        "response_playbook": {
            "investigation": ["Review the test authentication logs."],
            "containment": ["Follow the approved test procedure."],
            "safety_note": "This is a simulated test.",
        },
    }


def test_incident_report_contains_required_sections() -> None:
    report = build_incident_report(sample_detection())

    assert "ENERGYSHIELD SECURITY INCIDENT REPORT" in report
    assert "Why the Alert Triggered" in report
    assert "Brute Force (T1110)" in report
    assert "Recommended Investigation Steps" in report
    assert "Recommended Containment Actions" in report


def test_incident_report_can_be_saved(tmp_path) -> None:
    report_path = save_incident_report(sample_detection(), tmp_path)

    assert report_path.name == "ES-ALERT-TEST_incident_report.md"
    assert report_path.exists()
    assert report_path.read_text(encoding="utf-8") == build_incident_report(
        sample_detection()
    )
