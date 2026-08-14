"""Central configuration for EnergyShield detection and risk rules.

Keeping thresholds in one file makes the rules easy to find, explain, and tune.
The values are intentionally simple because this is a learning project.
"""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIRECTORY = PROJECT_ROOT / "data"
REPORTS_DIRECTORY = PROJECT_ROOT / "reports"

WARNING_FAILED_LOGINS = 10
CRITICAL_FAILED_LOGINS = 20
PORT_SCAN_THRESHOLD = 10
CRITICAL_PORT_SCAN_THRESHOLD = 20
MULTI_HOST_THRESHOLD = 5
NETWORK_TIME_WINDOW_MINUTES = 5

# These ports are not inherently malicious. EnergyShield flags them because their
# use deserves analyst review in this fictional environment.
UNUSUAL_PORTS = {21, 23, 2323, 3389, 4444, 5900, 8088}

PRIVILEGED_USERNAMES = {"admin", "scada_admin", "ot_engineer", "secops_admin"}

# A hostname containing one of these labels represents a fictional operational or
# critical energy system. No electrical control logic is implemented.
CRITICAL_SYSTEM_LABELS = {
    "SOLAR-SCADA",
    "WIND-SCADA",
    "BESS-CONTROLLER",
    "SUBSTATION-HMI",
    "OPERATIONS-SERVER",
}

RISK_BANDS = (
    (20, "NORMAL"),
    (40, "LOW"),
    (60, "MEDIUM"),
    (80, "HIGH"),
    (100, "CRITICAL"),
)

