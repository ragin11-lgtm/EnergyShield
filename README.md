# EnergyShield

> EnergyShield is a simulated Security Operations Center monitoring platform designed to demonstrate defensive cybersecurity concepts in a fictional energy infrastructure environment.

EnergyShield turns 75 safe, local JSON events into explainable security alerts. It detects authentication abuse, simulated network reconnaissance, unauthorized access, privilege changes, and malware notifications; assigns deterministic risk scores; adds conservative MITRE ATT&CK mappings; and recommends defensive response steps. Analysts can use either a terminal summary or an interactive Streamlit dashboard.

No real infrastructure, electrical control logic, network scanning, or exploitation is included.

## Overview

The fictional company has corporate systems and OT-labeled monitoring assets such as `SOLAR-SCADA-01`, `BESS-CONTROLLER-01`, and `SUBSTATION-HMI-01`. These names provide energy-sector context only. Every event is a JSON record generated locally with private or documentation-only IP addresses.

The application follows a simple pipeline:

```text
Fictional Energy Systems
          |
          v
 Security Events / Logs
          |
          v
      Log Loader
          |
          v
   Detection Engine
          |
          +-------------------+
          |                   |
          v                   v
     Risk Engine        MITRE Mapping
          |                   |
          +---------+---------+
                    |
                    v
              SOC Dashboard
                    |
                    v
            Incident Response
```

## Why I Built This

I built EnergyShield to practice Python while learning how SOC analysts turn raw logs into useful alerts. The energy setting adds beginner-friendly IT/OT context: operational availability, controlled changes, network segmentation, and coordination with operations all influence how an analyst should respond.

This is a portfolio lab, not a production monitoring product and not a real SCADA implementation.

## Architecture

EnergyShield uses one shared analysis pipeline for both interfaces. The full component responsibilities and data flow are documented in [docs/architecture.md](docs/architecture.md).

## Features

- 75 deterministic events containing normal and suspicious behavior
- Safe addresses from private and documentation-only ranges
- Authentication rules for repeated failures, brute force, privileged accounts, lockouts, and after-hours activity
- Network rules for simulated port scans, unusual ports, and rapid multi-host contact
- Security-event rules for denied access, administrator privilege changes, and simulated malware
- Explainable 0–100 risk scoring with visible additive factors
- Conservative ATT&CK enrichment with `Needs verification` when a mapping is not justified
- OT-aware incident-response recommendations
- Streamlit dashboard with five summary cards, seven charts, five filters, alert drill-down, and report actions
- CLI mode that requires no dashboard dependencies
- Markdown incident reports saved under `reports/`
- Unit tests for thresholds, network aggregation, scoring, and malformed input
- Detailed architecture, detection, incident-response, and learning guides under `docs/`

## Technologies

- Python 3.10+ recommended
- Python standard library for loading, detection, enrichment, reporting, and CLI output
- Streamlit for the local dashboard
- pandas for dashboard tables and grouping
- Plotly for charts
- pytest for automated tests
- JSON for fictional event fixtures

## Installation

Clone or download the repository, enter its directory, and create an isolated environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Running the CLI

```bash
python main.py
```

The CLI loads the three files in `data/`, analyzes all 75 events, prints headline metrics, and displays each enriched alert. It never opens a network connection.

## Running the Dashboard

```bash
streamlit run dashboard/app.py
```

Open the local address Streamlit prints, usually `http://localhost:8501`. Use the sidebar to filter by severity, system, username, source IP, or event type. Select an alert near the bottom of the page to see evidence, scoring factors, ATT&CK context, response steps, and report actions.

The checked-in Streamlit configuration binds the lab to `127.0.0.1` by default so it is available only on the local computer. The V1 dashboard has no authentication and should not be exposed to a network.

## Detection Rules

| Rule | Detection | Trigger | Alert severity |
|---|---|---|---|
| `AUTH-001` | Repeated failed logins / possible brute force | 10–19 failures / 20+ failures | Warning / Critical |
| `AUTH-002` | Privileged account under possible attack | Privileged account and 10+ failures | Critical |
| `AUTH-003` | Login outside normal hours | Fixture event carries the after-hours event type | Warning |
| `AUTH-004` | Account lockout | Fixture event records an account lockout | Warning |
| `NET-001` | Possible port scan | One source reaches 10+ distinct ports in five minutes | Warning; Critical at 20+ ports |
| `NET-002` | Connection to unusual port | Port is in the configurable review list | Warning |
| `NET-003` | Possible reconnaissance or lateral movement | One source reaches 5+ systems in five minutes | High |
| `ACCESS-001` | Unauthorized access attempt | Event records denied unauthorized access | High |
| `PRIV-001` | Unauthorized administrator privilege change | Event records a new administrator assignment | Critical |
| `MAL-001` | Simulated malware detection | Event records a fictional endpoint malware alert | Critical |

Counts from 0–9 are classified as `NORMAL` and do not create an active alert. This keeps harmless password mistakes visible in the event data without flooding the SOC alert queue. Thresholds and unusual ports are centralized in `src/config.py`.

See [docs/detection_rules.md](docs/detection_rules.md) for the complete logic, limitations, and examples.

## Risk Scoring

Risk is deterministic: a severity base score is combined with applicable context and capped at 100.

| Factor | Points |
|---|---:|
| Info alert base | 10 |
| Low alert base | 25 |
| Warning or Medium alert base | 45 |
| High alert base | 65 |
| Critical alert base | 80 |
| Privileged account | +10 |
| Fictional critical/OT system | +10 |
| 10–19 failed logins | +5 |
| 20+ failed logins | +10 |
| Simulated malware | +10 |
| Administrator privilege change | +10 |
| Three or more related events | +5 |

| Score | Risk level |
|---:|---|
| 0–20 | Normal |
| 21–40 | Low |
| 41–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

Alert severity describes the rule's urgency; risk level describes the total context. They are related but intentionally separate. The exact code is in `src/risk_engine.py`.

## MITRE ATT&CK

The mapping layer is intentionally conservative:

- Brute Force — `T1110`
- Valid Accounts — `T1078`
- Network Service Scanning — `T1046`
- Account Manipulation — `T1098`

Rules without enough evidence for a confident technique use `Needs verification`. ATT&CK provides analyst vocabulary; a mapping does not prove that an attacker used a technique.

## Energy / OT Security Context

EnergyShield labels selected fictional hosts as operational or critical systems. Their involvement adds risk and adds response guidance about availability, safety, change control, and coordination with operations. The project never controls a physical process.

Start with [docs/energy_sector_context.md](docs/energy_sector_context.md) for an explanation of OT, ICS, SCADA, and the difference between IT and OT response priorities.

The defensive response procedures are documented separately in [docs/incident_response_playbook.md](docs/incident_response_playbook.md).

## Example Alert

```text
[CRITICAL] Privileged Account Under Possible Attack
User: admin
Source IP: 192.0.2.25
System: SOLAR-SCADA-01
Failed Logins: 27
Risk Score: 100/100 (CRITICAL)
MITRE ATT&CK: Brute Force (T1110)
```

This record is fictional. The documentation address `192.0.2.25` is not scanned or contacted.

## Screenshots

Add portfolio screenshots here after running the dashboard locally:

- Dashboard overview and summary cards
- Alert filtering and recent-alert table
- Selected alert with risk and response tabs
- Generated Markdown incident report

## Project Structure

```text
EnergyShield/
├── README.md
├── .streamlit/config.toml         # Local-only dashboard binding
├── main.py                       # Command-line interface
├── requirements.txt
├── data/                         # 75 fictional JSON events
├── dashboard/app.py              # Streamlit interface
├── docs/                         # Architecture and learning material
├── reports/.gitkeep              # Generated reports stay local
├── scripts/generate_sample_data.py
├── src/
│   ├── config.py                 # Thresholds and review lists
│   ├── models.py                 # Event and alert data shapes
│   ├── log_loader.py             # JSON validation and defaults
│   ├── detection_engine.py       # Authentication/network/security rules
│   ├── risk_engine.py            # Deterministic scoring
│   ├── mitre_mapping.py          # ATT&CK enrichment
│   ├── incident_response.py      # Defensive playbooks
│   ├── reporting.py              # Markdown reports
│   └── utils.py                  # Pipeline orchestration and metrics
└── tests/                         # pytest unit tests
```

The structure adds `src/config.py` and `scripts/generate_sample_data.py` to the original concept. Keeping rule settings in one module avoids scattered magic numbers; keeping fixture generation separate makes the dataset reproducible without adding complexity to the application.

## Testing

```bash
python -m pytest -q
python -m compileall -q main.py src dashboard scripts tests
```

To recreate the exact sample fixtures:

```bash
python scripts/generate_sample_data.py
```

The generator only writes local JSON files. It performs no scanning or network activity.

## What I Learned

- How JSON objects become Python dictionaries
- How small functions and modules create a readable analysis pipeline
- How threshold-based SOC rules trade sensitivity against alert noise
- Why alert severity and contextual risk are different measurements
- How to add ATT&CK context without overstating evidence
- Why OT response must protect availability and coordinate with operations
- How pandas, Plotly, and Streamlit turn enriched alerts into an analyst workflow
- How tests make detection thresholds safe to change

The step-by-step teaching path is in [docs/how_it_works.md](docs/how_it_works.md).

## Future Improvements

- Ingest Windows Event Logs, Linux authentication logs, or syslog
- Express selected rules in Sigma and translate them into SIEM queries
- Add Microsoft Sentinel or Splunk examples
- Store alerts in SQLite or PostgreSQL
- Add a REST API, dashboard authentication, and role-based access
- Add approved threat-intelligence enrichment and alert notifications
- Map relevant controls to the NIST Cybersecurity Framework and NIST SP 800-82 concepts
- Package the lab with Docker and add continuous integration
- Expand OT-specific monitoring while continuing to avoid control functionality

These are roadmap ideas, not features claimed by the current version.

## Ethical / Safety Disclaimer

EnergyShield is a defensive cybersecurity learning project. All organizations, identities, systems, addresses, logs, malware notices, and alerts are fictional. The repository does not scan public IP addresses, exploit systems, send attack traffic, control industrial equipment, or interact with real ICS/SCADA environments.

**EnergyShield simulates cybersecurity monitoring around fictional operational technology systems. It does not implement or interact with real industrial control systems.**

In a real organization, analysts must follow approved incident-response, safety, legal, privacy, and change-control procedures.
