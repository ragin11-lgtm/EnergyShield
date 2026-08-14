# EnergyShield Architecture

## Design Goal

EnergyShield is a small, readable pipeline for learning how a SOC turns events into analyst-ready alerts. The design separates each responsibility so a student can change one stage without rewriting the others.

```text
data/*.json
    |
    v
log_loader.py  -- normalize fields and report data problems
    |
    v
detection_engine.py  -- apply transparent security rules
    |
    +----------------------+----------------------+
    |                      |                      |
    v                      v                      v
risk_engine.py     mitre_mapping.py     incident_response.py
    |                      |                      |
    +----------------------+----------------------+
                           |
                           v
                       alert dictionaries
                           |
                 +---------+----------+
                 |                    |
                 v                    v
              main.py         dashboard/app.py
                                      |
                                      v
                              reporting.py
```

## Data Flow

1. `main.py` or `dashboard/app.py` asks `load_all_events()` to read the fixtures.
2. `log_loader.py` checks that each file exists, contains valid JSON, and holds a non-empty list. Each usable item becomes a normalized event dictionary.
3. `analyze_security_events()` in `src/utils.py` starts the alert pipeline.
4. `detection_engine.py` applies login, network, and security-event rules.
5. `risk_engine.py` adds a score, band, and point-by-point explanation.
6. `mitre_mapping.py` adds a verified educational mapping or `Needs verification`.
7. `incident_response.py` adds investigation and containment guidance. OT-labeled hosts receive extra availability and coordination cautions.
8. The CLI prints the alerts. The dashboard turns them into cards, filters, charts, tables, and an alert detail view.
9. `reporting.py` can turn a selected enriched alert into a Markdown report.

## Main Components

### Sample data

The three files in `data/` hold 75 deterministic events:

- `sample_logins.json`: 30 authentication events
- `sample_network_events.json`: 30 network events
- `sample_security_events.json`: 15 general security events

`scripts/generate_sample_data.py` reproduces them. It only writes JSON and performs no network operations.

### Models

`SecurityEvent` and `Detection` in `src/models.py` are Python dataclasses. They list expected fields and defaults in one place. Processing functions convert them to dictionaries because dictionaries are easy for a beginner to inspect and easy for pandas to turn into tables.

### Configuration

`src/config.py` contains paths, failed-login thresholds, network thresholds, unusual ports, privileged usernames, critical-system labels, and risk bands. This prevents rule values from being scattered across many files.

### Interfaces

The CLI and dashboard share the exact same loading and analysis functions. The interface changes, but the detection results do not. This avoids duplicate rule logic.

## Why This Structure

The original proposed structure is retained with two small additions:

- `src/config.py` keeps thresholds explicit and changeable.
- `scripts/generate_sample_data.py` makes the fictional dataset reproducible.

These additions improve clarity without adding a framework, database, service layer, or other production complexity.

## Trust Boundaries and Safety

The application reads local fixture files and optionally writes local Markdown reports. It has no packet sender, scanner, exploit code, device protocol, or industrial controller connection. Hostnames such as `SOLAR-SCADA-01` are labels used to teach contextual scoring.

The checked-in Streamlit configuration binds the dashboard to `127.0.0.1` for local viewing. The V1 dashboard has no authentication and must not be exposed to a network.

## Limitations

- Events are deterministic fixtures rather than live telemetry.
- Rules use simple thresholds and fixture event types.
- Related events are grouped by source and a five-minute window, not by a production correlation engine.
- Alerts have no lifecycle, owner, comments, or persistent database.
- ATT&CK mappings are educational and do not establish attacker intent.
- OT context changes risk and response text but does not model a physical process.
- The dashboard is a single-user local lab.

These limitations keep V1 safe and explainable.
