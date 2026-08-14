# How EnergyShield Works

This guide assumes you understand variables, `if` statements, loops, lists, and dictionaries. It explains the newer ideas one layer at a time. Keep the code open while reading and run `python main.py` after each section so the ideas stay connected to visible output.

## 1. What Happens When `main.py` Starts

Python reads the file from top to bottom. It imports reusable functions, defines `print_alert()` and `main()`, and reaches this block:

```python
if __name__ == "__main__":
    raise SystemExit(main())
```

When you run `python main.py`, Python gives the file the special name `__main__`, so `main()` runs. `main()` then:

1. prints the EnergyShield heading;
2. calls `load_all_events(DATA_DIRECTORY)`;
3. prints any non-fatal data warnings;
4. calls `analyze_security_events(events)`;
5. builds headline counts with `build_summary()`; and
6. loops over detections and calls `print_alert()` for each one.

`main()` returns `0` after success and `1` when the input files cannot be loaded. These are conventional process exit codes.

## 2. How Events Are Loaded

JSON is a text format for structured data. A JSON object uses key/value pairs and closely resembles a Python dictionary. A JSON array resembles a Python list.

One simplified fixture record looks like this:

```json
{
  "event_id": "LOGIN-022",
  "event_type": "privileged_login_failure",
  "username": "admin",
  "source_ip": "192.0.2.25",
  "hostname": "SOLAR-SCADA-01",
  "failed_logins": 27,
  "privileged_account": true
}
```

`json.load()` changes the JSON array into a Python list and each object into a dictionary. `load_event_file()` verifies that the file exists, is not empty, contains valid JSON, and has a list at the top level.

Then this loop processes every item:

```python
for position, raw_event in enumerate(raw_data, start=1):
    # Validate and normalize one item.
```

`normalize_event()` fills missing optional values with safe defaults such as `"Unknown"` or `0`. It converts numeric strings such as `"12"` into integers. Bad numeric values produce warnings rather than stopping the entire analysis.

Invalid JSON and completely empty input are different: the loader cannot safely continue, so it raises `LogLoadError` with an understandable message.

## 3. How a Dictionary Represents an Event

A dictionary connects a key to a value:

```python
event = {
    "username": "admin",
    "failed_logins": 27,
    "privileged_account": True,
}
```

You can retrieve a value with `event["username"]`. EnergyShield often uses `event.get("username", "Unknown")` instead. `.get()` avoids a crash if the key is missing and returns the default value.

Values can have different types:

- `"admin"` is a string.
- `27` is an integer.
- `True` is a Boolean.
- `None` means no value is available.

The loader normalizes types once so later rules can be simpler.

## 4. How Loops Process Events

The detection functions receive `events`, which is a list of dictionaries. A loop examines one event at a time:

```python
for event in events:
    event_type = str(event.get("event_type", "")).lower()
    failed_logins = int(event.get("failed_logins", 0) or 0)
```

This pattern scales from one event to 75 without copying the rule 75 times. When a rule matches, the function appends a new alert dictionary to the `detections` list.

Network correlation adds one extra step. Events are grouped by source IP using `defaultdict(list)`, then each source's events are examined inside a five-minute window. This lets the program detect a pattern across many records instead of only inspecting records individually.

## 5. How Detection Rules Work

Detection engineering turns evidence into a consistent review condition. The simplest EnergyShield rule is the failed-login classifier:

```python
if failed_logins >= CRITICAL_FAILED_LOGINS:
    return "CRITICAL"
if failed_logins >= WARNING_FAILED_LOGINS:
    return "WARNING"
return "NORMAL"
```

The order matters. A count of 27 also satisfies `>= 10`, so the code must check the critical threshold first.

Normal events stay in the event list but do not enter the active-alert list. This avoids treating every typo as an incident. Suspicious conditions call `_new_detection()`, which creates the same set of fields for every rule.

Rules should be testable and explainable. Each alert includes `why_triggered`, such as the count, time window, and threshold that matched.

## 6. Why Functions Are Used

A function gives a name to a reusable job:

```python
def risk_level_for_score(score: int) -> str:
    # Return a label for the score.
```

The value inside the parentheses is an input parameter. `return` sends an output back to the caller. Functions help because:

- the same logic is not copied into the CLI and dashboard;
- tests can call one small behavior directly;
- a name such as `load_event_file` explains intent; and
- changes stay inside the responsible module.

Type hints such as `score: int` and `-> str` describe expected types for people and editor tools. Python does not automatically enforce them at runtime.

## 7. Modules, Imports, and Classes

A Python file is a module. `from src.risk_engine import add_risk_scores` means “make that function from another module available here.” Modules keep unrelated responsibilities out of one giant file.

EnergyShield uses two small dataclasses in `src/models.py`. A class defines a reusable data shape. The `SecurityEvent` class lists event fields and defaults; `Detection` lists alert fields. `@dataclass` asks Python to generate routine setup code automatically.

The project quickly converts each dataclass instance to a dictionary with `to_dict()`. This gets the benefit of one documented shape while keeping rule processing beginner-friendly.

## 8. How Risk Scores Are Calculated

`calculate_risk_score()` begins with a base determined by alert severity. It then uses `if` statements to add points for context:

- privileged account: +10;
- fictional critical/OT system: +10;
- 10–19 failures: +5;
- 20+ failures: +10;
- simulated malware: +10;
- administrator privilege change: +10; and
- three or more related events: +5.

`min(score, 100)` caps the final value. `risk_level_for_score()` loops over the configured risk bands and returns Normal, Low, Medium, High, or Critical.

The function also appends a text explanation for every applied factor. The dashboard displays those strings, making the result easy to audit and explain to another person.

Severity and risk are not identical. Severity comes from the matched rule. Risk combines severity with user, host, failure-count, and related-event context.

## 9. How MITRE and Response Enrichment Work

`mitre_mapping.py` uses a dictionary whose keys are EnergyShield rule IDs. The value for each rule is another dictionary containing tactic, technique, and technique ID. `add_mitre_mappings()` looks up each alert. An unknown rule receives `Needs verification` rather than a guessed technique.

`incident_response.py` uses a similar mapping from rule ID to playbook name. `get_response_steps()` copies the relevant investigation and containment lists. If `is_critical_system()` returns true, it adds OT-specific cautions.

Neither module takes action against a system. They only add educational context to the alert dictionary.

## 10. How the Dashboard Receives Data

Streamlit reruns the Python script when the user changes a widget. `load_dashboard_data()` loads and analyzes the events, and `@st.cache_data` allows Streamlit to reuse unchanged results.

pandas converts the lists of dictionaries into DataFrames:

```python
events_frame = pd.DataFrame(events)
alerts_frame = pd.DataFrame(detections)
```

A DataFrame is a table with named columns. Code can filter rows, count values, group by a system, or find the highest score. Plotly Express turns those results into charts. Streamlit functions place the charts, metrics, tables, filters, tabs, and buttons on the page.

The dashboard never contains its own security rules. It calls the same `analyze_security_events()` function as the CLI, so both interfaces agree.

## 11. How Incident Reports Are Created

When you select an alert, `build_incident_report()` reads fields from that one enriched alert dictionary and inserts them into a Markdown template. It formats investigation and containment items as numbered lists.

There are two report paths:

- the dashboard download button sends the generated text to the browser;
- the save button calls `save_incident_report()`, which writes a safe filename under `reports/`.

The report includes the description, trigger reason, risk factors, ATT&CK context, response steps, and safety notice. Generated reports are ignored by Git so a local investigation artifact is not accidentally committed.

## 12. File-by-File Guide

### `main.py`

- **What this file does:** provides the terminal interface.
- **Why it exists:** the project remains useful without a web dashboard.
- **Important functions:** `main()`, `print_alert()`.
- **Inputs:** normalized fixtures loaded from `data/`.
- **Outputs:** console metrics, alerts, and process exit code.

### `src/config.py`

- **What this file does:** stores paths, thresholds, review ports, account names, system labels, and risk bands.
- **Why it exists:** one changeable source prevents magic numbers from being scattered.
- **Important values:** `WARNING_FAILED_LOGINS`, `PORT_SCAN_THRESHOLD`, `UNUSUAL_PORTS`, `CRITICAL_SYSTEM_LABELS`.
- **Inputs:** none.
- **Outputs:** constants imported by other modules.

### `src/models.py`

- **What this file does:** defines normalized event and alert shapes.
- **Why it exists:** defaults and expected fields are documented once.
- **Important classes:** `SecurityEvent`, `Detection`.
- **Inputs:** field values supplied by the loader or detector.
- **Outputs:** dataclass objects and dictionaries from `to_dict()`.

### `src/log_loader.py`

- **What this file does:** reads, validates, normalizes, and combines JSON events.
- **Why it exists:** detection rules should not repeat file and type handling.
- **Important functions:** `normalize_event()`, `load_event_file()`, `load_all_events()`.
- **Inputs:** a file or data-directory path.
- **Outputs:** `(events, warnings)` or a clear `LogLoadError`.

### `src/detection_engine.py`

- **What this file does:** applies authentication, network, and general security rules.
- **Why it exists:** all detection logic stays visible and testable.
- **Important functions:** `classify_failed_login_count()`, `detect_login_activity()`, `detect_network_activity()`, `detect_security_activity()`, `run_detections()`.
- **Inputs:** a list of normalized event dictionaries.
- **Outputs:** a list of detection dictionaries.

### `src/risk_engine.py`

- **What this file does:** adds contextual risk scores.
- **Why it exists:** alert creation and business-impact scoring are separate decisions.
- **Important functions:** `is_critical_system()`, `risk_level_for_score()`, `calculate_risk_score()`, `add_risk_scores()`.
- **Inputs:** detection dictionaries.
- **Outputs:** score, band, factors, and enriched detections.

### `src/mitre_mapping.py`

- **What this file does:** adds educational ATT&CK fields.
- **Why it exists:** mappings remain centralized and conservative.
- **Important value/function:** `MITRE_MAPPINGS`, `add_mitre_mappings()`.
- **Inputs:** detection rule IDs.
- **Outputs:** tactic, technique, and technique ID fields.

### `src/incident_response.py`

- **What this file does:** selects defensive investigation and containment guidance.
- **Why it exists:** analysts need a next step after an alert.
- **Important functions:** `get_response_steps()`, `add_response_guidance()`.
- **Inputs:** an enriched detection and its system context.
- **Outputs:** playbook lists, safety note, and recommended action.

### `src/reporting.py`

- **What this file does:** builds and saves Markdown incident reports.
- **Why it exists:** report formatting and file writing should not clutter the dashboard.
- **Important functions:** `build_incident_report()`, `save_incident_report()`.
- **Inputs:** one fully enriched detection.
- **Outputs:** Markdown text or a saved file path.

### `src/utils.py`

- **What this file does:** connects the pipeline stages and calculates summary metrics.
- **Why it exists:** the CLI and dashboard need the same orchestration.
- **Important functions:** `analyze_security_events()`, `build_summary()`.
- **Inputs:** event and detection lists.
- **Outputs:** enriched detections and metric counts.

### `dashboard/app.py`

- **What this file does:** renders the local SOC dashboard.
- **Why it exists:** visual exploration helps an analyst find patterns and inspect alerts.
- **Important functions:** `load_dashboard_data()`, `apply_filters()`, `render_metrics()`, `render_charts()`, `render_alert_details()`, `main()`.
- **Inputs:** the same events and detections used by the CLI plus user filter selections.
- **Outputs:** a Streamlit page and optional local/downloaded report.

### `scripts/generate_sample_data.py`

- **What this file does:** deterministically creates the three JSON fixture files.
- **Why it exists:** the dataset can be understood and reproduced.
- **Important functions:** `build_login_events()`, `build_network_events()`, `build_security_events()`, `write_events()`, `main()`.
- **Inputs:** hard-coded fictional scenarios and base time.
- **Outputs:** 75 local JSON records; no network activity.

### `tests/`

- **What these files do:** call small units with controlled inputs and compare actual results to expected results.
- **Why they exist:** threshold and loader changes can otherwise silently break detections.
- **Important tests:** failed-login boundaries, privileged-account behavior, network aggregation, scoring boundaries, valid JSON, invalid values, invalid JSON, and empty files.
- **Inputs:** small dictionaries and temporary JSON files.
- **Outputs:** passing assertions or a precise pytest failure.

## 13. Learning Milestones

### Milestone 1 — Dictionaries and lists

Study one record in `data/sample_logins.json`, then `SecurityEvent.to_dict()` in `src/models.py`. Be able to explain keys, values, types, and a list of event dictionaries.

### Milestone 2 — The event-processing loop

Study `detect_login_activity()` in `src/detection_engine.py`. Trace one normal event and one suspicious event through the loop.

### Milestone 3 — Functions and modules

Study `main()` in `main.py` and `analyze_security_events()` in `src/utils.py`. Draw which function calls which module.

### Milestone 4 — JSON and error handling

Study `load_event_file()` and `normalize_event()` in `src/log_loader.py`. Create a copy of a fixture, change one number to a bad string, and observe the warning in a safe test.

### Milestone 5 — Detection engineering

Study `classify_failed_login_count()`, `detect_network_activity()`, and `docs/detection_rules.md`. Explain false positives, thresholds, time windows, and why rule matches need investigation.

### Milestone 6 — Risk scoring

Study `calculate_risk_score()` and `risk_level_for_score()` in `src/risk_engine.py`. Calculate one sample alert by hand and compare it with the CLI.

### Milestone 7 — pandas, Plotly, and Streamlit

Study the DataFrame creation in `dashboard/app.py`, then one chart and one filter. Be able to explain that pandas shapes data, Plotly creates the figure, and Streamlit renders the interface.

### Milestone 8 — Cybersecurity and OT concepts

Study `src/mitre_mapping.py`, `src/incident_response.py`, and `docs/energy_sector_context.md`. Explain why ATT&CK is context rather than proof and why OT containment requires operations coordination.

Before presenting the project as your own work, make sure you can run it, explain one event end-to-end, change a threshold safely, and describe its limitations without reading the code.
