# Detection Rules

## How to Read the Rules

A detection rule is an `if` statement applied consistently to security events. The event provides evidence, the configuration provides a threshold, and the rule decides whether to create an alert.

EnergyShield favors understandable thresholds over machine learning. A rule match is a reason to investigate, not proof of malicious behavior.

## Configuration

The values below come from `src/config.py`:

| Setting | V1 value | Meaning |
|---|---:|---|
| `WARNING_FAILED_LOGINS` | 10 | Start alerting on repeated authentication failures |
| `CRITICAL_FAILED_LOGINS` | 20 | Treat the failure count as possible brute force |
| `PORT_SCAN_THRESHOLD` | 10 | Distinct ports needed in the time window |
| `CRITICAL_PORT_SCAN_THRESHOLD` | 20 | Distinct ports needed for critical scan severity |
| `MULTI_HOST_THRESHOLD` | 5 | Distinct systems needed for rapid multi-host contact |
| `NETWORK_TIME_WINDOW_MINUTES` | 5 | Aggregation window for source behavior |

The unusual-port review set is `21, 23, 2323, 3389, 4444, 5900, 8088`. These ports are not automatically malicious. Their use is simply uncommon or sensitive in this fictional environment and deserves validation.

## Authentication Rules

### AUTH-001 — Failed-login thresholds

- 0–9 failures: `NORMAL`; retain the event but create no active alert.
- 10–19 failures: `WARNING` alert named **Repeated Failed Logins**.
- 20 or more failures: `CRITICAL` alert named **Possible Brute-Force Attack**.

The rule applies to `failed_login`, `repeated_failed_logins`, and `privileged_login_failure` event types.

Example:

```python
if failed_logins >= CRITICAL_FAILED_LOGINS:
    # Create a critical brute-force alert.
elif failed_logins >= WARNING_FAILED_LOGINS:
    # Create a warning alert.
```

### AUTH-002 — Privileged account under possible attack

Create an additional critical alert when:

1. the event is a supported failed-login type;
2. the failure count is at least 10; and
3. `privileged_account` is true or the normalized username appears in `PRIVILEGED_USERNAMES`.

This rule does not rely only on the literal username `admin`.

### AUTH-003 — Login outside normal hours

Create a warning when the fixture event type is `suspicious_login_outside_hours`. The alert explicitly says schedule context is not proof of compromise.

### AUTH-004 — Account lockout

Create a warning when the event type is `account_lockout`. A lockout can result from user error, a stale service credential, or password guessing, so an analyst must review context.

## Network Rules

### NET-001 — Possible port scan

1. Group network events by source IP.
2. Sort valid timestamps.
3. Find the five-minute window with the most distinct destination ports.
4. Alert at 10 ports and use critical severity at 20 ports.

The alert stores all related event IDs from the selected window so the analyst can see that it was based on multiple records.

### NET-002 — Connection to unusual port

Create a warning for each connection whose destination port is in `UNUSUAL_PORTS`. This is a contextual review rule, not a malware verdict.

### NET-003 — Possible reconnaissance or lateral movement

Using the same source grouping and time-window logic, create a high alert when one source contacts at least five distinct hostnames. Inventory tools and approved administrators can also behave this way, so validation is required.

## General Security Rules

| Rule | Fixture event type | Result |
|---|---|---|
| `ACCESS-001` | `unauthorized_access_attempt` | High alert for denied access requiring context review |
| `PRIV-001` | `new_admin_privilege` | Critical alert requiring approval and identity-log review |
| `MAL-001` | `malware_detection` | Critical alert representing a fictional endpoint detection |

## Detection Output

Every alert includes:

- alert and rule IDs
- rule name, severity, and description
- affected user and host
- source IP and timestamp
- the reason the rule triggered
- related fixture event IDs and evidence

Later pipeline stages add the risk score, ATT&CK fields, and response playbook.

## Rule Limitations

- A single fixture can create more than one alert. For example, 27 failures against a privileged account match both `AUTH-001` and `AUTH-002`.
- The network window uses event timestamps but does not model packet state, sessions, or protocol semantics.
- Event types are trusted after normalization; V1 does not authenticate the data source.
- Thresholds are lab choices, not universal industry standards.
- No rule automatically blocks, disables, quarantines, or changes a system.

## Safe Tuning Exercise

Change one value in `src/config.py`, predict which test or sample alert will change, and then run `python -m pytest -q` plus `python main.py`. This is a simple way to learn how detection sensitivity affects noise.
