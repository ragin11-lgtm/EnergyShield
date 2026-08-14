# EnergyShield Interview Guide

Use these answers as study notes, not a script. Adjust the first-person wording so every statement is true for you.

## 1. Walk me through EnergyShield.

**Example answer:** EnergyShield is a local defensive SOC simulation for a fictional energy company. It loads 75 JSON events, normalizes them, runs transparent authentication, network, and security rules, calculates contextual risk, attaches conservative MITRE ATT&CK mappings and response steps, and shows the results in either a CLI or Streamlit dashboard. It does not connect to real infrastructure.

## 2. Why did you build it?

**Example answer:** I wanted one project that joined Python fundamentals with the workflow of a SOC analyst. The energy context helped me learn why privileged access, segmentation, system availability, and careful coordination matter around operational environments.

## 3. Why did you use dictionaries for events and alerts?

**Example answer:** JSON objects load naturally as Python dictionaries. Dictionaries let each event carry named fields such as `source_ip` and `failed_logins`, and pandas can easily turn a list of them into a table. I still used small dataclasses to document the expected shapes and defaults.

## 4. What happens to malformed input?

**Example answer:** The loader rejects missing files, empty files, invalid JSON, and the wrong top-level type with a clear `LogLoadError`. For recoverable field problems, it supplies safe defaults and returns warnings. For example, an invalid failed-login string becomes zero and does not crash the whole analysis.

## 5. How does the brute-force rule work?

**Example answer:** Failed-login counts from zero through nine are normal and create no active alert. Ten through nineteen create a warning, and twenty or more create a critical possible-brute-force alert. The thresholds are in `src/config.py`, and unit tests check the exact boundaries.

## 6. How do you detect attacks against privileged accounts?

**Example answer:** When a supported failed-login event reaches ten failures, the code checks both the event's `privileged_account` Boolean and a configurable set of privileged usernames. If either says the account is privileged, it creates an additional critical alert. That avoids hard-coding only `admin`.

## 7. How does the port-scan detection work?

**Example answer:** The detector groups network records by source IP, sorts valid timestamps, and finds the five-minute window with the most distinct destination ports. Ten ports creates a warning and twenty creates a critical alert. It is simulated log correlation; the program never sends packets.

## 8. How is risk calculated?

**Example answer:** Risk is deterministic and additive. It starts with an alert-severity base, then adds visible points for a privileged account, an OT-labeled critical system, failed-login count, selected rule types, and multiple related events. The score is capped at 100 and every factor is displayed so an analyst can reproduce it.

## 9. Why can severity and risk level be different?

**Example answer:** Severity describes the rule match itself. Risk includes context around the match. A warning about an unusual port can receive more risk when it targets an OT-labeled system, while a high-severity rule starts with a larger base even on a corporate host.

## 10. Why would a privileged SCADA account score higher?

**Example answer:** Privilege raises the potential impact of account misuse, and an OT-labeled host raises concern about operational availability and coordination. EnergyShield adds ten points for each. The hostname is only fictional context; the project does not operate SCADA equipment.

## 11. How do you use MITRE ATT&CK?

**Example answer:** I map specific rule IDs to techniques only when the behavior supports a mapping, such as Brute Force `T1110` or Network Service Scanning `T1046`. Generic detections use `Needs verification`. ATT&CK helps organize analyst thinking but does not prove attacker intent.

## 12. What is the difference between IT and OT security?

**Example answer:** IT usually supports business information and services, while OT supports physical operations. Both need confidentiality, integrity, and availability, but an OT response must pay special attention to safety, process stability, long asset lifecycles, and coordination before isolation or change. Those are general tendencies, not rules for every environment.

## 13. How did you make the project safe?

**Example answer:** All events are deterministic local JSON records using private or documentation-only addresses. The generator only writes files. There is no scanner, exploit code, packet transmission, device protocol, or electrical control logic. Response actions are recommendations, never automated commands.

## 14. What tests did you write?

**Example answer:** pytest covers normal, warning, and critical login boundaries, the extra privileged alert, port-scan and multi-host aggregation, risk-band boundaries and contextual scoring, valid event loading, bad numeric values, invalid JSON, empty input, and non-object items. I also compile the modules and exercise the CLI and dashboard startup paths.

## 15. What are the project's limitations, and what would you improve first?

**Example answer:** It uses fixture data, simple thresholds, an in-memory alert list, and a local unauthenticated dashboard. It does not have live telemetry, a database, case management, or production OT protocols. My first improvement would be a safe parser for a real exported log format plus stronger schema validation and tests, followed by persistent storage and a CI workflow. Any production-style expansion would need security and privacy design first.

## Practice Checklist

Before an interview, be able to:

- run the CLI and dashboard without notes;
- trace `LOGIN-022` from JSON to its two alerts;
- calculate one risk score by hand;
- explain why 0–9 failures do not create alerts;
- name one likely false positive for a network rule;
- describe why ATT&CK mapping is not attribution;
- state the safety disclaimer and at least three limitations; and
- change a threshold, predict the effect, and run the tests.
