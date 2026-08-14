# Incident Response Playbook

> This playbook supports a simulated learning environment. Real organizations must follow approved incident-response, safety, legal, and change-control procedures.

EnergyShield separates **investigation** from **containment**. Investigation gathers and validates evidence. Containment changes access or connectivity and therefore requires authorization. For OT-labeled systems, safety and availability must be considered before any change.

## Common Analyst Workflow

1. Confirm the alert fields and source evidence.
2. Decide whether the behavior has an expected business explanation.
3. Search for related activity across users, sources, and systems.
4. Record what was checked and what evidence supports the conclusion.
5. Escalate according to severity, privilege, and system criticality.
6. Use containment only through approved procedures.

## Brute Force

Investigation:

1. Review authentication logs for the user and source IP.
2. Confirm whether the account and source are expected.
3. Check MFA status and look for a success after the failures.
4. Search for the same source against other accounts or systems.

Potential containment:

1. Restrict the source if evidence, policy, and authorization support it.
2. Reset credentials if compromise is suspected.
3. Revoke suspicious sessions and increase monitoring.

## Privileged Account Attack

Investigation:

1. Validate the account owner and expected administrative activity.
2. Review privileged sessions, MFA records, and recent access changes.
3. Search the source across authentication and network logs.
4. Escalate promptly when an OT-labeled system is involved.

Potential containment:

1. Restrict or disable the account through the approved identity process.
2. Revoke sessions and rotate credentials if compromise is suspected.
3. Notify security, identity, and affected operations owners.

## Port Scan

Investigation:

1. Confirm the number of ports, targets, and time window.
2. Determine whether the source is an approved scanner or management tool.
3. Review firewall and endpoint logs for follow-on access.

Potential containment:

1. Block or rate-limit the source only when policy and evidence support it.
2. Increase monitoring around the targeted segment.

## Suspicious Lateral Movement or Multi-Host Contact

Investigation:

1. List every contacted system in the alert window.
2. Compare the behavior with approved administration or inventory activity.
3. Check each target for logins, remote-service use, and access failures.

Potential containment:

1. Isolate the source endpoint if malicious behavior is confirmed and policy permits.
2. Restrict unnecessary east-west traffic using approved segmentation controls.
3. Preserve logs before changes remove evidence.

## Malware Alert

Investigation:

1. Validate the alert and identify the affected file or process.
2. Review process, network, and user activity around the detection time.
3. Search other systems for the same indicators.

Potential containment:

1. Isolate the endpoint using the approved process.
2. Quarantine the artifact and preserve evidence.
3. Coordinate with operations before changing an OT asset.

## Unauthorized Privilege Change

Investigation:

1. Identify who requested and performed the assignment.
2. Compare the change with tickets, approvals, and identity audit logs.
3. Review actions performed after the privileges changed.

Potential containment:

1. Remove unauthorized privileges through the approved identity process.
2. Suspend affected sessions and rotate credentials when needed.
3. Review whether the same actor changed other accounts.

## Unauthorized Access Attempt

Investigation:

1. Review the denied resource, account, source, and authentication context.
2. Determine whether the attempt was user error or suspicious behavior.
3. Search for repeated attempts against other resources.

Potential containment:

1. Restrict the source or account if the risk is confirmed.
2. Preserve relevant logs and escalate repeated behavior.

## Suspicious Activity on SCADA / OT-Labeled Systems

Add these steps to every relevant playbook:

1. Coordinate with the operations owner before taking action.
2. Assess safety and availability impact before isolation, restart, or configuration change.
3. Review monitoring and segmentation evidence at the IT/OT boundary.
4. Use approved OT procedures and avoid unplanned shutdowns.
5. Prefer controlled network containment coordinated with operations personnel.

EnergyShield automatically appends these cautions when a hostname or system type matches the configured fictional critical-system labels.

## Documentation

The dashboard can build and save a Markdown report containing the incident summary, evidence explanation, risk factors, ATT&CK context, and recommended steps. In a real SOC, analysts would also record ownership, status, evidence sources, decisions, timestamps, approvals, and lessons learned.
