# Cloud Threat Detection & Incident Response (Simulation)

This repository contains a **simulation** of multi-cloud threat detection and incident response workflows using **mock Azure sign-in logs** and **AWS GuardDuty** findings.  
It is portfolio-ready and **does not require live cloud access**.

## What’s Included
- Mock datasets (Azure sign-in CSV, GuardDuty JSON)
- KQL-style detection examples
- Python correlation pipeline → CSV + Markdown report
- MITRE ATT&CK mapping for detections
- IR playbooks and architecture diagram (Mermaid)




## Quickstart
```bash
# 1) (Optional) create venv, but only stdlib is used
python3 -V   # Python 3.8+
# 2) Run the full pipeline
python3 scripts/run_all.py
# Outputs:
# - reports/correlated_incidents.csv
# - reports/incident_summary_report.md

OR RUN STEP BY STEP
python3 scripts/correlate_incidents.py
python3 scripts/generate_incident_report.py


Dataset Overview

datasets/azure_sentinel_mock_logs.csv – Azure sign-in events (success/failed).

datasets/aws_guardduty_mock_findings.json – Sample GuardDuty findings.

Detection Logic (high level)

Brute-force/Password spray: multiple failed sign-ins for a user in a short window.

GuardDuty High-Severity: EC2 malware/dropper or reconnaissance.

Simple multi-cloud correlation: If high failed-login activity occurs within ±2h of a GuardDuty finding, it’s flagged as a correlated incident.

MITRE ATT&CK Mapping

Sign-in brute force → TA0006: Credential Access / T1110: Brute Force

GuardDuty Trojan/Dropper → TA0002: Execution / T1204

Port Scan Recon → TA0043: Reconnaissance

See: detection/mitre_mapping.json

IR Playbooks

Actionable steps for triage, containment, and recovery are in docs/playbooks.md.

Architecture

Mermaid diagram in docs/architecture.mmd. GitHub renders it automatically.

Skills Demonstrated

SIEM concepts (Azure Sentinel-style detections, KQL examples)

Multi-cloud correlation

Python automation for detection → reporting

ATT&CK mapping and IR playbooks

Notes

This is a deterministic simulation built for recruiters to run locally without cloud creds.

All code uses Python stdlib only.
