#!/usr/bin/env python3
"""
Read reports/correlated_incidents.csv and produce a human-readable Markdown report
with counts, highlights, and ATT&CK mapping references.
Outputs: reports/incident_summary_report.md
"""
from pathlib import Path
import csv, json
from collections import Counter

BASE = Path(__file__).resolve().parents[1]
REPORTS = BASE / "reports"
DETECTION = BASE / "detection"

infile = REPORTS / "correlated_incidents.csv"
outfile = REPORTS / "incident_summary_report.md"

# load mitre mapping
mitre = {}
with (DETECTION / "mitre_mapping.json").open() as f:
    mitre = json.load(f)

if not infile.exists():
    md = "# Incident Summary Report\n\nNo incidents found. Run `scripts/correlate_incidents.py` first.\n"
    outfile.write_text(md)
    print(f"Wrote: {outfile}")
    raise SystemExit(0)

rows = []
with infile.open() as f:
    r = csv.DictReader(f)
    for row in r:
        rows.append(row)

# stats
by_source = Counter([x["Source"] for x in rows])
correlated = [x for x in rows if x.get("Correlation") == "YES"]
high_gd = [x for x in rows if x["Source"] == "GuardDuty" and x["Severity"] == "High"]

def map_mitre(event, source):
    if source == "AzureSignin" and event == "Failed Login Burst":
        return mitre.get("AzureSignin-FailedBurst", {})
    if source == "GuardDuty" and "Trojan" in event:
        return mitre.get("GuardDuty-TrojanDropper", {})
    if source == "GuardDuty" and "Portscan" in event:
        return mitre.get("GuardDuty-Portscan", {})
    return {}

lines = []
lines.append("# Incident Summary Report\n")
lines.append("## Overview\n")
lines.append(f"- Total records: **{len(rows)}**\n")
lines.append(f"- By source: **{dict(by_source)}**\n")
lines.append(f"- Correlated multi-cloud incidents: **{len(correlated)}**\n")
lines.append(f"- High severity GuardDuty findings: **{len(high_gd)}**\n")

for i, row in enumerate(rows, start=1):
    mit = map_mitre(row["Event"], row["Source"])
    tack = f"{mit.get('tactic','')}/{mit.get('technique','')}" if mit else "N/A"
    lines.append(f"\n## Incident {i}\n")
    lines.append(f"- Timestamp: {row['Timestamp']}\n")
    lines.append(f"- Source: {row['Source']}\n")
    lines.append(f"- Event: {row['Event']}\n")
    lines.append(f"- Severity: {row['Severity']}\n")
    lines.append(f"- Item: {row['ResourceOrUser']}\n")
    lines.append(f"- Correlation: {row['Correlation']}\n")
    if row.get("CorrelatedUser"):
        lines.append(f"- Correlated User: {row['CorrelatedUser']}\n")
    lines.append(f"- ATT&CK: {tack}\n")
    lines.append(f"- Notes: {row['Notes']}\n")

lines.append("\n---\n")
lines.append("### Recommendations (Simulation)\n")
lines.append("- Enforce MFA and lockout policies; monitor failed sign-in bursts.\n")
lines.append("- Isolate suspected EC2 instances; rotate IAM credentials.\n")
lines.append("- Implement network rate-limiting; review SGs and WAF.\n")

outfile.write_text("".join(lines))
print(f"Wrote: {outfile}")
