#!/usr/bin/env python3
"""
Correlate Azure sign-in failures with AWS GuardDuty findings and output a unified CSV.
- Flags "failed login burst" if a user has >=3 failures within 10 minutes.
- Marks incidents as CORRELATED if a GuardDuty finding occurs within +/- 120 minutes of a failed burst window.
Outputs: reports/correlated_incidents.csv
"""
from pathlib import Path
import csv, json
from datetime import datetime, timedelta

BASE = Path(__file__).resolve().parents[1]
DATASETS = BASE / "datasets"
REPORTS = BASE / "reports"
DETECTION = BASE / "detection"
REPORTS.mkdir(exist_ok=True, parents=True)

# ---- helpers
ISO = "%Y-%m-%dT%H:%M:%SZ"
def parse_ts(s): return datetime.strptime(s, ISO)

# load azure logs
azure_rows = []
with (DATASETS / "azure_sentinel_mock_logs.csv").open() as f:
    r = csv.DictReader(f)
    for row in r:
        row["Timestamp"] = row["Timestamp"].strip()
        row["ts"] = parse_ts(row["Timestamp"])
        azure_rows.append(row)

# load guardduty findings
with (DATASETS / "aws_guardduty_mock_findings.json").open() as f:
    gd = json.load(f)
for g in gd:
    g["ts"] = parse_ts(g["time"])

# detect failed login bursts per user (>=3 failures within 10 minutes)
failed_bursts = []  # list of dicts: user, start, end, count
from collections import defaultdict, deque
events_by_user = defaultdict(list)
for a in azure_rows:
    if a.get("Status") == "Failed":
        events_by_user[a["User"]].append(a)

for user, evts in events_by_user.items():
    evts.sort(key=lambda x: x["ts"])
    window = deque()
    for e in evts:
        window.append(e)
        # shrink window to 10 minutes
        while (window[-1]["ts"] - window[0]["ts"]) > timedelta(minutes=10):
            window.popleft()
        if len(window) >= 3:
            failed_bursts.append({
                "User": user,
                "Start": window[0]["ts"],
                "End": window[-1]["ts"],
                "Count": len(window)
            })

# correlate with GuardDuty within +/- 120 minutes
def is_correlated(burst, finding):
    return abs(finding["ts"] - burst["End"]) <= timedelta(minutes=120)

rows_out = []
# include all GuardDuty findings
for g in gd:
    sev_label = "High" if g["severity"] >= 7 else "Medium" if g["severity"] >= 4 else "Low"
    mitre_key = "GuardDuty-TrojanDropper" if "Trojan" in g["type"] else (
                "GuardDuty-Portscan" if "Portscan" in g["type"] else "GuardDuty-Other")
    correlated = False
    corr_user = ""
    for burst in failed_bursts:
        if is_correlated(burst, g):
            correlated = True
            corr_user = burst["User"]
            break
    rows_out.append({
        "Timestamp": g["time"],
        "Source": "GuardDuty",
        "Event": g["type"],
        "Severity": sev_label,
        "ResourceOrUser": g["resource"],
        "Correlation": "YES" if correlated else "NO",
        "CorrelatedUser": corr_user,
        "Notes": "Mock GD finding"
    })

# include azure failed login events (summarized as bursts)
for b in failed_bursts:
    rows_out.append({
        "Timestamp": b["End"].strftime(ISO),
        "Source": "AzureSignin",
        "Event": "Failed Login Burst",
        "Severity": "Medium",
        "ResourceOrUser": b["User"],
        "Correlation": "N/A",
        "CorrelatedUser": b["User"],
        "Notes": f"{b['Count']} failures in 10m window"
    })

# write CSV
out = REPORTS / "correlated_incidents.csv"
with out.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=[
        "Timestamp","Source","Event","Severity","ResourceOrUser","Correlation","CorrelatedUser","Notes"
    ])
    writer.writeheader()
    for r in sorted(rows_out, key=lambda x: x["Timestamp"]):
        writer.writerow(r)

print(f"Wrote: {out}")
