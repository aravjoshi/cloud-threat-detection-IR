#!/usr/bin/env python3
"""
Convenience runner: executes correlation and report generation.
"""
import subprocess, sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
scripts = BASE / "scripts"

steps = [
    [sys.executable, str(scripts / "correlate_incidents.py")],
    [sys.executable, str(scripts / "generate_incident_report.py")]
]

for cmd in steps:
    print(">>", " ".join(cmd))
    subprocess.check_call(cmd)
print("\nPipeline complete. See the 'reports/' folder.")
