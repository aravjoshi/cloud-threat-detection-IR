# Incident Response Playbooks (Simulation)

## P1: High-Severity GuardDuty + Failed Sign-in Burst
- **Triage**
  - Validate GuardDuty `severity >= 7` finding context.
  - Check Azure sign-in burst (≥3 failures in 5–10 min).
- **Containment**
  - Isolate impacted EC2 instance (security group deny-all).
  - Force user password reset; enable MFA.
- **Eradication**
  - Rebuild instance from clean AMI; rotate IAM creds.
- **Recovery**
  - Re-enable traffic with least-privilege SG rules; monitor for recurrence.
- **Lessons Learned**
  - Add alert thresholds; enforce MFA and lockout policy.

## P2: Recon Only (Portscan)
- **Triage**: Confirm source IP and scope.
- **Containment**: Rate-limit or block at edge.
- **Follow-up**: Hunt for lateral movement; add WAF rules.
