# KQL-Style Detection Examples (Illustrative)

> These are conceptual KQL snippets to showcase detection logic recruiters expect.

## 1) Multiple Failed Sign-ins (Potential Brute Force)
```kql
SigninLogs
| where ResultType != "0"                   // non-success
| summarize FailedCount=count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedCount >= 3
```
2) Impossible Travel (not used in code, extra)
SigninLogs
| summarize arg_min(TimeGenerated, Location) by UserPrincipalName
| order by UserPrincipalName, TimeGenerated asc
| extend PrevLocation=prev(Location)
| where PrevLocation != "" and Location != PrevLocation and
       datetime_diff("minute", TimeGenerated, prev(TimeGenerated)) < 60

3) High-Severity GuardDuty

(in AWS you’d filter on severity >= 7; shown here conceptually)

GuardDutyFindings
| where severity >= 7
