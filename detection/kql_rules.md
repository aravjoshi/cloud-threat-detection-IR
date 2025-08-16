# KQL-Style Detection Examples (Illustrative)

> These are conceptual KQL snippets to showcase detection logic recruiters expect.

## 1) Multiple Failed Sign-ins (Potential Brute Force)
```kql
SigninLogs
| where ResultType != "0"                   // non-success
| summarize FailedCount=count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedCount >= 3
