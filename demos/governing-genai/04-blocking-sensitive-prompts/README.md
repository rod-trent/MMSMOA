# Demo: Blocking Sensitive Prompts in Practice
## Showing DLP enforcement and investigating blocked Copilot interactions

This script demonstrates the end-to-end flow of DLP enforcement on Copilot:
1. Shows test patterns that trigger each DLP rule
2. Queries the audit log for recent DLP block events on Copilot
3. Generates a report of blocked interactions for security review

## Prerequisites
```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Running the Demo
```powershell
# Show test patterns and recent DLP events (default)
.\Test-DLPEnforcement.ps1

# Show only blocked events for the last 7 days
.\Test-DLPEnforcement.ps1 -Days 7 -ShowBlockedOnly

# Generate enforcement report
.\Test-DLPEnforcement.ps1 -ExportReport .\dlp-enforcement-report.csv

# Simulate (show what would be blocked without connecting to live tenant)
.\Test-DLPEnforcement.ps1 -SimulateMode
```

## What the Script Shows
1. **Test patterns**: Examples of data that triggers each DLP rule (PII, PHI, credentials, financial)
2. **Policy status**: Current state of the Copilot DLP policy (enabled/audit/disabled)
3. **Recent blocks**: Audit log entries for `DLPRuleMatch` events on Copilot
4. **User impact**: Which users triggered the most DLP events
5. **Escalation guidance**: How to investigate and respond to DLP violations

## Presenter Notes
> "Now we can see the policy working. Notice that even in TestWithNotifications
> mode, we get full audit records of everything that would have been blocked.
> This lets you tune the policy before you flip the enforcement switch."
>
> Key talking point: DLP blocks happen at the prompt layer — before the AI ever
> sees the sensitive data. This is fundamentally different from monitoring
> what Copilot responded with after the fact.
