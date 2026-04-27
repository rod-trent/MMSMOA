# Demo: DLP Policy for Microsoft 365 Copilot
## Blocking sensitive data from appearing in Copilot prompts and responses

This script creates a Data Loss Prevention policy targeting the
**Microsoft 365 Copilot interaction** workload — blocking or warning when
users attempt to paste or reference sensitive information in Copilot prompts,
and preventing Copilot from surfacing sensitive data in its responses.

## Prerequisites
```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Running the Demo
```powershell
# Preview mode — show what would be created
.\Create-CopilotDLPPolicy.ps1 -WhatIf

# Create the policy in test (audit-only) mode
.\Create-CopilotDLPPolicy.ps1

# Create in enforcement mode (blocks immediately)
.\Create-CopilotDLPPolicy.ps1 -EnforcementMode Block
```

## Policy Rules Created

| Rule | Sensitive Info Types | Action |
|------|---------------------|--------|
| Block-PII | SSN, Passport, Driver's License, Credit Card | Block + notify |
| Block-PHI | Medical record numbers, DEA numbers, ICD codes | Block + notify |
| Warn-Credentials | Passwords, API keys, connection strings | Warn (allow override) |
| Block-Financial | Bank accounts, SWIFT codes, IBAN | Block + notify |

## How DLP Works with Copilot
- **Prompts**: If a user pastes text containing an SSN into Copilot for Microsoft 365, the prompt is blocked before it reaches the AI model.
- **Responses**: If Copilot would surface a document containing credit card numbers, DLP blocks the response and notifies the user.
- **Audit log**: All DLP events are captured in `Search-UnifiedAuditLog` under operation `DLPRuleMatch`.

## Presenter Notes
> "This is probably the most impactful thing you can do in a day. DLP policies for
> Copilot take about 15 minutes to configure and immediately protect against the
> most common AI data exfiltration scenarios — employees accidentally prompting
> with PII or PHI data."
>
> After creating the policy, open a browser with Copilot for Microsoft 365 and
> paste a fake SSN (e.g., `123-45-6789`) into the prompt box. The DLP policy
> will intercept it within minutes of policy creation.
