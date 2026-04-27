# Demo: Copilot Audit Log Analysis
## Understanding what users are doing with Microsoft 365 Copilot

This script queries the Microsoft Purview Unified Audit Log for all Copilot
interaction events and produces a comprehensive usage and risk report.

## Prerequisites
```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Running the Demo
```powershell
# Last 7 days (default)
.\Analyze-CopilotAuditLogs.ps1

# Last 30 days
.\Analyze-CopilotAuditLogs.ps1 -Days 30

# Focus on a specific user
.\Analyze-CopilotAuditLogs.ps1 -UserPrincipalName user@contoso.com

# Export CSV report
.\Analyze-CopilotAuditLogs.ps1 -ExportCsv .\copilot-audit-report.csv

# Export HTML dashboard
.\Analyze-CopilotAuditLogs.ps1 -ExportHtml .\copilot-dashboard.html
```

## What the Report Shows
- **Volume**: Total Copilot interactions by day, user, and workload
- **Top Users**: Users with highest interaction counts
- **Workload Distribution**: Copilot in Word vs. Teams vs. Outlook vs. others
- **DLP Hits**: Policy matches during Copilot sessions
- **Sensitive Labels Referenced**: Which sensitivity labels appeared in Copilot interactions
- **After-Hours Activity**: Interactions outside business hours (potential exfiltration risk signal)

## Audit Events Analyzed
| Operation | Description |
|-----------|-------------|
| `CopilotInteraction` | User sent a prompt to Copilot |
| `AIPluginInteraction` | Copilot invoked a plugin/tool |
| `DLPRuleMatch` | DLP policy triggered during Copilot |

## Presenter Notes
> "The audit log is your camera — it captures everything Copilot does on behalf
> of your users. Before you can answer 'did someone use Copilot to access data
> they shouldn't have?', you need to be querying this log on a schedule."
>
> Run the script live, then scroll to the DLP Hits section. Even in a clean demo
> tenant you'll see some events. Ask the audience: "What would you do if you
> saw 50 DLP hits for a single user in one day?"
