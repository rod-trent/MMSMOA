# Demo: Copilot Governance Autopilot Agent
## Secure your Microsoft 365 tenant in 90 seconds — one command, full lifecycle

This agent orchestrates all four governance demos into a single end-to-end workflow,
culminating in an executive-ready HTML scorecard with a compliance grade.

## What It Does

| Phase | Action | Output |
|-------|--------|--------|
| 1 | Deploy 4-tier sensitivity label taxonomy + auto-labeling policy | 13 labels across Public → Highly Confidential |
| 2 | Create DLP policy targeting Microsoft 365 Copilot interactions | 4 rules: PII, PHI, Credentials, Financial |
| 3 | Test DLP enforcement with simulated sensitive prompts | 6 test patterns evaluated (block/warn/allow) |
| 4 | Analyze Copilot audit logs for usage and risk signals | Volume trends, top users, DLP hits, after-hours activity |
| 5 | Generate unified executive governance scorecard | HTML report with compliance score (A+ to C) |

## Running the Demo

```powershell
# Simulation mode — no tenant connection, realistic demo data (conference-safe)
.\Invoke-GovernanceAutopilot.ps1 -SimulateMode

# Live mode — deploys real policies to your tenant
.\Invoke-GovernanceAutopilot.ps1 -LiveMode -Force

# Live mode with prefix (safe for shared/demo tenants)
.\Invoke-GovernanceAutopilot.ps1 -LiveMode -LabelPrefix "MMS_" -Force

# Skip specific phases (e.g., skip labels if already deployed)
.\Invoke-GovernanceAutopilot.ps1 -SimulateMode -SkipPhase 1,2

# Custom output path for the scorecard
.\Invoke-GovernanceAutopilot.ps1 -SimulateMode -OutputPath C:\Reports\scorecard.html
```

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-SimulateMode` | Run offline with simulated data (no tenant needed) | Default if neither specified |
| `-LiveMode` | Connect to tenant and deploy real policies | — |
| `-LabelPrefix` | Prefix for all created resources (avoids conflicts) | `""` |
| `-OutputPath` | Path for the HTML scorecard | Script directory |
| `-SkipPhase` | Array of phase numbers to skip (1-4) | `@()` |
| `-Force` | Skip all confirmation prompts | `$false` |

## Prerequisites

For **Simulate Mode**: None — runs fully offline.

For **Live Mode**:
```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Microsoft.Graph -Scope CurrentUser
```

Requires:
- Global Admin or Compliance Admin role
- Microsoft 365 Copilot licenses (for audit log data)
- Purview Audit enabled in the tenant

## Agent Platform Integration

Import `governance-autopilot-agent.json` into the AI Agent Platform to schedule
or chain this agent with other governance workflows.

| Setting | Value |
|---------|-------|
| Schedule | `0 6 * * 1` (Monday 6am — weekly governance check) |
| Timeout | 120 seconds |
| Group | Governance & Compliance |
| Default args | `-SimulateMode` (change to `-LiveMode -Force` for production) |

## Output: Governance Scorecard

The HTML scorecard includes:

- **Compliance score** (A+ through C) with visual ring indicator
- **Deployment timer** showing total elapsed seconds
- **Phase timeline** with pass/fail status per phase
- **Key metrics cards** — labels deployed, DLP rules, blocked prompts, interactions
- **Sensitivity label taxonomy** — full hierarchy with encryption status
- **DLP rule cards** — visual breakdown of each rule and its sensitive info types
- **Enforcement test results** — table of simulated prompts with block/warn/allow badges
- **Audit analysis** — daily volume chart, top users, workload distribution
- **Recommended next steps** — prioritized actions with impact ratings

## Presenter Notes

> "Everything you just watched me do across four separate demos? This agent does
> it in a single command. Labels, DLP, enforcement testing, audit analysis, and
> an executive report — all in under 90 seconds. That's what governance automation
> looks like."
>
> Run the simulation live on stage. The timer in the output and the scorecard both
> reinforce the speed message. Open the HTML scorecard in a browser for the visual
> payoff — the dark theme looks great on projectors.
>
> Key talking point: "This isn't just a demo trick. Schedule this agent weekly and
> you have continuous governance posture reporting — without logging into a portal."

## Files

| File | Purpose |
|------|---------|
| `Invoke-GovernanceAutopilot.ps1` | Main orchestration script |
| `governance-autopilot-agent.json` | Agent platform configuration (importable) |
| `governance-scorecard.html` | Generated output (created on run) |
| `README.md` | This file |
