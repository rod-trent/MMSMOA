<#
.SYNOPSIS
    Demonstrates DLP enforcement on Microsoft 365 Copilot: shows test patterns,
    queries blocked/warned interactions, and generates an enforcement report.

.DESCRIPTION
    Demo: "Blocking Sensitive Prompts in Practice"
    Session: Governing GenAI — Monitoring and Securing Copilot with Microsoft Purview
    Conference: MMS MOA 2026

    Three modes of operation:

    1. SIMULATE (-SimulateMode): No tenant connection needed. Shows the test
       patterns that trigger each rule and simulates what an enforcement report
       would look like with realistic sample data.

    2. LIVE (default): Connects to the tenant and queries real DLP audit events
       for Copilot interactions. Shows blocked and warned prompts.

    3. REPORT (-ExportReport): Generates a CSV suitable for incident review.

.PARAMETER Days
    How many days back to query. Default: 7.

.PARAMETER ShowBlockedOnly
    Filter to only show blocked events (not warns or audits).

.PARAMETER SimulateMode
    Run in offline simulation mode — no tenant connection required. Great for
    demos in environments without Copilot licenses or audit logs.

.PARAMETER PolicyName
    Name of the Copilot DLP policy to check. Default matches Create-CopilotDLPPolicy.ps1 output.

.PARAMETER ExportReport
    Optional. Path to export enforcement events as CSV.

.EXAMPLE
    .\Test-DLPEnforcement.ps1 -SimulateMode
    .\Test-DLPEnforcement.ps1 -Days 30 -ShowBlockedOnly
    .\Test-DLPEnforcement.ps1 -ExportReport .\dlp-blocks.csv
#>

[CmdletBinding()]
param(
    [int]$Days = 7,
    [switch]$ShowBlockedOnly,
    [switch]$SimulateMode,
    [string]$PolicyName = "Copilot-DLP-Governance",
    [string]$ExportReport = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Section([string]$Title, [string]$Color = "Cyan") {
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  │  $Title" -ForegroundColor $Color
    Write-Host "  └─────────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
}

function Write-TestPattern([string]$RuleName, [string]$Trigger, [string]$SampleData, [string]$Action) {
    $actionColor = if ($Action -eq "BLOCK") { "Red" } elseif ($Action -eq "WARN") { "Yellow" } else { "Green" }
    Write-Host ""
    Write-Host "  Rule    : $RuleName" -ForegroundColor White
    Write-Host "  Trigger : $Trigger" -ForegroundColor Gray
    Write-Host "  Sample  : " -NoNewline -ForegroundColor Gray
    Write-Host $SampleData -ForegroundColor DarkYellow
    Write-Host "  Action  : " -NoNewline -ForegroundColor Gray
    Write-Host "[$Action]" -ForegroundColor $actionColor
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
}

# ── Show test patterns (always — regardless of mode) ─────────────────────────

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  DLP ENFORCEMENT — Microsoft 365 Copilot" -ForegroundColor Cyan
Write-Host "  Policy: $PolicyName" -ForegroundColor Gray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

Write-Section "TEST PATTERNS — What Triggers Each Rule"
Write-Host "  These are the input patterns that would trigger DLP enforcement." -ForegroundColor Gray
Write-Host "  Try them in Copilot for Microsoft 365 to see enforcement in action." -ForegroundColor Gray

Write-TestPattern `
    -RuleName   "Block-PII-In-Copilot" `
    -Trigger    "U.S. Social Security Number" `
    -SampleData 'Summarize this employee: John Smith, SSN 523-45-6789, DOB 1985-03-12' `
    -Action     "BLOCK"

Write-TestPattern `
    -RuleName   "Block-PII-In-Copilot" `
    -Trigger    "Credit Card Number" `
    -SampleData 'Draft a refund email for customer card 4532-1234-5678-9012 exp 03/26' `
    -Action     "BLOCK"

Write-TestPattern `
    -RuleName   "Block-PHI-In-Copilot" `
    -Trigger    "Health Insurance Number" `
    -SampleData 'Summarize the treatment plan for patient with insurance ID 1EG4-TE5-MK72' `
    -Action     "BLOCK"

Write-TestPattern `
    -RuleName   "Block-Financial-In-Copilot" `
    -Trigger    "Bank Account Number" `
    -SampleData 'Wire transfer instructions for account 12345678901 routing 021000021' `
    -Action     "BLOCK"

Write-TestPattern `
    -RuleName   "Warn-Credentials-In-Copilot" `
    -Trigger    "Azure AD Client Secret / Password" `
    -SampleData 'Debug this config: client_secret=Abc123!@#$XyZ789 tenant=contoso.onmicrosoft.com' `
    -Action     "WARN"

Write-TestPattern `
    -RuleName   "(No match — allowed)" `
    -Trigger    "General business question" `
    -SampleData 'Summarize the Q3 sales report and highlight key themes' `
    -Action     "ALLOW"

# ── Simulate mode ─────────────────────────────────────────────────────────────

if ($SimulateMode) {
    Write-Section "SIMULATED ENFORCEMENT REPORT (No live tenant connection)"
    Write-Host "  Showing realistic sample DLP enforcement data." -ForegroundColor Gray
    Write-Host "  In a live demo, this would show your actual blocked Copilot interactions." -ForegroundColor Gray

    $SimulatedEvents = @(
        [PSCustomObject]@{ Time="2026-01-14 09:23"; User="alice@contoso.com";   Rule="Block-PII-In-Copilot";        Action="Blocked"; SIT="U.S. Social Security Number"; Workload="Microsoft365Copilot" }
        [PSCustomObject]@{ Time="2026-01-14 10:47"; User="bob@contoso.com";     Rule="Warn-Credentials-In-Copilot"; Action="Warned";  SIT="General Password";            Workload="Microsoft365Copilot" }
        [PSCustomObject]@{ Time="2026-01-14 11:15"; User="carol@contoso.com";   Rule="Block-PII-In-Copilot";        Action="Blocked"; SIT="Credit Card Number";           Workload="Microsoft365Copilot" }
        [PSCustomObject]@{ Time="2026-01-14 14:02"; User="alice@contoso.com";   Rule="Block-Financial-In-Copilot";  Action="Blocked"; SIT="ABA Routing Number";           Workload="Microsoft365Copilot" }
        [PSCustomObject]@{ Time="2026-01-15 08:30"; User="dave@contoso.com";    Rule="Block-PHI-In-Copilot";        Action="Blocked"; SIT="U.S. Health Insurance Number"; Workload="Microsoft365Copilot" }
        [PSCustomObject]@{ Time="2026-01-15 16:55"; User="alice@contoso.com";   Rule="Block-PII-In-Copilot";        Action="Blocked"; SIT="U.S. Social Security Number"; Workload="Microsoft365Copilot" }
        [PSCustomObject]@{ Time="2026-01-15 23:12"; User="eve@contoso.com";     Rule="Block-Financial-In-Copilot";  Action="Blocked"; SIT="SWIFT Code";                   Workload="Microsoft365Copilot" }
        [PSCustomObject]@{ Time="2026-01-16 07:44"; User="bob@contoso.com";     Rule="Warn-Credentials-In-Copilot"; Action="Warned";  SIT="Azure AD Client Secret";      Workload="Microsoft365Copilot" }
    )

    if ($ShowBlockedOnly) {
        $SimulatedEvents = $SimulatedEvents | Where-Object { $_.Action -eq "Blocked" }
    }

    Write-Host ""
    Write-Host ("  {0,-20} {1,-30} {2,-40} {3,-10}" -f "Time", "User", "Rule", "Action") -ForegroundColor DarkCyan
    Write-Host ("  {0,-20} {1,-30} {2,-40} {3,-10}" -f "────────────────────", "──────────────────────────────", "────────────────────────────────────────", "──────────") -ForegroundColor DarkGray

    $SimulatedEvents | ForEach-Object {
        $color = if ($_.Action -eq "Blocked") { "Red" } elseif ($_.Action -eq "Warned") { "Yellow" } else { "Green" }
        Write-Host ("  {0,-20} {1,-30} {2,-40} " -f $_.Time, $_.User, $_.Rule) -NoNewline -ForegroundColor White
        Write-Host $_.Action -ForegroundColor $color
    }

    Write-Host ""
    $blocked = ($SimulatedEvents | Where-Object { $_.Action -eq "Blocked" }).Count
    $warned  = ($SimulatedEvents | Where-Object { $_.Action -eq "Warned"  }).Count
    Write-Host "  Totals: $blocked BLOCKED  |  $warned WARNED" -ForegroundColor Yellow

    Write-Section "TOP USERS BY DLP VIOLATIONS (Simulated)"
    $SimulatedEvents | Group-Object User | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name.PadRight(35)) $($_.Count) events" -ForegroundColor White
    }

    if ($ExportReport) {
        $SimulatedEvents | Export-Csv -Path $ExportReport -NoTypeInformation -Encoding UTF8
        Write-Host "`n  ✓ Simulated report exported to: $ExportReport" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host " [SIMULATE MODE] Connect to a real tenant for live enforcement data." -ForegroundColor Gray
    Write-Host " Run: .\Test-DLPEnforcement.ps1 (without -SimulateMode)" -ForegroundColor Gray
    exit 0
}

# ── Live mode ─────────────────────────────────────────────────────────────────

Write-Host "`n[1/4] Connecting to Exchange Online..." -ForegroundColor Cyan

if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
    Write-Error "Module 'ExchangeOnlineManagement' not found. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
}

if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
    Connect-ExchangeOnline -ShowBanner:$false
    Write-Host "  ✓ Connected." -ForegroundColor Green
} else {
    Write-Host "  ✓ Already connected." -ForegroundColor Green
}

# ── Check policy status ───────────────────────────────────────────────────────

Write-Host "`n[2/4] Checking DLP policy status..." -ForegroundColor Cyan

if (-not (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)) {
    Connect-IPPSSession -UseRPSSession:$false
}

$policy = Get-DlpCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue
if ($policy) {
    $modeColor = switch ($policy.Mode) {
        "Enable"                    { "Red"    }
        "TestWithNotifications"     { "Yellow" }
        "TestWithoutNotifications"  { "Gray"   }
        default                     { "White"  }
    }
    Write-Host "  Policy     : $($policy.Name)" -ForegroundColor White
    Write-Host "  Mode       : " -NoNewline -ForegroundColor White
    Write-Host $policy.Mode -ForegroundColor $modeColor
    Write-Host "  Last Modified: $($policy.WhenChanged)" -ForegroundColor Gray
    if ($policy.Mode -ne "Enable") {
        Write-Host "  ⚠  Policy is NOT in enforcement mode. Events are audited only." -ForegroundColor Yellow
        Write-Host "     To enforce: Set-DlpCompliancePolicy -Identity '$PolicyName' -Mode Enable" -ForegroundColor Gray
    }
} else {
    Write-Host "  ⚠  Policy '$PolicyName' not found." -ForegroundColor Yellow
    Write-Host "     Run .\Create-CopilotDLPPolicy.ps1 to create it." -ForegroundColor Gray
}

# ── Query DLP events ──────────────────────────────────────────────────────────

Write-Host "`n[3/4] Querying DLP audit events for Copilot (last $Days days)..." -ForegroundColor Cyan

$EndDate   = Get-Date
$StartDate = $EndDate.AddDays(-$Days)
$AllDlp    = @()
$sessionId = "DLPCopilot-$(Get-Date -Format 'yyyyMMddHHmmss')"
$hasMore   = $true
$page      = 1

while ($hasMore) {
    $batch = Search-UnifiedAuditLog `
        -StartDate      $StartDate `
        -EndDate        $EndDate `
        -Operations     "DLPRuleMatch" `
        -ResultSize     5000 `
        -SessionId      $sessionId `
        -SessionCommand "ReturnLargeSet"

    if ($batch -and $batch.Count -gt 0) {
        # Filter to Copilot workload
        $copilotDlp = $batch | Where-Object {
            $data = $_.AuditData | ConvertFrom-Json -ErrorAction SilentlyContinue
            $data -and ($data.Workload -match "Copilot" -or $data.PolicyDetails.PolicyName -match "Copilot")
        }
        $AllDlp += $copilotDlp
        Write-Host "  Page $page: $($batch.Count) raw events → $($copilotDlp.Count) Copilot DLP events" -ForegroundColor Gray
        $page++
        if ($batch.Count -lt 5000) { $hasMore = $false }
    } else {
        $hasMore = $false
    }
}

Write-Host "  ✓ Total Copilot DLP events: $($AllDlp.Count)" -ForegroundColor $(if ($AllDlp.Count -gt 0) { "Yellow" } else { "Green" })

# ── Parse and display ─────────────────────────────────────────────────────────

Write-Host "`n[4/4] Building enforcement report..." -ForegroundColor Cyan

if ($AllDlp.Count -eq 0) {
    Write-Host ""
    Write-Host "  ✓ No DLP events for Copilot found in the last $Days days." -ForegroundColor Green
    Write-Host "  This means either:" -ForegroundColor Gray
    Write-Host "    • No users triggered DLP rules in Copilot (good!)" -ForegroundColor Gray
    Write-Host "    • Policy was recently created and events haven't occurred yet" -ForegroundColor Gray
    Write-Host "    • Try the test patterns above to generate events, then rerun in 15 mins" -ForegroundColor Gray
    exit 0
}

$ParsedDlp = $AllDlp | ForEach-Object {
    $data = $_.AuditData | ConvertFrom-Json -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Time     = $_.CreationDate.ToString("yyyy-MM-dd HH:mm")
        User     = $_.UserIds
        Rule     = ($data.PolicyDetails.Rules | Select-Object -First 1).RuleName
        Policy   = ($data.PolicyDetails | Select-Object -First 1).PolicyName
        Action   = ($data.PolicyDetails.Rules | Select-Object -First 1).ActionParameters.Action
        SIT      = (($data.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveType | Select-Object -ExpandProperty Name) -join ", ")
        Workload = $data.Workload
    }
}

if ($ShowBlockedOnly) {
    $ParsedDlp = $ParsedDlp | Where-Object { $_.Action -match "Block" }
}

Write-Section "ENFORCEMENT EVENTS"
Write-Host ""
Write-Host ("  {0,-20} {1,-30} {2,-35} {3,-10}" -f "Time", "User", "Rule", "Action") -ForegroundColor DarkCyan
Write-Host ("  {0,-20} {1,-30} {2,-35} {3,-10}" -f "────────────────────", "──────────────────────────────", "───────────────────────────────────", "──────────") -ForegroundColor DarkGray

$ParsedDlp | Sort-Object Time -Descending | ForEach-Object {
    $color = if ($_.Action -match "Block") { "Red" } elseif ($_.Action -match "Override") { "Yellow" } else { "White" }
    Write-Host ("  {0,-20} {1,-30} {2,-35} " -f $_.Time, $_.User, $_.Rule) -NoNewline -ForegroundColor White
    Write-Host $_.Action -ForegroundColor $color
}

Write-Section "TOP VIOLATORS"
$ParsedDlp | Group-Object User | Sort-Object Count -Descending | Select-Object -First $ShowTopN ?? 10 | ForEach-Object {
    Write-Host "  $($_.Name.PadRight(40)) $($_.Count) events" -ForegroundColor White
}

if ($ExportReport) {
    $ParsedDlp | Export-Csv -Path $ExportReport -NoTypeInformation -Encoding UTF8
    Write-Host "`n  ✓ Report exported to: $ExportReport" -ForegroundColor Green
}

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " INVESTIGATION GUIDANCE:" -ForegroundColor Yellow
Write-Host "  • Users with >5 DLP events/day warrant a conversation with their manager" -ForegroundColor White
Write-Host "  • Warn-with-override events: check if users are overriding with valid justification" -ForegroundColor White
Write-Host "  • After-hours DLP blocks are a strong signal for insider threat investigation" -ForegroundColor White
Write-Host "  • Correlate with Sentinel: pipe DLP events into Log Analytics for SIEM alerting" -ForegroundColor White
Write-Host ""
