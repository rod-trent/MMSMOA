<#
.SYNOPSIS
    Queries the Purview Unified Audit Log for Microsoft 365 Copilot interaction
    events and generates a usage and risk analysis report.

.DESCRIPTION
    Demo: "Copilot Audit Log Analysis"
    Session: Governing GenAI — Monitoring and Securing Copilot with Microsoft Purview
    Conference: MMS MOA 2026

    Analyzes CopilotInteraction, AIPluginInteraction, and DLPRuleMatch events
    from the Unified Audit Log and produces:
      - Interaction volume trends by day
      - Top users by Copilot usage
      - Workload distribution (Word, Teams, Outlook, etc.)
      - DLP policy matches during Copilot sessions
      - After-hours activity patterns
      - Sensitivity label usage in Copilot interactions

.PARAMETER Days
    Number of days to look back. Default: 7.

.PARAMETER UserPrincipalName
    Optional. Limit results to a specific user.

.PARAMETER ExportCsv
    Optional. Path to export raw events as CSV.

.PARAMETER ExportHtml
    Optional. Path to export an HTML dashboard report.

.PARAMETER ShowTopN
    How many top users/workloads to display. Default: 10.

.EXAMPLE
    .\Analyze-CopilotAuditLogs.ps1
    .\Analyze-CopilotAuditLogs.ps1 -Days 30 -ExportCsv .\report.csv
    .\Analyze-CopilotAuditLogs.ps1 -UserPrincipalName alice@contoso.com
#>

[CmdletBinding()]
param(
    [int]$Days = 7,
    [string]$UserPrincipalName = "",
    [string]$ExportCsv = "",
    [string]$ExportHtml = "",
    [int]$ShowTopN = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Prerequisites ─────────────────────────────────────────────────────────────

function Assert-Module([string]$Name) {
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Error "Module '$Name' not found. Run: Install-Module $Name -Scope CurrentUser"
    }
}

Assert-Module "ExchangeOnlineManagement"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  │  $Title" -ForegroundColor Cyan
    Write-Host "  └─────────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
}

function Format-Bar([int]$Value, [int]$Max, [int]$Width = 30) {
    $filled = if ($Max -gt 0) { [int]([Math]::Round($Value / $Max * $Width)) } else { 0 }
    $bar    = ("█" * $filled).PadRight($Width)
    return $bar
}

# ── Connection ────────────────────────────────────────────────────────────────

Write-Host "`n[1/6] Connecting to Exchange Online (Unified Audit Log)..." -ForegroundColor Cyan

if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
    Connect-ExchangeOnline -ShowBanner:$false
    Write-Host "  ✓ Connected." -ForegroundColor Green
} else {
    Write-Host "  ✓ Already connected." -ForegroundColor Green
}

# ── Audit log query ───────────────────────────────────────────────────────────

$EndDate   = Get-Date
$StartDate = $EndDate.AddDays(-$Days)

Write-Host "`n[2/6] Querying Unified Audit Log ($Days days: $($StartDate.ToString('yyyy-MM-dd')) → $($EndDate.ToString('yyyy-MM-dd')))..." -ForegroundColor Cyan

$AllEvents = @()
$Operations = @("CopilotInteraction", "AIPluginInteraction", "DLPRuleMatch")

foreach ($op in $Operations) {
    Write-Host "  → Fetching: $op" -ForegroundColor Gray
    $page        = 1
    $sessionId   = "CopilotAudit-$(Get-Date -Format 'yyyyMMddHHmmss')-$op"
    $hasMore     = $true

    while ($hasMore) {
        $params = @{
            StartDate   = $StartDate
            EndDate     = $EndDate
            Operations  = $op
            ResultSize  = 5000
            SessionId   = $sessionId
            SessionCommand = "ReturnLargeSet"
        }

        if ($UserPrincipalName) { $params.UserIds = $UserPrincipalName }

        $batch = Search-UnifiedAuditLog @params

        if ($batch -and $batch.Count -gt 0) {
            $AllEvents += $batch
            Write-Host "    Page $page: $($batch.Count) events (total: $($AllEvents.Count))" -ForegroundColor Gray
            $page++
            if ($batch.Count -lt 5000) { $hasMore = $false }
        } else {
            $hasMore = $false
        }
    }
}

Write-Host "  ✓ Total events retrieved: $($AllEvents.Count)" -ForegroundColor Green

if ($AllEvents.Count -eq 0) {
    Write-Host ""
    Write-Warning "No Copilot audit events found in the last $Days days."
    Write-Host "  Possible reasons:" -ForegroundColor Yellow
    Write-Host "    • Audit logging is not enabled (check compliance.microsoft.com > Audit)" -ForegroundColor Gray
    Write-Host "    • No Copilot licenses assigned in this tenant" -ForegroundColor Gray
    Write-Host "    • The search window is too narrow — try -Days 30" -ForegroundColor Gray
    exit 0
}

# ── Parse events ──────────────────────────────────────────────────────────────

Write-Host "`n[3/6] Parsing audit events..." -ForegroundColor Cyan

$Parsed = $AllEvents | ForEach-Object {
    $auditData = $null
    try {
        $auditData = $_.AuditData | ConvertFrom-Json -ErrorAction SilentlyContinue
    } catch {}

    [PSCustomObject]@{
        CreationDate    = $_.CreationDate
        Date            = $_.CreationDate.ToString("yyyy-MM-dd")
        Hour            = $_.CreationDate.Hour
        UserPrincipalName = $_.UserIds
        Operation       = $_.Operations
        Workload        = if ($auditData) { $auditData.Workload } else { "Unknown" }
        AppName         = if ($auditData) { $auditData.AppName } else { "" }
        ContextId       = if ($auditData) { $auditData.Id } else { "" }
        # DLP-specific fields
        PolicyName      = if ($auditData) { $auditData.PolicyDetails.PolicyName } else { "" }
        RuleName        = if ($auditData) { ($auditData.PolicyDetails.Rules | Select-Object -First 1).RuleName } else { "" }
        SensitiveInfoTypes = if ($auditData -and $auditData.SensitiveInfoDetectionIsIncluded) {
            ($auditData.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveType | Select-Object -ExpandProperty Name) -join ", "
        } else { "" }
        # Label info
        LabelName       = if ($auditData) { $auditData.LabelName } else { "" }
    }
}

Write-Host "  ✓ Parsed $($Parsed.Count) events." -ForegroundColor Green

# ── Export raw data if requested ──────────────────────────────────────────────

if ($ExportCsv) {
    $Parsed | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "  ✓ Raw data exported to: $ExportCsv" -ForegroundColor Green
}

# ── Analysis ──────────────────────────────────────────────────────────────────

Write-Host "`n[4/6] Analyzing..." -ForegroundColor Cyan

$CopilotEvents = $Parsed | Where-Object { $_.Operation -eq "CopilotInteraction" -or $_.Operation -eq "AIPluginInteraction" }
$DlpEvents     = $Parsed | Where-Object { $_.Operation -eq "DLPRuleMatch" }

$TotalInteractions = $CopilotEvents.Count
$UniqueUsers       = ($CopilotEvents | Select-Object -ExpandProperty UserPrincipalName -Unique).Count

# ── Display results ───────────────────────────────────────────────────────────

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  COPILOT AUDIT LOG ANALYSIS — Last $Days Days" -ForegroundColor Cyan
Write-Host "  Tenant: $(if ($UserPrincipalName) { "Filtered: $UserPrincipalName" } else { "All Users" })" -ForegroundColor Gray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

Write-Host ""
Write-Host "  📊 SUMMARY" -ForegroundColor Cyan
Write-Host "  ──────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Total Copilot Interactions : $TotalInteractions" -ForegroundColor White
Write-Host "  Unique Users               : $UniqueUsers" -ForegroundColor White
Write-Host "  DLP Events (Copilot)       : $($DlpEvents.Count)" -ForegroundColor $(if ($DlpEvents.Count -gt 0) { "Yellow" } else { "White" })
Write-Host "  Analysis Period            : $($StartDate.ToString('MMM d')) – $($EndDate.ToString('MMM d, yyyy'))" -ForegroundColor Gray

# Daily volume trend
Write-Section "DAILY INTERACTION VOLUME"
$DailyVolume = $CopilotEvents | Group-Object -Property Date | Sort-Object Name
$MaxDay = ($DailyVolume | Measure-Object -Property Count -Maximum).Maximum
$DailyVolume | ForEach-Object {
    $bar = Format-Bar $_.Count $MaxDay 40
    Write-Host "  $($_.Name)  $bar  $($_.Count)" -ForegroundColor White
}

# Top users
Write-Section "TOP $ShowTopN USERS BY COPILOT INTERACTIONS"
$TopUsers = $CopilotEvents | Group-Object -Property UserPrincipalName |
    Sort-Object Count -Descending | Select-Object -First $ShowTopN
$MaxUser = ($TopUsers | Measure-Object -Property Count -Maximum).Maximum
$TopUsers | ForEach-Object {
    $bar  = Format-Bar $_.Count $MaxUser 30
    $user = $_.Name.PadRight(40).Substring(0, [Math]::Min(40, $_.Name.Length + 2))
    Write-Host "  $user  $bar  $($_.Count)" -ForegroundColor White
}

# Workload distribution
Write-Section "COPILOT WORKLOAD DISTRIBUTION"
$Workloads = $CopilotEvents | Group-Object -Property Workload | Sort-Object Count -Descending
$MaxWorkload = ($Workloads | Measure-Object -Property Count -Maximum).Maximum
$Workloads | ForEach-Object {
    $bar  = Format-Bar $_.Count $MaxWorkload 30
    $name = $_.Name.PadRight(25)
    Write-Host "  $name  $bar  $($_.Count)" -ForegroundColor White
}

# After-hours activity
Write-Section "AFTER-HOURS ACTIVITY (Outside 6am–7pm local)"
$AfterHours = $CopilotEvents | Where-Object { $_.Hour -lt 6 -or $_.Hour -gt 19 }
if ($AfterHours.Count -gt 0) {
    Write-Host "  ⚠  $($AfterHours.Count) interactions outside business hours" -ForegroundColor Yellow
    $AfterHoursUsers = $AfterHours | Group-Object -Property UserPrincipalName | Sort-Object Count -Descending | Select-Object -First 5
    $AfterHoursUsers | ForEach-Object {
        Write-Host "     $($_.Name): $($_.Count) events" -ForegroundColor Gray
    }
} else {
    Write-Host "  ✓ No significant after-hours activity detected." -ForegroundColor Green
}

# DLP events
Write-Section "DLP POLICY MATCHES DURING COPILOT SESSIONS"
if ($DlpEvents.Count -gt 0) {
    Write-Host "  ⚠  $($DlpEvents.Count) DLP events detected:" -ForegroundColor Yellow
    $DlpEvents | Group-Object -Property RuleName | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  • $($_.Name.PadRight(50)) $($_.Count) events" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "  Top Users Triggering DLP:" -ForegroundColor Yellow
    $DlpEvents | Group-Object -Property UserPrincipalName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host "     $($_.Name): $($_.Count) DLP events" -ForegroundColor Gray
    }
} else {
    Write-Host "  ✓ No DLP events found for Copilot interactions in this period." -ForegroundColor Green
}

# Label activity
$LabeledEvents = $CopilotEvents | Where-Object { $_.LabelName -ne "" -and $null -ne $_.LabelName }
if ($LabeledEvents.Count -gt 0) {
    Write-Section "SENSITIVITY LABELS IN COPILOT INTERACTIONS"
    $LabeledEvents | Group-Object -Property LabelName | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  • $($_.Name.PadRight(45)) $($_.Count) events" -ForegroundColor White
    }
}

# ── HTML report ───────────────────────────────────────────────────────────────

if ($ExportHtml) {
    Write-Host "`n[5/6] Generating HTML report..." -ForegroundColor Cyan

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm UTC"
    $dailyRows  = ($DailyVolume | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.Count)</td></tr>" }) -join "`n"
    $userRows   = ($TopUsers    | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.Count)</td></tr>" }) -join "`n"
    $dlpRows    = if ($DlpEvents.Count -gt 0) {
        ($DlpEvents | Group-Object RuleName | Sort-Object Count -Descending | ForEach-Object {
            "<tr><td>$($_.Name)</td><td>$($_.Count)</td></tr>"
        }) -join "`n"
    } else { "<tr><td colspan='2'>No DLP events</td></tr>" }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Copilot Audit Report</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background:#1a1a2e; color:#e0e0e0; margin:0; padding:20px; }
  h1   { color:#00d4ff; border-bottom:2px solid #00d4ff; padding-bottom:10px; }
  h2   { color:#88c0d0; margin-top:30px; }
  .stat-grid { display:flex; gap:20px; flex-wrap:wrap; margin:20px 0; }
  .stat-card { background:#16213e; border:1px solid #0f3460; border-radius:8px; padding:20px; min-width:150px; text-align:center; }
  .stat-value{ font-size:2em; font-weight:bold; color:#00d4ff; }
  .stat-label{ font-size:0.85em; color:#88c0d0; margin-top:5px; }
  table  { border-collapse:collapse; width:100%; margin-top:10px; }
  th,td  { padding:8px 12px; text-align:left; border-bottom:1px solid #0f3460; }
  th     { background:#0f3460; color:#88c0d0; }
  tr:hover { background:#16213e; }
  .warn  { color:#ffcc00; }
  footer { margin-top:40px; font-size:0.8em; color:#555; }
</style>
</head>
<body>
<h1>🛡️ Microsoft 365 Copilot — Audit Log Report</h1>
<p>Period: Last $Days days &nbsp;|&nbsp; Generated: $reportDate</p>

<div class="stat-grid">
  <div class="stat-card"><div class="stat-value">$TotalInteractions</div><div class="stat-label">Total Interactions</div></div>
  <div class="stat-card"><div class="stat-value">$UniqueUsers</div><div class="stat-label">Unique Users</div></div>
  <div class="stat-card"><div class="stat-value $(if($DlpEvents.Count -gt 0){'warn'}else{''})">$($DlpEvents.Count)</div><div class="stat-label">DLP Events</div></div>
  <div class="stat-card"><div class="stat-value">$($AfterHours.Count)</div><div class="stat-label">After-Hours</div></div>
</div>

<h2>Daily Volume</h2>
<table><tr><th>Date</th><th>Interactions</th></tr>$dailyRows</table>

<h2>Top Users</h2>
<table><tr><th>User</th><th>Interactions</th></tr>$userRows</table>

<h2>DLP Policy Matches</h2>
<table><tr><th>Rule</th><th>Events</th></tr>$dlpRows</table>

<footer>Generated by Analyze-CopilotAuditLogs.ps1 | MMS MOA 2026 Demo</footer>
</body>
</html>
"@

    $html | Out-File -FilePath $ExportHtml -Encoding UTF8
    Write-Host "  ✓ HTML report saved to: $ExportHtml" -ForegroundColor Green
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host "`n[6/6] Analysis complete." -ForegroundColor Cyan
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  • Set up recurring audit queries using a Logic App or Azure Automation" -ForegroundColor White
Write-Host "  • Alert on users with >N DLP events per day (tune threshold per org)" -ForegroundColor White
Write-Host "  • Review after-hours spikes manually for anomalous data access" -ForegroundColor White
Write-Host "  • Feed DLP event data into Microsoft Sentinel for SIEM correlation" -ForegroundColor White
Write-Host ""
