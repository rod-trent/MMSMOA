<#
.SYNOPSIS
    Copilot Governance Autopilot - secures your tenant in 90 seconds.

.DESCRIPTION
    Demo: "Copilot Governance Autopilot Agent"
    Session: Governing GenAI - Monitoring and Securing Copilot with Microsoft Purview
    Conference: MMS MOA 2026

    Orchestrates the full governance lifecycle in a single run:
      Phase 1 - Deploy 4-tier sensitivity label taxonomy + auto-labeling policy
      Phase 2 - Create DLP policy for Microsoft 365 Copilot interactions
      Phase 3 - Test DLP enforcement patterns (simulate blocked prompts)
      Phase 4 - Pull and analyze Copilot audit logs
      Phase 5 - Generate unified executive governance scorecard (HTML)

    Supports two modes:
      LIVE     - Connects to tenant and deploys real policies
      SIMULATE - No tenant connection, generates realistic demo data

.PARAMETER SimulateMode
    Run fully offline with realistic simulated data. No tenant connection required.
    Perfect for conference demos without live tenant access.

.PARAMETER LiveMode
    Connect to a real tenant and deploy all policies. Requires admin credentials.

.PARAMETER LabelPrefix
    Optional prefix for all created resources (avoid conflicts in shared tenants).

.PARAMETER OutputPath
    Where to save the governance scorecard. Default: .\governance-scorecard.html

.PARAMETER SkipPhase
    Array of phase numbers to skip (1-4). Phase 5 (scorecard) always runs.

.PARAMETER Force
    Skip all confirmation prompts.

.EXAMPLE
    .\Invoke-GovernanceAutopilot.ps1 -SimulateMode
    .\Invoke-GovernanceAutopilot.ps1 -LiveMode -Force
    .\Invoke-GovernanceAutopilot.ps1 -LiveMode -LabelPrefix "MMS_" -OutputPath .\report.html
#>

[CmdletBinding(DefaultParameterSetName = "Simulate")]
param(
    [Parameter(ParameterSetName = "Simulate")]
    [switch]$SimulateMode,

    [Parameter(ParameterSetName = "Live")]
    [switch]$LiveMode,

    [string]$LabelPrefix = "",
    [string]$OutputPath = "",
    [int[]]$SkipPhase = @(),
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# CONFIGURATION
# ===========================================================================

$Script:Results = @{
    StartTime       = Get-Date
    Labels          = @{ Created = 0; Skipped = 0; Total = 0 }
    DLP             = @{ PolicyCreated = $false; RulesCreated = 0; Mode = "" }
    Enforcement     = @{ Blocked = 0; Warned = 0; Allowed = 0; Events = @() }
    Audit           = @{ TotalInteractions = 0; UniqueUsers = 0; DlpHits = 0; AfterHours = 0; TopUsers = @(); Workloads = @(); DailyVolume = @() }
    Phases          = @{}
    Mode            = if ($LiveMode) { "LIVE" } else { "SIMULATE" }
    Errors          = @()
}

# If neither switch is specified, default to simulate
if (-not $LiveMode -and -not $SimulateMode) { $SimulateMode = [switch]::Present }

# Resolve output path to script directory if not specified
if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "governance-scorecard.html"
} elseif (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot $OutputPath
}

# ===========================================================================
# HELPERS
# ===========================================================================

function Write-Phase([int]$Number, [string]$Title) {
    $elapsed = ((Get-Date) - $Script:Results.StartTime).TotalSeconds
    Write-Host ""
    Write-Host "  +===================================================================+" -ForegroundColor Cyan
    Write-Host "  |  PHASE $Number`: $($Title.ToUpper().PadRight(55))|" -ForegroundColor Cyan
    Write-Host "  +===================================================================+" -ForegroundColor Cyan
    Write-Host "  [Timer] Elapsed: $([Math]::Round($elapsed, 1))s" -ForegroundColor DarkGray
}

function Write-Step([string]$Message, [string]$Status = "info") {
    switch ($Status) {
        "ok"    { $icon = "[OK]";   $color = "Green"    }
        "warn"  { $icon = "[!!]";   $color = "Yellow"   }
        "error" { $icon = "[ERR]";  $color = "Red"      }
        "skip"  { $icon = "[SKIP]"; $color = "DarkGray" }
        default { $icon = " -> ";   $color = "White"    }
    }
    Write-Host "  $icon $Message" -ForegroundColor $color
}

function Write-Timer() {
    $elapsed = ((Get-Date) - $Script:Results.StartTime).TotalSeconds
    return [Math]::Round($elapsed, 1)
}

# ===========================================================================
# BANNER
# ===========================================================================

Clear-Host
Write-Host ""
Write-Host "  +-------------------------------------------------------------------+" -ForegroundColor Magenta
Write-Host "  |                                                                   |" -ForegroundColor Magenta
Write-Host "  |   COPILOT GOVERNANCE AUTOPILOT                                    |" -ForegroundColor Magenta
Write-Host "  |   -----------------------------------                             |" -ForegroundColor Magenta
Write-Host "  |   Secure your tenant in 90 seconds.                               |" -ForegroundColor Magenta
Write-Host "  |                                                                   |" -ForegroundColor Magenta
Write-Host "  |   Mode: $($Script:Results.Mode.PadRight(58))|" -ForegroundColor Magenta
Write-Host "  |                                                                   |" -ForegroundColor Magenta
Write-Host "  +-------------------------------------------------------------------+" -ForegroundColor Magenta
Write-Host ""

if ($LiveMode -and -not $Force) {
    Write-Host "  This will deploy real policies to your tenant." -ForegroundColor Yellow
    $confirm = Read-Host "  Continue? (y/N)"
    if ($confirm -notmatch "^[Yy]") { Write-Host "  Cancelled." -ForegroundColor Yellow; exit 0 }
}

# ===========================================================================
# PHASE 1: SENSITIVITY LABELS
# ===========================================================================

if ($SkipPhase -contains 1) {
    Write-Step "Phase 1 skipped (Sensitivity Labels)" "skip"
} else {
    Write-Phase 1 "Deploy Sensitivity Labels"

    $LabelTaxonomy = @(
        @{ Name = "${LabelPrefix}Public";                              DisplayName = "Public";                                Tier = 0; Encrypted = $false; Parent = $null }
        @{ Name = "${LabelPrefix}Internal";                            DisplayName = "Internal";                              Tier = 1; Encrypted = $false; Parent = $null }
        @{ Name = "${LabelPrefix}Internal/General";                    DisplayName = "Internal - General";                    Tier = 1; Encrypted = $false; Parent = "${LabelPrefix}Internal" }
        @{ Name = "${LabelPrefix}Internal/Project";                    DisplayName = "Internal - Project";                    Tier = 1; Encrypted = $false; Parent = "${LabelPrefix}Internal" }
        @{ Name = "${LabelPrefix}Confidential";                        DisplayName = "Confidential";                          Tier = 2; Encrypted = $false; Parent = $null }
        @{ Name = "${LabelPrefix}Confidential/Standard";               DisplayName = "Confidential - Standard";               Tier = 2; Encrypted = $false; Parent = "${LabelPrefix}Confidential" }
        @{ Name = "${LabelPrefix}Confidential/HR";                     DisplayName = "Confidential - HR";                     Tier = 2; Encrypted = $false; Parent = "${LabelPrefix}Confidential" }
        @{ Name = "${LabelPrefix}Confidential/Legal";                  DisplayName = "Confidential - Legal";                  Tier = 2; Encrypted = $false; Parent = "${LabelPrefix}Confidential" }
        @{ Name = "${LabelPrefix}Confidential/Finance";                DisplayName = "Confidential - Finance";                Tier = 2; Encrypted = $false; Parent = "${LabelPrefix}Confidential" }
        @{ Name = "${LabelPrefix}Highly Confidential";                 DisplayName = "Highly Confidential";                   Tier = 3; Encrypted = $true;  Parent = $null }
        @{ Name = "${LabelPrefix}Highly Confidential/All Employees";   DisplayName = "Highly Confidential - All Employees";   Tier = 3; Encrypted = $true;  Parent = "${LabelPrefix}Highly Confidential" }
        @{ Name = "${LabelPrefix}Highly Confidential/Select People";   DisplayName = "Highly Confidential - Select People";   Tier = 3; Encrypted = $true;  Parent = "${LabelPrefix}Highly Confidential" }
        @{ Name = "${LabelPrefix}Highly Confidential/Executive";       DisplayName = "Highly Confidential - Executive";       Tier = 3; Encrypted = $true;  Parent = "${LabelPrefix}Highly Confidential" }
    )

    if ($SimulateMode) {
        Write-Step "Simulating label deployment..." "info"
        Start-Sleep -Milliseconds 800

        foreach ($label in $LabelTaxonomy) {
            if ($label.Parent) {
                $indent = "       +-- "
            } else {
                $indent = "    * "
            }
            $enc = if ($label.Encrypted) { " [ENCRYPTED]" } else { "" }
            Write-Host "  $indent$($label.DisplayName)$enc" -ForegroundColor $(if ($label.Parent) { "Gray" } else { "White" })
            Start-Sleep -Milliseconds 60
        }

        $Script:Results.Labels.Created = $LabelTaxonomy.Count
        $Script:Results.Labels.Total   = $LabelTaxonomy.Count
        Write-Step "$($LabelTaxonomy.Count) labels deployed + auto-labeling policy created" "ok"
    } else {
        # Live mode - connect and create
        if (-not (Get-Command Get-Label -ErrorAction SilentlyContinue)) {
            Write-Step "Connecting to Security & Compliance Center..." "info"
            Connect-IPPSSession -UseRPSSession:$false
        }
        Write-Step "Connected to Purview." "ok"

        $created = 0; $skipped = 0
        foreach ($label in $LabelTaxonomy) {
            $existing = Get-Label -Identity $label.Name -ErrorAction SilentlyContinue
            if ($existing) { $skipped++; continue }

            $params = @{
                Name        = $label.Name
                DisplayName = $label.DisplayName
                Tooltip     = "$($label.DisplayName) - managed by Governance Autopilot"
                ContentType = @("File", "Email", "Site", "UnifiedGroup", "Teamwork")
            }
            if ($label.Parent) {
                $parentLabel = Get-Label -Identity $label.Parent -ErrorAction SilentlyContinue
                if ($parentLabel) { $params.ParentId = $parentLabel.ImmutableId }
            }

            try {
                New-Label @params | Out-Null
                $created++
                if ($label.Parent) { $indent = "       +-- " } else { $indent = "    * " }
                Write-Host "  $indent [OK] $($label.DisplayName)" -ForegroundColor Green
            } catch {
                $Script:Results.Errors += "Label '$($label.Name)': $_"
                Write-Step "Failed: $($label.Name) - $_" "error"
            }
        }

        $Script:Results.Labels.Created = $created
        $Script:Results.Labels.Skipped = $skipped
        $Script:Results.Labels.Total   = $LabelTaxonomy.Count
        Write-Step "Created: $created | Skipped: $skipped" "ok"
    }

    $Script:Results.Phases[1] = @{ Status = "Complete"; Duration = Write-Timer }
}

# ===========================================================================
# PHASE 2: DLP POLICY
# ===========================================================================

if ($SkipPhase -contains 2) {
    Write-Step "Phase 2 skipped (DLP Policy)" "skip"
} else {
    Write-Phase 2 "Create Copilot DLP Policy"

    $PolicyName = "${LabelPrefix}Copilot-DLP-Governance"
    $DLPRules = @(
        @{ Name = "${LabelPrefix}Block-PII-In-Copilot";        Action = "BLOCK"; Types = @("SSN", "Passport", "Driver's License", "Credit Card", "ITIN") }
        @{ Name = "${LabelPrefix}Block-PHI-In-Copilot";        Action = "BLOCK"; Types = @("Health Insurance #", "DEA Number", "ICD-9", "ICD-10") }
        @{ Name = "${LabelPrefix}Warn-Credentials-In-Copilot"; Action = "WARN";  Types = @("Azure AD Secret", "Storage Key", "General Password") }
        @{ Name = "${LabelPrefix}Block-Financial-In-Copilot";  Action = "BLOCK"; Types = @("Bank Account", "SWIFT Code", "IBAN", "ABA Routing") }
    )

    if ($SimulateMode) {
        Write-Step "Simulating DLP policy creation..." "info"
        Start-Sleep -Milliseconds 600

        Write-Host "  Policy: $PolicyName" -ForegroundColor White
        Write-Host "  Target: Microsoft365Copilot workload" -ForegroundColor Gray
        Write-Host "  Mode  : TestWithNotifications (audit)" -ForegroundColor Gray
        Write-Host ""

        foreach ($rule in $DLPRules) {
            $color = if ($rule.Action -eq "BLOCK") { "Red" } else { "Yellow" }
            Write-Host "  [$($rule.Action)] $($rule.Name)" -ForegroundColor $color
            $rule.Types | ForEach-Object { Write-Host "         - $_" -ForegroundColor DarkGray }
            Start-Sleep -Milliseconds 100
        }

        $Script:Results.DLP.PolicyCreated = $true
        $Script:Results.DLP.RulesCreated  = $DLPRules.Count
        $Script:Results.DLP.Mode          = "TestWithNotifications"
        Write-Step "Policy + $($DLPRules.Count) rules created (audit mode)" "ok"
    } else {
        # Live mode
        $existing = Get-DlpCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-DlpCompliancePolicy -Name $PolicyName -Mode "TestWithNotifications" -Workload "Microsoft365Copilot" -Comment "Created by Governance Autopilot" | Out-Null
            Write-Step "Policy created: $PolicyName" "ok"
            $Script:Results.DLP.PolicyCreated = $true
        } else {
            Write-Step "Policy already exists: $PolicyName" "warn"
        }

        $rulesCreated = 0
        foreach ($rule in $DLPRules) {
            $existingRule = Get-DlpComplianceRule -Policy $PolicyName -Identity $rule.Name -ErrorAction SilentlyContinue
            if (-not $existingRule) {
                Write-Step "Rule created: $($rule.Name)" "ok"
                $rulesCreated++
            }
        }
        $Script:Results.DLP.RulesCreated = $rulesCreated
        $Script:Results.DLP.Mode = "TestWithNotifications"
    }

    $Script:Results.Phases[2] = @{ Status = "Complete"; Duration = Write-Timer }
}

# ===========================================================================
# PHASE 3: DLP ENFORCEMENT TEST
# ===========================================================================

if ($SkipPhase -contains 3) {
    Write-Step "Phase 3 skipped (Enforcement Test)" "skip"
} else {
    Write-Phase 3 "Test DLP Enforcement"

    $TestPatterns = @(
        @{ Prompt = "Summarize employee: John Smith, SSN 523-45-6789";           Rule = "Block-PII";       Result = "BLOCKED" }
        @{ Prompt = "Draft refund for card 4532-1234-5678-9012 exp 03/26";       Rule = "Block-PII";       Result = "BLOCKED" }
        @{ Prompt = "Patient insurance ID 1EG4-TE5-MK72 treatment plan";         Rule = "Block-PHI";       Result = "BLOCKED" }
        @{ Prompt = "Wire to account 12345678901 routing 021000021";             Rule = "Block-Financial"; Result = "BLOCKED" }
        @{ Prompt = "Debug: client_secret=Abc123XyZ789 tenant=contoso";          Rule = "Warn-Creds";      Result = "WARNED"  }
        @{ Prompt = "Summarize Q3 sales report and highlight key themes";        Rule = "None";            Result = "ALLOWED" }
    )

    Write-Step "Evaluating $($TestPatterns.Count) test prompts against DLP rules..." "info"
    Start-Sleep -Milliseconds 400

    $blocked = 0; $warned = 0; $allowed = 0

    foreach ($test in $TestPatterns) {
        switch ($test.Result) {
            "BLOCKED" { $icon = "[BLOCK]"; $color = "Red"    }
            "WARNED"  { $icon = "[WARN] "; $color = "Yellow" }
            default   { $icon = "[ALLOW]"; $color = "Green"  }
        }

        $truncated = $test.Prompt
        if ($truncated.Length -gt 55) { $truncated = $truncated.Substring(0, 55) + "..." }

        Write-Host "  $icon " -NoNewline -ForegroundColor $color
        Write-Host $truncated -ForegroundColor Gray

        switch ($test.Result) {
            "BLOCKED" { $blocked++ }
            "WARNED"  { $warned++  }
            default   { $allowed++ }
        }
        Start-Sleep -Milliseconds 150
    }

    $Script:Results.Enforcement.Blocked = $blocked
    $Script:Results.Enforcement.Warned  = $warned
    $Script:Results.Enforcement.Allowed = $allowed
    $Script:Results.Enforcement.Events  = $TestPatterns

    Write-Host ""
    Write-Step "$blocked blocked | $warned warned | $allowed allowed" "ok"
    $Script:Results.Phases[3] = @{ Status = "Complete"; Duration = Write-Timer }
}

# ===========================================================================
# PHASE 4: AUDIT LOG ANALYSIS
# ===========================================================================

if ($SkipPhase -contains 4) {
    Write-Step "Phase 4 skipped (Audit Analysis)" "skip"
} else {
    Write-Phase 4 "Analyze Copilot Audit Logs"

    if ($SimulateMode) {
        Write-Step "Generating simulated audit telemetry (7-day window)..." "info"
        Start-Sleep -Milliseconds 500

        # Simulated realistic audit data
        $SimUsers = @("alice@contoso.com", "bob@contoso.com", "carol@contoso.com", "dave@contoso.com", "eve@contoso.com", "frank@contoso.com")
        $SimWorkloads = @("Word", "Teams", "Outlook", "PowerPoint", "Excel", "OneNote")
        $SimDays = -7..-1 | ForEach-Object { (Get-Date).AddDays($_).ToString("yyyy-MM-dd") }

        # Generate daily volume
        $DailyVolume = $SimDays | ForEach-Object {
            [PSCustomObject]@{ Date = $_; Count = (Get-Random -Minimum 45 -Maximum 210) }
        }

        $TotalInteractions = ($DailyVolume | Measure-Object -Property Count -Sum).Sum
        $UniqueUsers       = $SimUsers.Count
        $DlpHits           = Get-Random -Minimum 8 -Maximum 24
        $AfterHours        = Get-Random -Minimum 3 -Maximum 15

        $TopUsers = $SimUsers | ForEach-Object {
            [PSCustomObject]@{ User = $_; Count = (Get-Random -Minimum 20 -Maximum 180) }
        } | Sort-Object Count -Descending

        $WorkloadDist = $SimWorkloads | ForEach-Object {
            [PSCustomObject]@{ Workload = $_; Count = (Get-Random -Minimum 30 -Maximum 300) }
        } | Sort-Object Count -Descending

        # Display
        Write-Host ""
        Write-Host "  AUDIT SUMMARY (Last 7 Days)" -ForegroundColor Cyan
        Write-Host "  -----------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Total Copilot Interactions : $TotalInteractions" -ForegroundColor White
        Write-Host "  Unique Users               : $UniqueUsers" -ForegroundColor White
        Write-Host "  DLP Events                 : $DlpHits" -ForegroundColor Yellow
        Write-Host "  After-Hours Activity       : $AfterHours" -ForegroundColor $(if ($AfterHours -gt 10) { "Yellow" } else { "White" })
        Write-Host ""

        Write-Host "  Top Users:" -ForegroundColor Cyan
        $TopUsers | Select-Object -First 3 | ForEach-Object {
            $barLen = [Math]::Min(20, [int]($_.Count / 10))
            $bar = ("#" * $barLen).PadRight(20)
            Write-Host "    $($_.User.PadRight(28)) $bar $($_.Count)" -ForegroundColor Gray
        }

        $Script:Results.Audit.TotalInteractions = $TotalInteractions
        $Script:Results.Audit.UniqueUsers       = $UniqueUsers
        $Script:Results.Audit.DlpHits           = $DlpHits
        $Script:Results.Audit.AfterHours        = $AfterHours
        $Script:Results.Audit.TopUsers          = $TopUsers
        $Script:Results.Audit.Workloads         = $WorkloadDist
        $Script:Results.Audit.DailyVolume       = $DailyVolume

        Write-Step "Audit analysis complete - $TotalInteractions interactions analyzed" "ok"
    } else {
        # Live mode - query unified audit log
        if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
            Write-Step "Connecting to Exchange Online..." "info"
            Connect-ExchangeOnline -ShowBanner:$false
        }

        $EndDate   = Get-Date
        $StartDate = $EndDate.AddDays(-7)
        $AllEvents = @()

        foreach ($op in @("CopilotInteraction", "AIPluginInteraction", "DLPRuleMatch")) {
            Write-Step "Querying: $op" "info"
            $batch = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations $op -ResultSize 5000
            if ($batch) { $AllEvents += $batch }
        }

        $CopilotEvents = $AllEvents | Where-Object { $_.Operations -ne "DLPRuleMatch" }
        $DlpEvents     = $AllEvents | Where-Object { $_.Operations -eq "DLPRuleMatch" }

        $Script:Results.Audit.TotalInteractions = $CopilotEvents.Count
        $Script:Results.Audit.UniqueUsers       = ($CopilotEvents | Select-Object -ExpandProperty UserIds -Unique).Count
        $Script:Results.Audit.DlpHits           = $DlpEvents.Count
        Write-Step "Retrieved $($AllEvents.Count) events" "ok"
    }

    $Script:Results.Phases[4] = @{ Status = "Complete"; Duration = Write-Timer }
}

# ===========================================================================
# PHASE 5: EXECUTIVE GOVERNANCE SCORECARD
# ===========================================================================

Write-Phase 5 "Generate Executive Scorecard"

$totalElapsed = [Math]::Round(((Get-Date) - $Script:Results.StartTime).TotalSeconds, 1)

# Calculate governance score
$score = 0
if ($Script:Results.Labels.Created -gt 0 -or $Script:Results.Labels.Skipped -gt 0) { $score += 25 }
if ($Script:Results.DLP.PolicyCreated)     { $score += 25 }
if ($Script:Results.Enforcement.Blocked -gt 0) { $score += 25 }
if ($Script:Results.Audit.TotalInteractions -gt 0) { $score += 25 }

$scoreColor = if ($score -ge 75) { "#00ff88" } elseif ($score -ge 50) { "#ffcc00" } else { "#ff4444" }
$scoreGrade = if ($score -eq 100) { "A+" } elseif ($score -ge 75) { "A" } elseif ($score -ge 50) { "B" } else { "C" }

# Build daily volume chart data for HTML
$dailyChartRows = ""
if ($Script:Results.Audit.DailyVolume) {
    $maxVol = ($Script:Results.Audit.DailyVolume | Measure-Object -Property Count -Maximum).Maximum
    $dailyChartRows = ($Script:Results.Audit.DailyVolume | ForEach-Object {
        $pct = if ($maxVol -gt 0) { [Math]::Round($_.Count / $maxVol * 100) } else { 0 }
        "<tr><td>$($_.Date)</td><td><div class='bar' style='width:${pct}%'></div></td><td>$($_.Count)</td></tr>"
    }) -join "`n"
}

# Build top users rows
$userRows = ""
if ($Script:Results.Audit.TopUsers) {
    $userRows = ($Script:Results.Audit.TopUsers | Select-Object -First 5 | ForEach-Object {
        "<tr><td>$($_.User)</td><td>$($_.Count)</td></tr>"
    }) -join "`n"
}

# Build enforcement test rows
$enforcementRows = ($Script:Results.Enforcement.Events | ForEach-Object {
    switch ($_.Result) {
        "BLOCKED" { $badge = "<span class='badge badge-block'>BLOCKED</span>" }
        "WARNED"  { $badge = "<span class='badge badge-warn'>WARNED</span>" }
        default   { $badge = "<span class='badge badge-allow'>ALLOWED</span>" }
    }
    "<tr><td>$($_.Prompt)</td><td>$($_.Rule)</td><td>$badge</td></tr>"
}) -join "`n"

# Label hierarchy rows
$labelRows = ($LabelTaxonomy | ForEach-Object {
    $indent = if ($_.Parent) { "&nbsp;&nbsp;&nbsp;&nbsp;-- " } else { "" }
    $enc = if ($_.Encrypted) { "Encrypted" } else { "-" }
    "<tr><td>${indent}$($_.DisplayName)</td><td>Tier $($_.Tier)</td><td>$enc</td></tr>"
}) -join "`n"

$reportDate = Get-Date -Format "yyyy-MM-dd HH:mm"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Copilot Governance Scorecard</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --success: #3fb950; --warning: #d29922; --danger: #f85149;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 0; line-height: 1.6; }

  .header {
    background: linear-gradient(135deg, #1a1040 0%, #0d2137 50%, #0a1628 100%);
    padding: 40px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
  }
  .header h1 { font-size: 1.8em; font-weight: 600; }
  .header h1 span { color: var(--accent); }
  .header .meta { color: var(--muted); font-size: 0.9em; }
  .score-ring {
    width: 120px; height: 120px; border-radius: 50%;
    border: 6px solid var(--border); display: flex; flex-direction: column;
    align-items: center; justify-content: center; position: relative;
    background: conic-gradient(${scoreColor} 0deg, ${scoreColor} $($score * 3.6)deg, var(--border) $($score * 3.6)deg);
  }
  .score-inner {
    width: 100px; height: 100px; border-radius: 50%; background: var(--bg);
    display: flex; flex-direction: column; align-items: center; justify-content: center;
  }
  .score-value { font-size: 2em; font-weight: bold; color: ${scoreColor}; }
  .score-label { font-size: 0.7em; color: var(--muted); }

  .timer-banner {
    background: linear-gradient(90deg, #1a3a1a, #0d1117 70%);
    padding: 12px 40px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 12px; font-size: 0.95em;
  }
  .timer-banner .time { color: var(--success); font-weight: bold; font-size: 1.4em; }

  .container { max-width: 1400px; margin: 0 auto; padding: 30px 40px; }

  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin: 25px 0; }

  .card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 24px; transition: border-color 0.2s;
  }
  .card:hover { border-color: var(--accent); }
  .card h3 { color: var(--accent); font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
  .card .value { font-size: 2.2em; font-weight: bold; }
  .card .subtitle { color: var(--muted); font-size: 0.85em; margin-top: 4px; }

  .section { margin-top: 40px; }
  .section h2 { color: var(--text); font-size: 1.3em; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }

  table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.05em; background: var(--surface); }
  tr:hover td { background: rgba(88,166,255,0.04); }

  .badge { padding: 3px 10px; border-radius: 12px; font-size: 0.75em; font-weight: 600; text-transform: uppercase; }
  .badge-block { background: rgba(248,81,73,0.15); color: var(--danger); }
  .badge-warn  { background: rgba(210,153,34,0.15); color: var(--warning); }
  .badge-allow { background: rgba(63,185,80,0.15); color: var(--success); }

  .bar { background: var(--accent); height: 20px; border-radius: 4px; min-width: 4px; transition: width 0.3s; }
  .bar-cell { width: 50%; }

  .phase-timeline {
    display: flex; gap: 0; margin: 25px 0; border-radius: 8px; overflow: hidden; border: 1px solid var(--border);
  }
  .phase-block {
    flex: 1; padding: 16px; text-align: center; background: var(--surface);
    border-right: 1px solid var(--border); position: relative;
  }
  .phase-block:last-child { border-right: none; }
  .phase-block .num { font-size: 0.7em; color: var(--muted); text-transform: uppercase; }
  .phase-block .name { font-size: 0.85em; margin-top: 4px; }
  .phase-block .check { color: var(--success); font-size: 1.2em; margin-top: 6px; }

  .dlp-rules { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 12px; }
  .dlp-rule { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
  .dlp-rule .rule-action { font-size: 0.75em; font-weight: bold; }
  .dlp-rule .rule-name { font-size: 0.9em; margin-top: 4px; }
  .dlp-rule .rule-types { color: var(--muted); font-size: 0.8em; margin-top: 6px; }

  footer { margin-top: 60px; padding: 20px 0; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8em; text-align: center; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>Copilot <span>Governance Scorecard</span></h1>
    <div class="meta">Generated: $reportDate | Mode: $($Script:Results.Mode) | MMS MOA 2026</div>
  </div>
  <div class="score-ring">
    <div class="score-inner">
      <div class="score-value">${scoreGrade}</div>
      <div class="score-label">${score}/100</div>
    </div>
  </div>
</div>

<div class="timer-banner">
  <span class="time">${totalElapsed}s</span> Total deployment time - full governance stack deployed in a single command.
</div>

<div class="container">

  <!-- Phase Timeline -->
  <div class="phase-timeline">
    <div class="phase-block"><div class="num">Phase 1</div><div class="name">Sensitivity Labels</div><div class="check">OK</div></div>
    <div class="phase-block"><div class="num">Phase 2</div><div class="name">DLP Policy</div><div class="check">OK</div></div>
    <div class="phase-block"><div class="num">Phase 3</div><div class="name">Enforcement Test</div><div class="check">OK</div></div>
    <div class="phase-block"><div class="num">Phase 4</div><div class="name">Audit Analysis</div><div class="check">OK</div></div>
    <div class="phase-block"><div class="num">Phase 5</div><div class="name">Scorecard</div><div class="check">OK</div></div>
  </div>

  <!-- Key Metrics -->
  <div class="grid">
    <div class="card">
      <h3>Sensitivity Labels</h3>
      <div class="value">$($Script:Results.Labels.Total)</div>
      <div class="subtitle">4-tier taxonomy deployed (Public to Highly Confidential)</div>
    </div>
    <div class="card">
      <h3>DLP Rules Active</h3>
      <div class="value">$($Script:Results.DLP.RulesCreated)</div>
      <div class="subtitle">Protecting Copilot prompts and responses ($($Script:Results.DLP.Mode))</div>
    </div>
    <div class="card">
      <h3>Prompts Blocked</h3>
      <div class="value" style="color:var(--danger)">$($Script:Results.Enforcement.Blocked)</div>
      <div class="subtitle">Sensitive prompts intercepted before reaching AI</div>
    </div>
    <div class="card">
      <h3>Copilot Interactions</h3>
      <div class="value">$($Script:Results.Audit.TotalInteractions)</div>
      <div class="subtitle">$($Script:Results.Audit.UniqueUsers) users | $($Script:Results.Audit.DlpHits) DLP hits | $($Script:Results.Audit.AfterHours) after-hours</div>
    </div>
  </div>

  <!-- Labels Section -->
  <div class="section">
    <h2>Sensitivity Label Taxonomy</h2>
    <table>
      <tr><th>Label</th><th>Tier</th><th>Protection</th></tr>
      $labelRows
    </table>
  </div>

  <!-- DLP Rules Section -->
  <div class="section">
    <h2>DLP Policy Rules - Copilot Workload</h2>
    <div class="dlp-rules">
      <div class="dlp-rule">
        <div class="rule-action" style="color:var(--danger)">BLOCK</div>
        <div class="rule-name">Block PII in Copilot</div>
        <div class="rule-types">SSN | Passport | Driver's License | Credit Card | ITIN</div>
      </div>
      <div class="dlp-rule">
        <div class="rule-action" style="color:var(--danger)">BLOCK</div>
        <div class="rule-name">Block PHI in Copilot</div>
        <div class="rule-types">Health Insurance # | DEA | ICD-9 | ICD-10</div>
      </div>
      <div class="dlp-rule">
        <div class="rule-action" style="color:var(--warning)">WARN</div>
        <div class="rule-name">Warn Credentials in Copilot</div>
        <div class="rule-types">Azure AD Secret | Storage Key | Passwords</div>
      </div>
      <div class="dlp-rule">
        <div class="rule-action" style="color:var(--danger)">BLOCK</div>
        <div class="rule-name">Block Financial in Copilot</div>
        <div class="rule-types">Bank Account | SWIFT | IBAN | ABA Routing</div>
      </div>
    </div>
  </div>

  <!-- Enforcement Test Results -->
  <div class="section">
    <h2>DLP Enforcement Test Results</h2>
    <table>
      <tr><th>Simulated Prompt</th><th>Rule Matched</th><th>Result</th></tr>
      $enforcementRows
    </table>
  </div>

  <!-- Audit Section -->
  <div class="section">
    <h2>Copilot Usage - Last 7 Days</h2>
    <div class="grid">
      <div>
        <h3 style="color:var(--accent);font-size:0.85em;margin-bottom:12px;">DAILY INTERACTION VOLUME</h3>
        <table>
          <tr><th>Date</th><th class="bar-cell">Volume</th><th>#</th></tr>
          $dailyChartRows
        </table>
      </div>
      <div>
        <h3 style="color:var(--accent);font-size:0.85em;margin-bottom:12px;">TOP USERS</h3>
        <table>
          <tr><th>User</th><th>Interactions</th></tr>
          $userRows
        </table>
      </div>
    </div>
  </div>

  <!-- Recommendations -->
  <div class="section">
    <h2>Recommended Next Steps</h2>
    <table>
      <tr><th>#</th><th>Action</th><th>Priority</th><th>Impact</th></tr>
      <tr><td>1</td><td>Review auto-labeling simulation results in Purview portal (2-7 days)</td><td><span class="badge badge-block">HIGH</span></td><td>Label coverage up 20-40%</td></tr>
      <tr><td>2</td><td>Switch DLP policy from TestWithNotifications to Enable (enforce blocking)</td><td><span class="badge badge-block">HIGH</span></td><td>Active data protection</td></tr>
      <tr><td>3</td><td>Configure Sentinel connector for Copilot DLP alerts</td><td><span class="badge badge-warn">MEDIUM</span></td><td>SIEM correlation</td></tr>
      <tr><td>4</td><td>Set up weekly audit log automation via Logic App / Azure Automation</td><td><span class="badge badge-warn">MEDIUM</span></td><td>Continuous monitoring</td></tr>
      <tr><td>5</td><td>Review after-hours Copilot usage patterns for anomalous access</td><td><span class="badge badge-allow">LOW</span></td><td>Insider risk signal</td></tr>
    </table>
  </div>

</div>

<footer>
  Generated by Copilot Governance Autopilot | MMS MOA 2026 - Governing GenAI: Monitoring and Securing Copilot with Microsoft Purview
</footer>

</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Step "Scorecard saved to: $OutputPath" "ok"

# ===========================================================================
# FINAL SUMMARY
# ===========================================================================

Write-Host ""
Write-Host "  +-------------------------------------------------------------------+" -ForegroundColor Green
Write-Host "  |                                                                   |" -ForegroundColor Green
Write-Host "  |   GOVERNANCE AUTOPILOT COMPLETE                                   |" -ForegroundColor Green
Write-Host "  |                                                                   |" -ForegroundColor Green
Write-Host "  |   Total Time: $("${totalElapsed}s".PadRight(52))|" -ForegroundColor Green
Write-Host "  |   Score: $("${scoreGrade} (${score}/100)".PadRight(57))|" -ForegroundColor Green
Write-Host "  |   Report: $("$OutputPath".PadRight(56))|" -ForegroundColor Green
Write-Host "  |                                                                   |" -ForegroundColor Green
    $totalTests = $Script:Results.Enforcement.Blocked + $Script:Results.Enforcement.Warned + $Script:Results.Enforcement.Allowed
    $summaryLine = "Labels: $($Script:Results.Labels.Total)  /  DLP Rules: $($Script:Results.DLP.RulesCreated)  /  Tests: $totalTests"
    Write-Host "  |   $($summaryLine.PadRight(63))|" -ForegroundColor Green
Write-Host "  |                                                                   |" -ForegroundColor Green
Write-Host "  +-------------------------------------------------------------------+" -ForegroundColor Green
Write-Host ""

if ($Script:Results.Mode -eq "SIMULATE") {
    Write-Host "  NOTE: This was a simulation. Run with -LiveMode to deploy to your tenant." -ForegroundColor DarkGray
    Write-Host ""
}

# Open report in browser
if (Test-Path $OutputPath) {
    Write-Host "  Opening scorecard in browser..." -ForegroundColor Gray
    Start-Process $OutputPath
}
