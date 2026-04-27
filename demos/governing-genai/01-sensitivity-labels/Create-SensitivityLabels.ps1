<#
.SYNOPSIS
    Creates a 4-tier sensitivity label taxonomy in Microsoft Purview and
    enables an auto-labeling policy for SharePoint content accessed by Copilot.

.DESCRIPTION
    Demo: "Creating Sensitivity Labels for AI Content"
    Session: Governing GenAI — Monitoring and Securing Copilot with Microsoft Purview
    Conference: MMS MOA 2026

    Creates the following label hierarchy:
      Public
      Internal
        Internal/General
        Internal/Project
      Confidential
        Confidential/Standard
        Confidential/HR
        Confidential/Legal
        Confidential/Finance
      Highly Confidential
        Highly Confidential/All Employees
        Highly Confidential/Select People
        Highly Confidential/Executive

.PARAMETER WhatIf
    Preview mode — show what would be created without making changes.

.PARAMETER Force
    Skip all confirmation prompts.

.PARAMETER LabelPrefix
    Optional prefix added to all label names (useful for testing in shared tenants).
    Example: -LabelPrefix "DEMO_"

.EXAMPLE
    .\Create-SensitivityLabels.ps1 -WhatIf
    .\Create-SensitivityLabels.ps1 -Force
    .\Create-SensitivityLabels.ps1 -LabelPrefix "MMS_"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [string]$LabelPrefix = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Prerequisites ────────────────────────────────────────────────────────────

function Assert-Module([string]$Name) {
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Error "Module '$Name' not found. Run: Install-Module $Name -Scope CurrentUser"
    }
}

Assert-Module "ExchangeOnlineManagement"

# ── Connection ───────────────────────────────────────────────────────────────

Write-Host "`n[1/5] Connecting to Security & Compliance Center..." -ForegroundColor Cyan

if (-not (Get-Command Get-Label -ErrorAction SilentlyContinue)) {
    Connect-IPPSSession -UseRPSSession:$false
    Write-Host "  ✓ Connected." -ForegroundColor Green
} else {
    Write-Host "  ✓ Already connected." -ForegroundColor Green
}

# ── Label taxonomy definition ────────────────────────────────────────────────

$Taxonomy = @(
    @{
        Name        = "${LabelPrefix}Public"
        DisplayName = "Public"
        Tooltip     = "Information approved for public release. No restrictions."
        Priority    = 0
        Color       = "#00B050"
        Parent      = $null
        Encrypt     = $false
        MarkContent = $false
        CopilotScenario = "Copilot can freely reference and summarize Public content."
    },
    @{
        Name        = "${LabelPrefix}Internal"
        DisplayName = "Internal"
        Tooltip     = "Business information for internal use. Not for external distribution."
        Priority    = 1
        Color       = "#0070C0"
        Parent      = $null
        Encrypt     = $false
        MarkContent = $true
        CopilotScenario = "Copilot can reference Internal content within the org."
    },
    @{
        Name        = "${LabelPrefix}Internal/General"
        DisplayName = "Internal - General"
        Tooltip     = "General internal information with no specific sensitivity."
        Priority    = 0
        Color       = "#0070C0"
        Parent      = "${LabelPrefix}Internal"
        Encrypt     = $false
        MarkContent = $true
        CopilotScenario = "Default for most internal documents."
    },
    @{
        Name        = "${LabelPrefix}Internal/Project"
        DisplayName = "Internal - Project"
        Tooltip     = "Project-specific information shared within project teams."
        Priority    = 1
        Color       = "#0070C0"
        Parent      = "${LabelPrefix}Internal"
        Encrypt     = $false
        MarkContent = $true
        CopilotScenario = "Copilot can reference within project team members."
    },
    @{
        Name        = "${LabelPrefix}Confidential"
        DisplayName = "Confidential"
        Tooltip     = "Sensitive business information. Limit to those with a need to know."
        Priority    = 2
        Color       = "#FFC000"
        Parent      = $null
        Encrypt     = $false
        MarkContent = $true
        CopilotScenario = "Copilot will warn before including Confidential content in outputs."
    },
    @{
        Name        = "${LabelPrefix}Confidential/Standard"
        DisplayName = "Confidential - Standard"
        Tooltip     = "Standard confidential business information."
        Priority    = 0
        Color       = "#FFC000"
        Parent      = "${LabelPrefix}Confidential"
        Encrypt     = $false
        MarkContent = $true
        CopilotScenario = "General confidential content — Copilot can summarize with label applied to output."
    },
    @{
        Name        = "${LabelPrefix}Confidential/HR"
        DisplayName = "Confidential - HR"
        Tooltip     = "Human Resources data: compensation, performance, personal information."
        Priority    = 1
        Color       = "#FFC000"
        Parent      = "${LabelPrefix}Confidential"
        Encrypt     = $false
        MarkContent = $true
        CopilotScenario = "Copilot will apply this label to summaries of HR documents."
    },
    @{
        Name        = "${LabelPrefix}Confidential/Legal"
        DisplayName = "Confidential - Legal"
        Tooltip     = "Attorney-client privileged or legally sensitive information."
        Priority    = 2
        Color       = "#FFC000"
        Parent      = "${LabelPrefix}Confidential"
        Encrypt     = $false
        MarkContent = $true
        CopilotScenario = "Copilot output citing Legal docs inherits this label."
    },
    @{
        Name        = "${LabelPrefix}Confidential/Finance"
        DisplayName = "Confidential - Finance"
        Tooltip     = "Financial data: earnings, forecasts, budgets, account numbers."
        Priority    = 3
        Color       = "#FFC000"
        Parent      = "${LabelPrefix}Confidential"
        Encrypt     = $false
        MarkContent = $true
        CopilotScenario = "Auto-labeled when credit card or bank account numbers detected."
    },
    @{
        Name        = "${LabelPrefix}Highly Confidential"
        DisplayName = "Highly Confidential"
        Tooltip     = "Highest sensitivity. Unauthorized disclosure would cause severe harm."
        Priority    = 3
        Color       = "#FF0000"
        Parent      = $null
        Encrypt     = $true
        MarkContent = $true
        CopilotScenario = "Copilot cannot include Highly Confidential content in summaries unless user has explicit access."
    },
    @{
        Name        = "${LabelPrefix}Highly Confidential/All Employees"
        DisplayName = "Highly Confidential - All Employees"
        Tooltip     = "Highly confidential — visible to all employees but encrypted."
        Priority    = 0
        Color       = "#FF0000"
        Parent      = "${LabelPrefix}Highly Confidential"
        Encrypt     = $true
        MarkContent = $true
        CopilotScenario = "Encryption enforced. Copilot output inherits encryption."
    },
    @{
        Name        = "${LabelPrefix}Highly Confidential/Select People"
        DisplayName = "Highly Confidential - Select People"
        Tooltip     = "Restricted to specific named individuals. Encryption enforced."
        Priority    = 1
        Color       = "#FF0000"
        Parent      = "${LabelPrefix}Highly Confidential"
        Encrypt     = $true
        MarkContent = $true
        CopilotScenario = "Copilot BLOCKED from summarizing — only explicitly authorized users."
    },
    @{
        Name        = "${LabelPrefix}Highly Confidential/Executive"
        DisplayName = "Highly Confidential - Executive"
        Tooltip     = "Executive and board-level information. Strict need-to-know."
        Priority    = 2
        Color       = "#FF0000"
        Parent      = "${LabelPrefix}Highly Confidential"
        Encrypt     = $true
        MarkContent = $true
        CopilotScenario = "Copilot BLOCKED. DLP policy enforces no AI access to Executive content."
    }
)

# ── Display what will be created ─────────────────────────────────────────────

Write-Host "`n[2/5] Label taxonomy to create:" -ForegroundColor Cyan
$Taxonomy | ForEach-Object {
    $indent = if ($_.Parent) { "  └─ " } else { "• " }
    $encrypt = if ($_.Encrypt) { " [ENCRYPTED]" } else { "" }
    Write-Host "  $indent$($_.DisplayName)$encrypt" -ForegroundColor $(if ($_.Parent) { "Gray" } else { "White" })
}

if (-not $Force -and -not $WhatIfPreference) {
    $confirm = Read-Host "`nCreate these labels? (y/N)"
    if ($confirm -notmatch "^[Yy]") { Write-Host "Cancelled." -ForegroundColor Yellow; exit 0 }
}

# ── Create labels ─────────────────────────────────────────────────────────────

Write-Host "`n[3/5] Creating sensitivity labels..." -ForegroundColor Cyan
$created = 0
$skipped = 0

foreach ($label in $Taxonomy) {
    $existing = Get-Label -Identity $label.Name -ErrorAction SilentlyContinue

    if ($existing) {
        Write-Host "  ⊙ Exists: $($label.DisplayName)" -ForegroundColor Gray
        $skipped++
        continue
    }

    $params = @{
        Name               = $label.Name
        DisplayName        = $label.DisplayName
        Tooltip            = $label.Tooltip
        ContentType        = @("File", "Email", "Site", "UnifiedGroup", "Teamwork", "PurviewAssets")
        Disabled           = $false
    }

    if ($label.Color) { $params.LabelColor = $label.Color }

    if ($label.Parent) {
        $parentLabel = Get-Label -Identity $label.Parent -ErrorAction SilentlyContinue
        if ($parentLabel) { $params.ParentId = $parentLabel.ImmutableId }
    }

    if ($label.MarkContent) {
        $params.ApplyContentMarkingHeaderEnabled = $true
        $params.ApplyContentMarkingHeaderText    = "SENSITIVITY: $($label.DisplayName.ToUpper())"
        $params.ApplyContentMarkingHeaderFontSize = 10
        $params.ApplyContentMarkingHeaderFontColor = $label.Color
        $params.ApplyContentMarkingHeaderAlignment = "Center"
    }

    if ($PSCmdlet.ShouldProcess($label.Name, "Create sensitivity label")) {
        try {
            New-Label @params | Out-Null
            Write-Host "  ✓ Created: $($label.DisplayName)" -ForegroundColor Green
            $created++
        } catch {
            Write-Warning "  ✗ Failed to create '$($label.Name)': $_"
        }
    }
}

Write-Host "  Created: $created  |  Skipped (already exist): $skipped" -ForegroundColor Cyan

# ── Create label policy ───────────────────────────────────────────────────────

Write-Host "`n[4/5] Publishing labels in a label policy..." -ForegroundColor Cyan

$policyName = "${LabelPrefix}Copilot-Governance-Policy"
$topLevelLabels = $Taxonomy | Where-Object { -not $_.Parent } | Select-Object -ExpandProperty Name

$existingPolicy = Get-LabelPolicy -Identity $policyName -ErrorAction SilentlyContinue

if ($existingPolicy) {
    Write-Host "  ⊙ Policy already exists: $policyName" -ForegroundColor Gray
} else {
    if ($PSCmdlet.ShouldProcess($policyName, "Create label policy")) {
        try {
            New-LabelPolicy `
                -Name        $policyName `
                -Labels      ($Taxonomy | Select-Object -ExpandProperty Name) `
                -ExchangeLocation "All" `
                -SharePointLocation "All" `
                -OneDriveLocation "All" `
                -TeamsLocation "All" `
                -MandatoryComment "All documents must be labeled before sharing." `
                -RequireDowngradeJustification $true | Out-Null
            Write-Host "  ✓ Policy created: $policyName" -ForegroundColor Green
        } catch {
            Write-Warning "  ✗ Failed to create policy: $_"
        }
    }
}

# ── Create auto-labeling policy (simulation mode) ────────────────────────────

Write-Host "`n[5/5] Creating auto-labeling policy (simulation mode)..." -ForegroundColor Cyan

$autoLabelPolicyName = "${LabelPrefix}AutoLabel-Copilot-Simulation"
$existingAutoPolicy  = Get-AutoSensitivityLabelPolicy -Identity $autoLabelPolicyName -ErrorAction SilentlyContinue

if ($existingAutoPolicy) {
    Write-Host "  ⊙ Auto-label policy already exists: $autoLabelPolicyName" -ForegroundColor Gray
} else {
    if ($PSCmdlet.ShouldProcess($autoLabelPolicyName, "Create auto-labeling policy")) {
        try {
            # Policy in simulation mode — safe to run in production
            New-AutoSensitivityLabelPolicy `
                -Name              $autoLabelPolicyName `
                -ApplySensitivityLabel "${LabelPrefix}Confidential/Finance" `
                -SharePointLocation "All" `
                -OneDriveLocation  "All" `
                -ExchangeLocation  "All" `
                -Mode              "SimulationWithoutNotifications" | Out-Null

            # Rule: Credit card numbers → Confidential/Finance
            New-AutoSensitivityLabelRule `
                -Name           "${autoLabelPolicyName}-FinancialData" `
                -Policy         $autoLabelPolicyName `
                -ContentContainsSensitiveInformation @(
                    @{ Name="Credit Card Number"; minCount=1 },
                    @{ Name="ABA Routing Number"; minCount=1 }
                ) | Out-Null

            Write-Host "  ✓ Auto-labeling policy created in SIMULATION mode." -ForegroundColor Green
            Write-Host "  → Review results at: https://compliance.microsoft.com > Auto-labeling" -ForegroundColor Gray
            Write-Host "  → Switch to enforcement after reviewing simulation report (typically 2-7 days)." -ForegroundColor Gray
        } catch {
            Write-Warning "  ✗ Failed to create auto-labeling policy: $_"
        }
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " DEMO COMPLETE — Sensitivity Labels Created" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host " NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Open https://compliance.microsoft.com > Information Protection > Labels" -ForegroundColor White
Write-Host "  2. Verify the label hierarchy is visible" -ForegroundColor White
Write-Host "  3. Open a Word doc and apply a label manually — show the header stamp" -ForegroundColor White
Write-Host "  4. Check auto-labeling simulation results (2-7 days after creation)" -ForegroundColor White
Write-Host "  5. Show Copilot respecting label-based access in M365 apps" -ForegroundColor White
Write-Host ""
