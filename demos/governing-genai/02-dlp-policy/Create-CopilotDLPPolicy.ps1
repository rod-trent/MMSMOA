<#
.SYNOPSIS
    Creates a DLP policy targeting Microsoft 365 Copilot interactions to prevent
    sensitive data from appearing in AI prompts and responses.

.DESCRIPTION
    Demo: "DLP Policy for Microsoft 365 Copilot"
    Session: Governing GenAI — Monitoring and Securing Copilot with Microsoft Purview
    Conference: MMS MOA 2026

    Creates a DLP compliance policy with four rules:
      - Block PII (SSN, passport, driver's license, credit card numbers)
      - Block PHI (medical record numbers, DEA numbers, ICD codes)
      - Warn on credentials (API keys, passwords, connection strings)
      - Block financial identifiers (bank account, SWIFT, IBAN)

    Policy location: Microsoft365Copilot (covers Copilot for M365 prompts/responses)
    Default mode: TestWithNotifications (audit only — does not block in production)

.PARAMETER EnforcementMode
    Policy enforcement mode. Default is 'TestWithNotifications' (audit only).
    Use 'Enable' to block in production.

.PARAMETER PolicyPrefix
    Optional prefix for policy/rule names (useful in shared demo tenants).

.PARAMETER WhatIf
    Preview — show what would be created without making changes.

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    .\Create-CopilotDLPPolicy.ps1 -WhatIf
    .\Create-CopilotDLPPolicy.ps1
    .\Create-CopilotDLPPolicy.ps1 -EnforcementMode Enable -Force
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("TestWithNotifications", "TestWithoutNotifications", "Enable")]
    [string]$EnforcementMode = "TestWithNotifications",

    [string]$PolicyPrefix = "",

    [switch]$Force
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

# ── Connection ────────────────────────────────────────────────────────────────

Write-Host "`n[1/4] Connecting to Security & Compliance Center..." -ForegroundColor Cyan

if (-not (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)) {
    Connect-IPPSSession -UseRPSSession:$false
    Write-Host "  ✓ Connected." -ForegroundColor Green
} else {
    Write-Host "  ✓ Already connected." -ForegroundColor Green
}

# ── Policy definition ─────────────────────────────────────────────────────────

$PolicyName = "${PolicyPrefix}Copilot-DLP-Governance"

$Rules = @(
    @{
        Name        = "${PolicyPrefix}Block-PII-In-Copilot"
        Description = "Block PII from appearing in Copilot prompts or being surfaced in responses."
        SensitiveInfoTypes = @(
            @{ Name = "U.S. Social Security Number (SSN)"; minCount = 1 },
            @{ Name = "U.S. / U.K. Passport Number"; minCount = 1 },
            @{ Name = "U.S. Driver's License Number"; minCount = 1 },
            @{ Name = "Credit Card Number"; minCount = 1 },
            @{ Name = "U.S. Individual Taxpayer Identification Number (ITIN)"; minCount = 1 }
        )
        NotifyUser  = $true
        BlockAction = $true
        UserNotificationText = "This message was blocked because it appears to contain Personally Identifiable Information (PII). Remove sensitive data and try again, or contact your compliance team."
    },
    @{
        Name        = "${PolicyPrefix}Block-PHI-In-Copilot"
        Description = "Block Protected Health Information from Copilot interactions."
        SensitiveInfoTypes = @(
            @{ Name = "U.S. Health Insurance Number"; minCount = 1 },
            @{ Name = "Drug Enforcement Agency (DEA) Number"; minCount = 1 },
            @{ Name = "International Classification of Diseases (ICD-9-CM)"; minCount = 1 },
            @{ Name = "International Classification of Diseases (ICD-10-CM)"; minCount = 1 }
        )
        NotifyUser  = $true
        BlockAction = $true
        UserNotificationText = "This message was blocked because it appears to contain Protected Health Information (PHI). HIPAA compliance requires that PHI not be processed by AI systems without appropriate authorization."
    },
    @{
        Name        = "${PolicyPrefix}Warn-Credentials-In-Copilot"
        Description = "Warn (with override allowed) when credentials are detected in Copilot."
        SensitiveInfoTypes = @(
            @{ Name = "Azure AD Client Secret"; minCount = 1 },
            @{ Name = "Azure Storage Account Access Key"; minCount = 1 },
            @{ Name = "General Password"; minCount = 1 }
        )
        NotifyUser  = $true
        BlockAction = $false
        UserNotificationText = "Warning: This message may contain credentials or secrets. Sharing secrets with AI systems is a security risk. Are you sure you want to continue?"
    },
    @{
        Name        = "${PolicyPrefix}Block-Financial-In-Copilot"
        Description = "Block financial account identifiers from Copilot interactions."
        SensitiveInfoTypes = @(
            @{ Name = "ABA Routing Number"; minCount = 1 },
            @{ Name = "SWIFT Code"; minCount = 1 },
            @{ Name = "International Banking Account Number (IBAN)"; minCount = 1 },
            @{ Name = "U.S. Bank Account Number"; minCount = 1 }
        )
        NotifyUser  = $true
        BlockAction = $true
        UserNotificationText = "This message was blocked because it appears to contain financial account information. Contact your compliance team if you need assistance."
    }
)

# ── Show preview ──────────────────────────────────────────────────────────────

Write-Host "`n[2/4] DLP policy to create:" -ForegroundColor Cyan
Write-Host "  Policy Name  : $PolicyName" -ForegroundColor White
Write-Host "  Location     : Microsoft365Copilot" -ForegroundColor White
Write-Host "  Mode         : $EnforcementMode" -ForegroundColor $(if ($EnforcementMode -eq "Enable") { "Yellow" } else { "White" })
Write-Host ""
Write-Host "  Rules:" -ForegroundColor White
foreach ($rule in $Rules) {
    $action = if ($rule.BlockAction) { "BLOCK" } else { "WARN" }
    $color  = if ($rule.BlockAction) { "Red" } else { "Yellow" }
    Write-Host "    [$action] $($rule.Name)" -ForegroundColor $color
    $rule.SensitiveInfoTypes | ForEach-Object { Write-Host "          • $($_.Name)" -ForegroundColor Gray }
}

if ($EnforcementMode -eq "Enable" -and -not $Force -and -not $WhatIfPreference) {
    Write-Host ""
    Write-Warning "You are about to create a policy in ENFORCEMENT mode. This WILL block users immediately."
    $confirm = Read-Host "Type 'ENFORCE' to confirm"
    if ($confirm -ne "ENFORCE") { Write-Host "Cancelled." -ForegroundColor Yellow; exit 0 }
} elseif (-not $Force -and -not $WhatIfPreference) {
    $confirm = Read-Host "`nCreate policy in $EnforcementMode mode? (y/N)"
    if ($confirm -notmatch "^[Yy]") { Write-Host "Cancelled." -ForegroundColor Yellow; exit 0 }
}

# ── Create policy ─────────────────────────────────────────────────────────────

Write-Host "`n[3/4] Creating DLP compliance policy..." -ForegroundColor Cyan

$existing = Get-DlpCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue

if ($existing) {
    Write-Host "  ⊙ Policy already exists: $PolicyName" -ForegroundColor Gray
} else {
    if ($PSCmdlet.ShouldProcess($PolicyName, "Create DLP compliance policy")) {
        New-DlpCompliancePolicy `
            -Name                  $PolicyName `
            -Comment               "Controls sensitive data in Microsoft 365 Copilot interactions. Created for MMS MOA 2026 demo." `
            -Mode                  $EnforcementMode `
            -Workload              "Microsoft365Copilot" | Out-Null
        Write-Host "  ✓ Policy created: $PolicyName" -ForegroundColor Green
    }
}

# ── Create rules ──────────────────────────────────────────────────────────────

Write-Host "`n[4/4] Creating DLP rules..." -ForegroundColor Cyan

foreach ($rule in $Rules) {
    $existingRule = Get-DlpComplianceRule -Policy $PolicyName -Identity $rule.Name -ErrorAction SilentlyContinue

    if ($existingRule) {
        Write-Host "  ⊙ Rule exists: $($rule.Name)" -ForegroundColor Gray
        continue
    }

    $ruleParams = @{
        Name           = $rule.Name
        Policy         = $PolicyName
        Comment        = $rule.Description
        ContentContainsSensitiveInformation = $rule.SensitiveInfoTypes
    }

    # Notification
    if ($rule.NotifyUser) {
        $ruleParams.NotifyUser         = "LastModifier", "SiteAdmin"
        $ruleParams.NotifyPolicyTipCustomText = $rule.UserNotificationText
    }

    # Block or audit
    if ($rule.BlockAction) {
        $ruleParams.BlockAccess        = $true
        $ruleParams.BlockAccessScope   = "All"
        $ruleParams.GenerateAlert      = "SiteAdmin"
        $ruleParams.GenerateIncidentReport = "SiteAdmin"
        $ruleParams.IncidentReportContent = @("Title", "Severity", "RulesMatched",
                                               "Detections", "SensitiveInformationType",
                                               "DocumentAuthor", "Service", "MatchedItem")
    } else {
        # Warn with override allowed
        $ruleParams.NotifyOverrideRequirements = "WithJustification"
    }

    if ($PSCmdlet.ShouldProcess($rule.Name, "Create DLP rule")) {
        try {
            New-DlpComplianceRule @ruleParams | Out-Null
            $action = if ($rule.BlockAction) { "BLOCK" } else { "WARN " }
            Write-Host "  ✓ [$action] $($rule.Name)" -ForegroundColor Green
        } catch {
            Write-Warning "  ✗ Failed: $($rule.Name) — $_"
        }
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " DEMO COMPLETE — Copilot DLP Policy Created" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host " Policy Mode: $EnforcementMode" -ForegroundColor $(if ($EnforcementMode -eq "Enable") { "Yellow" } else { "Green" })
Write-Host ""
Write-Host " NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Open https://compliance.microsoft.com > Data loss prevention > Policies" -ForegroundColor White
Write-Host "  2. Click '$PolicyName' to review rules" -ForegroundColor White
Write-Host "  3. Open Copilot for Microsoft 365 in a browser" -ForegroundColor White
Write-Host "  4. Try: 'Summarize this employee record: SSN 123-45-6789, salary 95000'" -ForegroundColor White
Write-Host "     → Policy intercepts the prompt within 15-60 minutes of creation" -ForegroundColor Gray
Write-Host "  5. Review DLP alerts at: https://compliance.microsoft.com > Alerts" -ForegroundColor White
Write-Host ""
if ($EnforcementMode -ne "Enable") {
    Write-Host " ⚠  Policy is in $EnforcementMode mode — events are AUDITED but NOT blocked." -ForegroundColor Yellow
    Write-Host "    To enforce: Set-DlpCompliancePolicy -Identity '$PolicyName' -Mode Enable" -ForegroundColor Yellow
    Write-Host ""
}
