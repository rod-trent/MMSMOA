<#
.SYNOPSIS
    Registers the Entra ID application that lets an AI client (Claude, ChatGPT,
    VS Code, Copilot Studio) call the Microsoft Sentinel MCP server.

.DESCRIPTION
    Demo 1, Mission 1 - "Wire the Model"
    Session:    Empowering SOC Teams: How Claude, Copilot, ChatGPT, MCP Servers,
                and Agents Drive Efficiency
    Conference: MMS Midway 2026 (San Diego)

    This is the pre-flight step from slide 15, step 1. It creates a public-client
    Entra app registration with the delegated permission the hosted Sentinel MCP
    server requires, then prints the connector URLs to paste into the AI client.

    Nothing here grants write access. The signed-in analyst's own RBAC decides
    what the MCP server returns on every call - this app registration only
    establishes *which client* is allowed to ask.

.PARAMETER Client
    Which AI client to configure redirect URIs for. One or more of:
    Claude, ChatGPT, VSCode, CopilotStudio. Default: Claude.

.PARAMETER DisplayName
    Display name for the app registration.

.EXAMPLE
    .\Register-SentinelMcpApp.ps1 -WhatIf
    Dry run. Prints the full plan without touching the tenant. Do this first.

.EXAMPLE
    .\Register-SentinelMcpApp.ps1 -Client Claude,ChatGPT

.NOTES
    Requires the Microsoft.Graph.Applications module and an account holding
    Application Administrator (or Cloud Application Administrator).

    Admin consent for the delegated permission must still be granted by a
    Privileged Role Administrator - this script prints the consent URL.

    Verify the current endpoint list against Microsoft Learn before the session;
    the hosted MCP server is evolving and collection URLs have changed before.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Claude', 'ChatGPT', 'VSCode', 'CopilotStudio')]
    [string[]] $Client = @('Claude'),

    [string] $DisplayName = 'Sentinel MCP - AI Client'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants - the values from slides 11 and 15
# ---------------------------------------------------------------------------

# Hosted Sentinel MCP server collections.
#   Data Exploration -> Mission 1 (natural-language investigation)
#   Triage           -> Demo 3 (the auto-triage agent)
$McpEndpoints = [ordered]@{
    'Data Exploration' = 'https://sentinel.microsoft.com/mcp/data-exploration'
    'Triage'           = 'https://sentinel.microsoft.com/mcp/triage'
    'Agent Creation'   = 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation'
}

# Redirect URIs published by each vendor for MCP OAuth callbacks.
$RedirectUris = @{
    Claude        = @(
        'https://claude.ai/api/mcp/auth_callback',
        'https://claude.com/api/mcp/auth_callback'
    )
    ChatGPT       = @('https://chatgpt.com/connector_platform_oauth_redirect')
    VSCode        = @('https://vscode.dev/redirect', 'http://localhost')
    CopilotStudio = @('https://global.consent.azure-apim.net/redirect')
}

# Microsoft Sentinel Platform - the resource the MCP server sits behind.
$SentinelPlatformAppId = '9ec59623-ce40-4dc8-a635-ed0275b5d58a'
$DelegatedScopeName    = 'SentinelPlatform.DelegatedAccess'

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

function Write-Step {
    param([int] $Number, [string] $Text)
    Write-Host ''
    Write-Host "[$Number] $Text" -ForegroundColor Cyan
}

function Write-Detail {
    param([string] $Text = '')
    Write-Host "    $Text" -ForegroundColor DarkGray
}

function Assert-GraphModule {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
        throw 'Microsoft.Graph.Applications is not installed. Run: Install-Module Microsoft.Graph.Applications -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Applications -ErrorAction Stop
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '=================================================================' -ForegroundColor Yellow
Write-Host ' Mission 1 pre-flight: register the AI client for Sentinel MCP'    -ForegroundColor Yellow
Write-Host ' MMS Midway 2026 - Empowering SOC Teams'                          -ForegroundColor Yellow
Write-Host '=================================================================' -ForegroundColor Yellow

$uris = @()
foreach ($c in $Client) { $uris += $RedirectUris[$c] }
$uris = $uris | Select-Object -Unique

Write-Step 1 'Planned configuration'
Write-Detail "App display name : $DisplayName"
Write-Detail "Clients          : $($Client -join ', ')"
Write-Detail 'Redirect URIs    :'
$uris | ForEach-Object { Write-Detail "                   $_" }
Write-Detail "Delegated scope  : $DelegatedScopeName"
Write-Detail 'Sign-in audience : single tenant'

Assert-GraphModule

Write-Step 2 'Connecting to Microsoft Graph'
if ($PSCmdlet.ShouldProcess('Microsoft Graph', 'Connect with Application.ReadWrite.All')) {
    Connect-MgGraph -Scopes 'Application.ReadWrite.All' -NoWelcome
    $ctx = Get-MgContext
    Write-Detail "Tenant : $($ctx.TenantId)"
    Write-Detail "Account: $($ctx.Account)"
}
else {
    Write-Detail 'WhatIf: would connect with Application.ReadWrite.All'
}

Write-Step 3 'Resolving the delegated permission'

$requiredResourceAccess = @(
    @{
        ResourceAppId  = $SentinelPlatformAppId
        ResourceAccess = @()
    }
)

if ($PSCmdlet.ShouldProcess($DelegatedScopeName, 'Resolve delegated scope id')) {
    $sentinelSp = Get-MgServicePrincipal -Filter "appId eq '$SentinelPlatformAppId'" -ErrorAction SilentlyContinue |
                  Select-Object -First 1

    if (-not $sentinelSp) {
        Write-Warning 'Microsoft Sentinel Platform service principal not found in this tenant.'
        Write-Detail 'That usually means the Sentinel data lake is not enabled yet, which is a'
        Write-Detail 'hard prerequisite for the hosted MCP server (slide 11). Enable it in the'
        Write-Detail 'Defender portal, then re-run. Continuing so you can review the rest.'
    }
    else {
        $scope = $sentinelSp.Oauth2PermissionScopes |
                 Where-Object { $_.Value -eq $DelegatedScopeName } |
                 Select-Object -First 1

        if (-not $scope) {
            throw "Scope '$DelegatedScopeName' is not exposed by the Sentinel Platform service principal."
        }

        # Type 'Scope' = delegated. Never 'Role' here - an application permission
        # would let the client read the workspace without an analyst identity,
        # which breaks the per-user RBAC story on slide 11.
        $requiredResourceAccess[0].ResourceAccess = @(
            @{ Id = $scope.Id; Type = 'Scope' }
        )
        Write-Detail "Resolved $DelegatedScopeName -> $($scope.Id)"
    }
}

Write-Step 4 'Creating or updating the app registration'

$app = $null
$existing = $null

if ($PSCmdlet.ShouldProcess($DisplayName, 'Look up existing app registration')) {
    $existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue |
                Select-Object -First 1
}

if ($existing) {
    Write-Detail "App already exists (appId $($existing.AppId)) - merging redirect URIs."
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Update app registration')) {
        $merged = @($existing.PublicClient.RedirectUris) + $uris | Select-Object -Unique
        Update-MgApplication -ApplicationId $existing.Id `
            -PublicClient @{ RedirectUris = $merged } `
            -RequiredResourceAccess $requiredResourceAccess
        $app = Get-MgApplication -ApplicationId $existing.Id
    }
}
elseif ($PSCmdlet.ShouldProcess($DisplayName, 'Create app registration')) {
    $app = New-MgApplication `
        -DisplayName $DisplayName `
        -SignInAudience 'AzureADMyOrg' `
        -PublicClient @{ RedirectUris = $uris } `
        -RequiredResourceAccess $requiredResourceAccess `
        -IsFallbackPublicClient:$true
    Write-Detail "Created appId $($app.AppId)"
}
else {
    Write-Detail 'WhatIf: would create the app registration shown above.'
}

Write-Step 5 'Admin consent'
if ($app) {
    $tenantId = (Get-MgContext).TenantId
    $consentUrl = "https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$($app.AppId)"
    Write-Detail 'Have a Privileged Role Administrator open:'
    Write-Host "    $consentUrl" -ForegroundColor Green
}
else {
    Write-Detail 'WhatIf: the consent URL is printed here once the app exists.'
}

Write-Step 6 'Least privilege check (slide 20)'
Write-Detail 'The demo account for Mission 1 should hold Security Reader and nothing more.'
Write-Detail 'Verify in the Defender portal under Settings > Roles. If that account can'
Write-Detail 'close incidents or isolate devices, you are not demonstrating least privilege.'

Write-Step 7 'Connector URLs to paste into the AI client'
foreach ($name in $McpEndpoints.Keys) {
    Write-Host ('    {0,-17} {1}' -f $name, $McpEndpoints[$name]) -ForegroundColor White
}
Write-Detail
Write-Detail 'Mission 1 uses Data Exploration. Demo 3 (the triage agent) uses Triage.'
Write-Detail 'Next: copy claude_desktop_config.example.json, then run'
Write-Detail '  pwsh ./Test-SentinelMcpConnection.ps1'

Write-Host ''
