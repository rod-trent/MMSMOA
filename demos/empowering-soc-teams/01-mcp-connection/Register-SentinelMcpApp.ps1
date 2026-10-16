<#
.SYNOPSIS
    Registers the Microsoft Entra application that lets Claude or ChatGPT call
    the Microsoft Sentinel MCP server as a custom connector.

.DESCRIPTION
    Demo 1, Mission 1 - "Wire the Model"
    Session:    Empowering SOC Teams
    Conference: MMS 2026 Midway Edition - San Diego, October 25-28 2026

    Follows the documented setup at:
    https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-chatgpt-claude-connector

    IMPORTANT - this differs from a normal "connect an MCP client" app:

      * It is a CONFIDENTIAL client, not a public one. The redirect URI goes on
        the *Web* platform and the app has a CLIENT SECRET. Claude's connector
        form asks for both an Application (client) ID and an OAuth Client
        Secret, so a public client with no secret cannot be used.
      * Only the DATA EXPLORATION collection is reachable through the Claude or
        ChatGPT connector. Triage and Agent Creation are not - see -Collection
        below and the note at the end of this script.

    The connector itself is a PRERELEASE feature. Re-read the Learn article the
    week of the conference; this is the part of the demo most likely to move.

.PARAMETER Client
    Which client to add a redirect URI for: Claude, ChatGPT, or both.

.PARAMETER DisplayName
    Display name for the app registration.

.PARAMETER SecretMonths
    Lifetime of the generated client secret, in months. Default 6.

.EXAMPLE
    .\Register-SentinelMcpApp.ps1 -WhatIf
    Dry run. Prints the full plan without touching the tenant. Do this first.

.EXAMPLE
    Connect-MgGraph -Scopes Application.ReadWrite.All
    .\Register-SentinelMcpApp.ps1 -Client Claude

.NOTES
    Requires Microsoft.Graph.Applications and an account holding Application
    Administrator (or Cloud Application Administrator). The Learn article also
    calls for tenant-level administrative privileges to consent.

    The client secret is printed ONCE. Paste it straight into Claude's
    connector form; this script never writes it to disk.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Claude', 'ChatGPT')]
    [string[]] $Client = @('Claude'),

    [string] $DisplayName = 'Sentinel MCP - AI Client',

    [ValidateRange(1, 24)]
    [int] $SecretMonths = 6
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants - verified against Microsoft Learn, October 2026
# ---------------------------------------------------------------------------

# Hosted Sentinel MCP collections.
#   Data exploration -> the ONLY collection reachable from Claude or ChatGPT
#   Triage           -> Visual Studio Code only, at time of writing
#   Agent creation   -> Security Copilot / supported editors
$McpEndpoints = [ordered]@{
    'Data Exploration' = 'https://sentinel.microsoft.com/mcp/data-exploration'
    'Triage'           = 'https://sentinel.microsoft.com/mcp/triage'
    'Agent Creation'   = 'https://sentinel.microsoft.com/mcp/security-copilot-agent-creation'
}

# Redirect URIs exactly as the Learn article lists them. These go on the Web
# platform, not the public-client platform.
$RedirectUris = @{
    Claude  = 'https://claude.ai/api/mcp/auth_callback'
    ChatGPT = 'https://chatgpt.com/connector_platform_oauth_redirect'
}

# "Sentinel Platform Services" - the resource the MCP server sits behind.
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
    # Under -WhatIf we only print the plan, so a missing module is a warning,
    # not a failure. That keeps the dry run usable while rehearsing.
    $present = [bool](Get-Module -ListAvailable -Name Microsoft.Graph.Applications)

    if ($present) {
        Import-Module Microsoft.Graph.Applications -ErrorAction Stop
        return
    }

    $msg = 'Microsoft.Graph.Applications is not installed. Run: Install-Module Microsoft.Graph.Applications -Scope CurrentUser'
    if ($WhatIfPreference) {
        Write-Warning $msg
        Write-Detail 'Continuing the dry run anyway - nothing below will touch a tenant.'
    }
    else {
        throw $msg
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '=================================================================' -ForegroundColor Yellow
Write-Host ' Mission 1 pre-flight: register the AI client for Sentinel MCP'    -ForegroundColor Yellow
Write-Host ' MMS 2026 Midway Edition - Empowering SOC Teams'                   -ForegroundColor Yellow
Write-Host '=================================================================' -ForegroundColor Yellow

$uris = @($Client | ForEach-Object { $RedirectUris[$_] })

Write-Step 1 'Planned configuration'
Write-Detail "App display name : $DisplayName"
Write-Detail "Clients          : $($Client -join ', ')"
Write-Detail 'Platform         : Web (confidential client, has a secret)'
Write-Detail 'Redirect URIs    :'
$uris | ForEach-Object { Write-Detail "                   $_" }
Write-Detail "Delegated scope  : $DelegatedScopeName"
Write-Detail "Client secret    : generated, valid $SecretMonths month(s)"
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
    @{ ResourceAppId = $SentinelPlatformAppId; ResourceAccess = @() }
)

if ($PSCmdlet.ShouldProcess($DelegatedScopeName, 'Resolve delegated scope id')) {
    $sentinelSp = Get-MgServicePrincipal -Filter "appId eq '$SentinelPlatformAppId'" -ErrorAction SilentlyContinue |
                  Select-Object -First 1

    if (-not $sentinelSp) {
        Write-Warning 'Sentinel Platform Services service principal not found in this tenant.'
        Write-Detail 'That usually means the Sentinel data lake is not onboarded yet, which is a'
        Write-Detail 'hard prerequisite. Onboard it in the Defender portal, then re-run.'
        Write-Detail 'Continuing so you can review the rest of the plan.'
    }
    else {
        $scope = $sentinelSp.Oauth2PermissionScopes |
                 Where-Object { $_.Value -eq $DelegatedScopeName } |
                 Select-Object -First 1
        if (-not $scope) {
            throw "Scope '$DelegatedScopeName' is not exposed by Sentinel Platform Services."
        }
        # Type 'Scope' = delegated. Never 'Role' - an application permission
        # would read the workspace with no analyst identity attached, and the
        # per-user RBAC story would be a lie.
        $requiredResourceAccess[0].ResourceAccess = @(@{ Id = $scope.Id; Type = 'Scope' })
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
    Write-Detail "App exists (appId $($existing.AppId)) - merging Web redirect URIs."
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Update app registration')) {
        $merged = @($existing.Web.RedirectUris) + $uris | Select-Object -Unique
        Update-MgApplication -ApplicationId $existing.Id `
            -Web @{ RedirectUris = $merged } `
            -RequiredResourceAccess $requiredResourceAccess
        $app = Get-MgApplication -ApplicationId $existing.Id
    }
}
elseif ($PSCmdlet.ShouldProcess($DisplayName, 'Create app registration')) {
    # Web platform + secret = confidential client. This is what Claude's
    # connector form expects; a public client has no secret to paste.
    $app = New-MgApplication `
        -DisplayName $DisplayName `
        -SignInAudience 'AzureADMyOrg' `
        -Web @{ RedirectUris = $uris } `
        -RequiredResourceAccess $requiredResourceAccess
    Write-Detail "Created appId $($app.AppId)"
}
else {
    Write-Detail 'WhatIf: would create the app registration shown above.'
}

Write-Step 5 'Client secret'
if ($app -and $PSCmdlet.ShouldProcess($DisplayName, 'Add a client secret')) {
    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        DisplayName = "MMS Midway demo ($(Get-Date -Format 'yyyy-MM-dd'))"
        EndDateTime = (Get-Date).AddMonths($SecretMonths)
    }
    Write-Host ''
    Write-Host '    Copy this now - it is shown once and never written to disk:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "      Client ID     : $($app.AppId)" -ForegroundColor Green
    Write-Host "      Client secret : $($secret.SecretText)" -ForegroundColor Green
    Write-Host "      Expires       : $($secret.EndDateTime.ToString('yyyy-MM-dd'))" -ForegroundColor DarkGray
    Write-Host ''
    Write-Detail 'If you lose it, add another secret in Entra; you cannot read this one back.'
}
else {
    Write-Detail 'WhatIf: a client secret is generated here and printed once.'
}

Write-Step 6 'Admin consent'
if ($app) {
    $tenantId = (Get-MgContext).TenantId
    Write-Detail 'Have a Privileged Role Administrator open:'
    Write-Host "    https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$($app.AppId)" -ForegroundColor Green
}
else {
    Write-Detail 'WhatIf: the consent URL is printed here once the app exists.'
}

Write-Step 7 'Least privilege check'
Write-Detail 'Sentinel MCP tools need at least one of: Security Administrator,'
Write-Detail 'Security Operator, or Security Reader. Use Security Reader for the demo.'
Write-Detail ''
Write-Detail 'The entity analyzer tools (analyze_user_entity / analyze_url_entity) additionally'
Write-Detail 'need Security Copilot Contributor and consume Security Compute Units.'
Write-Detail 'Skip them on stage unless you have SCUs to spend.'
Write-Detail ''
Write-Detail 'The graph tools (find_blastradius, find_walkable_paths, find_exposure_perimeter,'
Write-Detail 'find_connected_nodes, find_nodes, get_graph_context) are PREVIEW. They need the'
Write-Detail 'data lake onboarded to the Defender portal, and reading graph data in the portal'
Write-Detail 'needs at least read-only access in Microsoft Security Exposure Management.'
Write-Detail 'They bill against the Sentinel graph meter, not the data lake.'

Write-Step 8 'Add the connector in Claude'
Write-Detail 'Go to https://claude.ai/customize/connectors -> + -> Add a custom connector'
Write-Detail ''
Write-Detail '  Connector name   Microsoft Sentinel MCP'
Write-Detail "  MCP Server URL   $($McpEndpoints['Data Exploration'])"
Write-Detail '  Client ID        the Application (client) ID above'
Write-Detail '  Client secret    the secret above'
Write-Detail ''
Write-Detail 'Then Connect, and Configure to choose which tools to allow.'
Write-Detail 'Requires a Claude Pro, Max, Team, or Enterprise plan.'

Write-Step 9 'What you can and cannot reach from Claude'
foreach ($name in $McpEndpoints.Keys) {
    $via = switch ($name) {
        'Data Exploration' { 'Claude / ChatGPT / VS Code / Copilot Studio / Foundry / Security Copilot' }
        'Triage'           { 'Visual Studio Code only' }
        default            { 'Security Copilot and supported editors' }
    }
    Write-Host ("    {0,-17} {1}" -f $name, $McpEndpoints[$name]) -ForegroundColor White
    Write-Host ("    {0,-17} via: {1}" -f '', $via) -ForegroundColor DarkGray
}
Write-Detail ''
Write-Detail 'Mission 1 uses Data Exploration, which is what Claude can reach.'
Write-Detail 'Mission 2 talks about the Triage collection - that is a VS Code demo,'
Write-Detail 'or run the offline agent in 03-triage-agent-hitl.'
Write-Detail ''
Write-Detail 'Next: pwsh ./Test-SentinelMcpConnection.ps1'

Write-Host ''
