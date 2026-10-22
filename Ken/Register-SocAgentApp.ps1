<#
.SYNOPSIS
    Registers the Microsoft Entra application that lets a custom SOC agent call
    Microsoft Defender and Microsoft Sentinel data through the Microsoft Graph
    security API.

.DESCRIPTION
    For Ken's agent build - MMS 2026 Midway Edition, "Empowering SOC Teams".

    This is NOT the same app as ../demos/empowering-soc-teams/01-mcp-connection/
    Register-SentinelMcpApp.ps1. That one wires Claude's hosted connector to the
    Sentinel MCP server and grants SentinelPlatform.DelegatedAccess. This one
    grants Microsoft Graph permissions so your own code can call:

        GET  /v1.0/security/incidents            SecurityIncident.Read.All
        GET  /v1.0/security/alerts_v2            SecurityAlert.Read.All
        POST /v1.0/security/runHuntingQuery      ThreatHunting.Read.All

    Run both if you want both demos. They are independent.

.PARAMETER AuthFlow
    AppOnly    Client credentials. A backend service holds a secret and calls
               Graph as itself. Simple, headless, and the usual choice for a
               Foundry-hosted agent. The cost: there is no analyst identity on
               the call, so every request sees everything the app can see and
               per-analyst RBAC is gone.

    Delegated  The React app signs the analyst in (SPA + PKCE, no secret), and
               calls carry that analyst's identity. Graph then evaluates each
               call against their own role - Security Reader, Security Operator
               and so on. Slower to build, but the access story is honest.

    Both       Registers a confidential client for the backend AND a SPA
               redirect URI for the React front end, so you can start on
               AppOnly and move to Delegated without re-registering.

    Default is Both.

.PARAMETER ReplyUrl
    SPA redirect URI for the React front end. Only used when AuthFlow includes
    Delegated. Default is the Vite dev server, http://localhost:5173.

.PARAMETER IncludeWriteBack
    Also request SecurityIncident.ReadWrite.All, so the agent can set
    classification, determination and comments on an incident. Leave this off
    until the read path works - a read-only agent cannot make a bad day worse.

.PARAMETER WorkspaceResourceId
    Optional. The ARM resource id of your Sentinel workspace. The script does
    not change any Azure role assignment; it prints the exact command you would
    run if you need the raw Log Analytics path as well. See step 8.

.PARAMETER DisplayName
    Display name for the app registration.

.PARAMETER SecretMonths
    Lifetime of the generated client secret, in months. Default 6.

.EXAMPLE
    .\Register-SocAgentApp.ps1 -WhatIf
    Dry run. Prints the full plan without touching the tenant. Do this first.

.EXAMPLE
    Connect-MgGraph -Scopes Application.ReadWrite.All
    .\Register-SocAgentApp.ps1 -AuthFlow Both

.NOTES
    Requires Microsoft.Graph.Applications and an account holding Application
    Administrator or Cloud Application Administrator. Granting admin consent for
    the application permissions additionally needs Privileged Role Administrator
    or Global Administrator.

    The client secret is printed ONCE. This script never writes it to disk.

    Verified against Microsoft Learn, October 2026:
      https://learn.microsoft.com/graph/api/security-list-incidents
      https://learn.microsoft.com/graph/api/security-list-alerts-v2
      https://learn.microsoft.com/graph/api/security-security-runhuntingquery
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('AppOnly', 'Delegated', 'Both')]
    [string] $AuthFlow = 'Both',

    [string] $ReplyUrl = 'http://localhost:5173',

    [switch] $IncludeWriteBack,

    [string] $WorkspaceResourceId,

    [string] $DisplayName = 'SOC Agent - Graph Security',

    [ValidateRange(1, 24)]
    [int] $SecretMonths = 6
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Microsoft Graph. This appId is the same in every tenant.
$GraphAppId = '00000003-0000-0000-c000-000000000000'

# Least-privileged permission for each endpoint the agent calls.
# 'Role' = application permission. 'Scope' = delegated permission.
$Permissions = @(
    @{ Name = 'SecurityIncident.Read.All'; Why = 'GET /security/incidents' }
    @{ Name = 'SecurityAlert.Read.All';    Why = 'GET /security/alerts_v2' }
    @{ Name = 'ThreatHunting.Read.All';    Why = 'POST /security/runHuntingQuery' }
)

if ($IncludeWriteBack) {
    $Permissions += @{
        Name = 'SecurityIncident.ReadWrite.All'
        Why  = 'PATCH /security/incidents/{id}'
    }
}

$wantsAppOnly   = $AuthFlow -in @('AppOnly', 'Both')
$wantsDelegated = $AuthFlow -in @('Delegated', 'Both')

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
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Applications) {
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
Write-Host ' SOC agent app registration - Defender + Sentinel via Graph'       -ForegroundColor Yellow
Write-Host ' MMS 2026 Midway Edition - Empowering SOC Teams'                   -ForegroundColor Yellow
Write-Host '=================================================================' -ForegroundColor Yellow

Write-Step 1 'Planned configuration'
Write-Detail "App display name : $DisplayName"
Write-Detail "Auth flow        : $AuthFlow"
Write-Detail 'Sign-in audience : single tenant'
if ($wantsAppOnly) {
    Write-Detail 'Backend          : confidential client, client secret, application permissions'
}
if ($wantsDelegated) {
    Write-Detail "Front end        : SPA platform + PKCE, no secret, redirect $ReplyUrl"
}
Write-Detail 'Permissions      :'
$Permissions | ForEach-Object { Write-Detail ("                   {0,-34} {1}" -f $_.Name, $_.Why) }
if (-not $IncludeWriteBack) {
    Write-Detail '                   (read-only - add -IncludeWriteBack for incident updates)'
}

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

Write-Step 3 'Resolving Microsoft Graph permission ids'

$appRoleAccess   = @()   # application permissions ('Role')
$delegatedAccess = @()   # delegated permissions   ('Scope')

if ($PSCmdlet.ShouldProcess('Microsoft Graph', 'Resolve permission ids')) {
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" -ErrorAction SilentlyContinue |
               Select-Object -First 1

    if (-not $graphSp) {
        throw 'Microsoft Graph service principal not found in this tenant. Check the signed-in tenant.'
    }

    foreach ($perm in $Permissions) {
        if ($wantsAppOnly) {
            $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $perm.Name } | Select-Object -First 1
            if (-not $role) {
                throw "Application permission '$($perm.Name)' is not exposed by Microsoft Graph in this tenant."
            }
            $appRoleAccess += @{ Id = $role.Id; Type = 'Role' }
            Write-Detail ("Role  {0,-34} -> {1}" -f $perm.Name, $role.Id)
        }

        if ($wantsDelegated) {
            $scope = $graphSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $perm.Name } | Select-Object -First 1
            if (-not $scope) {
                # Not every Graph permission exists in both shapes. Warn, do not fail.
                Write-Warning "Delegated scope '$($perm.Name)' not found - skipping it for the SPA."
            }
            else {
                $delegatedAccess += @{ Id = $scope.Id; Type = 'Scope' }
                Write-Detail ("Scope {0,-34} -> {1}" -f $perm.Name, $scope.Id)
            }
        }
    }
}
else {
    Write-Detail 'WhatIf: would resolve each permission above to its Graph id.'
}

$requiredResourceAccess = @(
    @{ ResourceAppId = $GraphAppId; ResourceAccess = @($appRoleAccess + $delegatedAccess) }
)

Write-Step 4 'Creating or updating the app registration'

$app      = $null
$existing = $null

if ($PSCmdlet.ShouldProcess($DisplayName, 'Look up existing app registration')) {
    $existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue |
                Select-Object -First 1
}

if ($existing) {
    Write-Detail "App exists (appId $($existing.AppId)) - merging configuration."
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Update app registration')) {
        $params = @{
            ApplicationId          = $existing.Id
            RequiredResourceAccess = $requiredResourceAccess
        }
        if ($wantsDelegated) {
            # The SPA platform is what gives you PKCE with no secret. Putting the
            # React reply URL on the Web platform would force a secret into the
            # browser bundle instead.
            $merged = @($existing.Spa.RedirectUris) + $ReplyUrl | Select-Object -Unique
            $params['Spa'] = @{ RedirectUris = $merged }
        }
        Update-MgApplication @params
        $app = Get-MgApplication -ApplicationId $existing.Id
    }
}
elseif ($PSCmdlet.ShouldProcess($DisplayName, 'Create app registration')) {
    $params = @{
        DisplayName            = $DisplayName
        SignInAudience         = 'AzureADMyOrg'
        RequiredResourceAccess = $requiredResourceAccess
    }
    if ($wantsDelegated) {
        $params['Spa'] = @{ RedirectUris = @($ReplyUrl) }
    }

    $app = New-MgApplication @params
    Write-Detail "Created appId $($app.AppId)"
}
else {
    Write-Detail 'WhatIf: would create the app registration shown above.'
}

Write-Step 5 'Enterprise application (service principal)'
if ($app -and $PSCmdlet.ShouldProcess($DisplayName, 'Ensure a service principal exists')) {
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue |
          Select-Object -First 1
    if (-not $sp) {
        $sp = New-MgServicePrincipal -AppId $app.AppId
        Write-Detail "Created the enterprise application (object id $($sp.Id))."
    }
    else {
        Write-Detail "Enterprise application already present (object id $($sp.Id))."
    }
    Write-Detail 'This object is what the Entra portal lists under Enterprise applications,'
    Write-Detail 'and what you assign Azure roles to in step 8.'
    $script:SpObjectId = $sp.Id
}
else {
    Write-Detail 'WhatIf: the enterprise application is created here if missing.'
}

Write-Step 6 'Client secret'
if ($wantsAppOnly -and $app -and $PSCmdlet.ShouldProcess($DisplayName, 'Add a client secret')) {
    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        DisplayName = "SOC agent ($(Get-Date -Format 'yyyy-MM-dd'))"
        EndDateTime = (Get-Date).AddMonths($SecretMonths)
    }
    Write-Host ''
    Write-Host '    Copy this now - it is shown once and never written to disk:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "      Tenant ID     : $((Get-MgContext).TenantId)" -ForegroundColor Green
    Write-Host "      Client ID     : $($app.AppId)"               -ForegroundColor Green
    Write-Host "      Client secret : $($secret.SecretText)"       -ForegroundColor Green
    Write-Host "      Expires       : $($secret.EndDateTime.ToString('yyyy-MM-dd'))" -ForegroundColor DarkGray
    Write-Host ''
    Write-Detail 'Put these in the backend only. Never ship a secret to the React bundle.'
    Write-Detail 'If you lose it, add another secret in Entra; you cannot read this one back.'
}
elseif (-not $wantsAppOnly) {
    Write-Detail 'Delegated-only: no secret is created. The SPA uses PKCE.'
}
else {
    Write-Detail 'WhatIf: a client secret is generated here and printed once.'
}

Write-Step 7 'Admin consent'
if ($app) {
    $tenantId = (Get-MgContext).TenantId
    Write-Detail 'Application permissions ALWAYS require admin consent. Have a'
    Write-Detail 'Privileged Role Administrator or Global Administrator open:'
    Write-Host ''
    Write-Host "    https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$($app.AppId)" -ForegroundColor Green
    Write-Host ''
    Write-Detail 'Until this is granted every Graph call returns 403, and the error text'
    Write-Detail 'does not always say that consent is what is missing. Check here first.'
}
else {
    Write-Detail 'WhatIf: the consent URL is printed here once the app exists.'
}

Write-Step 8 'What Graph does NOT cover'
Write-Detail 'Graph gives you unified incidents, alerts, and advanced hunting. It does'
Write-Detail 'not give you arbitrary KQL over every Sentinel table at full retention.'
Write-Detail ''
Write-Detail 'Through Graph, once the workspace is onboarded to the Defender portal:'
Write-Detail 'Defender XDR tables, plus Sentinel Analytics-tier tables via'
Write-Detail 'runHuntingQuery - but only inside the Analytics retention window.'
Write-Detail ''
Write-Detail 'For older data, Lake-tier tables, or a workspace that is not onboarded,'
Write-Detail 'use the Log Analytics query API. That is Azure RBAC on the workspace,'
Write-Detail 'not a Graph permission:'
Write-Detail ''
Write-Detail '    POST https://api.loganalytics.azure.com/v1/workspaces/{workspaceId}/query'
Write-Detail ''
if ($WorkspaceResourceId) {
    $objectId = if ($script:SpObjectId) { $script:SpObjectId } else { '<sp-object-id>' }
    Write-Detail 'To grant it, run this with Az.Resources. This script does not do it for you:'
    Write-Host ''
    Write-Host "    New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName 'Log Analytics Reader' -Scope '$WorkspaceResourceId'" -ForegroundColor Green
    Write-Host ''
    Write-Detail "'Log Analytics Data Reader' is tighter if you only need to run queries."
}
else {
    Write-Detail 'Re-run with -WorkspaceResourceId to print the exact role-assignment command.'
}

Write-Step 9 'Next'
Write-Detail 'No tenant yet? You do not need one to start. Build against the fixtures:'
Write-Detail ''
Write-Detail '    python mock/mock_graph_api.py'
Write-Detail '    # then point GRAPH_BASE_URL at http://localhost:8787/v1.0'
Write-Detail ''
Write-Detail 'The fixtures carry the real Graph response shapes, so the same client code'
Write-Detail 'runs against the mock and against graph.microsoft.com. See README.md.'

Write-Host ''
