<#
.SYNOPSIS
    Pre-flight check for Mission 1. Verifies that the Sentinel MCP connection
    will actually work before you stand in front of 300 people.

.DESCRIPTION
    Demo 1, Mission 1 - "Wire the Model"
    Session:    Empowering SOC Teams
    Conference: MMS Midway 2026 (San Diego)

    Runs seven checks in the order things usually break:

      1. Az / Graph modules present
      2. Signed in, and to the right tenant
      3. Sentinel data lake enabled (the MCP server needs it)
      4. App registration exists with the right redirect URIs
      5. Delegated scope consented
      6. Demo account holds Security Reader - and no more
      7. MCP endpoints reachable and returning 401 (not 404 / DNS failure)

    Check 7 is deliberately looking for HTTP 401. An unauthenticated GET to a
    working MCP endpoint should be rejected. A 404 means the URL moved; a DNS
    or timeout error means egress is blocked on the conference network, which
    is the single most common day-of failure.

.PARAMETER DemoAccount
    UPN of the account you will demo with. Skipped if not supplied.

.PARAMETER AppDisplayName
    Display name used by Register-SentinelMcpApp.ps1.

.EXAMPLE
    .\Test-SentinelMcpConnection.ps1 -DemoAccount analyst@contoso.com
#>

[CmdletBinding()]
param(
    [string] $DemoAccount,
    [string] $AppDisplayName = 'Sentinel MCP - AI Client'
)

$ErrorActionPreference = 'Continue'

$McpEndpoints = @(
    'https://sentinel.microsoft.com/mcp/data-exploration',
    'https://sentinel.microsoft.com/mcp/triage'
)

$SentinelPlatformAppId = '9ec59623-ce40-4dc8-a635-ed0275b5d58a'
$DelegatedScopeName    = 'SentinelPlatform.DelegatedAccess'

$script:Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string] $Name,
        [ValidateSet('PASS', 'FAIL', 'WARN', 'SKIP')] [string] $Status,
        [string] $Detail
    )
    $script:Results.Add([pscustomobject]@{
        Check  = $Name
        Status = $Status
        Detail = $Detail
    })

    $color = switch ($Status) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'WARN' { 'Yellow' }
        default { 'DarkGray' }
    }
    Write-Host ('  {0,-6} {1,-34} {2}' -f "[$Status]", $Name, $Detail) -ForegroundColor $color
}

Write-Host ''
Write-Host 'Mission 1 pre-flight -------------------------------------------' -ForegroundColor Yellow
Write-Host ''

# --- 1. Modules ------------------------------------------------------------

$needed = @('Az.Accounts', 'Az.Resources', 'Microsoft.Graph.Applications')
$missing = $needed | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

if ($missing) {
    Add-Result 'PowerShell modules' 'FAIL' "Missing: $($missing -join ', ')"
}
else {
    Add-Result 'PowerShell modules' 'PASS' 'Az.Accounts, Az.Resources, Microsoft.Graph.Applications'
}

# --- 2. Signed in ----------------------------------------------------------

$azContext = $null
try {
    Import-Module Az.Accounts -ErrorAction Stop
    $azContext = Get-AzContext -ErrorAction Stop
}
catch { }

if ($azContext) {
    Add-Result 'Azure sign-in' 'PASS' "$($azContext.Account.Id) / tenant $($azContext.Tenant.Id)"
}
else {
    Add-Result 'Azure sign-in' 'FAIL' 'Not signed in. Run Connect-AzAccount.'
}

# --- 3. Sentinel data lake -------------------------------------------------
# The data lake shows up as a Microsoft.SecurityInsights onboarding state plus
# the Sentinel Platform service principal being provisioned in the tenant.

$sentinelSp = $null
try {
    Import-Module Microsoft.Graph.Applications -ErrorAction Stop
    if (Get-MgContext) {
        $sentinelSp = Get-MgServicePrincipal -Filter "appId eq '$SentinelPlatformAppId'" -ErrorAction SilentlyContinue |
                      Select-Object -First 1
    }
}
catch { }

if (-not (Get-MgContext)) {
    Add-Result 'Sentinel data lake' 'SKIP' 'Not connected to Graph. Run Connect-MgGraph.'
}
elseif ($sentinelSp) {
    Add-Result 'Sentinel data lake' 'PASS' 'Sentinel Platform service principal present'
}
else {
    Add-Result 'Sentinel data lake' 'FAIL' 'Platform SP missing - enable the data lake in the Defender portal'
}

# --- 4 & 5. App registration and consent -----------------------------------

if (-not (Get-MgContext)) {
    Add-Result 'App registration' 'SKIP' 'Not connected to Graph'
    Add-Result 'Delegated consent' 'SKIP' 'Not connected to Graph'
}
else {
    $app = Get-MgApplication -Filter "displayName eq '$AppDisplayName'" -ErrorAction SilentlyContinue |
           Select-Object -First 1

    if (-not $app) {
        Add-Result 'App registration' 'FAIL' "No app named '$AppDisplayName'. Run Register-SentinelMcpApp.ps1."
        Add-Result 'Delegated consent' 'SKIP' 'No app to check'
    }
    else {
        $redirects = @($app.PublicClient.RedirectUris)
        $hasClaude = $redirects | Where-Object { $_ -like '*claude*mcp/auth_callback' }

        if ($hasClaude) {
            Add-Result 'App registration' 'PASS' "appId $($app.AppId), $($redirects.Count) redirect URI(s)"
        }
        else {
            Add-Result 'App registration' 'WARN' "appId $($app.AppId) but no Claude redirect URI found"
        }

        # Consent shows up as an oauth2PermissionGrant against the Sentinel SP.
        $granted = $false
        if ($sentinelSp) {
            $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue |
                  Select-Object -First 1
            if ($sp) {
                $grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'" -ErrorAction SilentlyContinue
                $granted = [bool]($grants | Where-Object {
                    $_.ResourceId -eq $sentinelSp.Id -and $_.Scope -match $DelegatedScopeName
                })
            }
        }

        if ($granted) {
            Add-Result 'Delegated consent' 'PASS' "$DelegatedScopeName granted"
        }
        else {
            Add-Result 'Delegated consent' 'FAIL' "$DelegatedScopeName not consented - open the admin consent URL"
        }
    }
}

# --- 6. Demo account least privilege ---------------------------------------

if (-not $DemoAccount) {
    Add-Result 'Demo account privilege' 'SKIP' 'Pass -DemoAccount to check'
}
elseif (-not (Get-MgContext)) {
    Add-Result 'Demo account privilege' 'SKIP' 'Not connected to Graph'
}
else {
    try {
        $user = Get-MgUser -UserId $DemoAccount -ErrorAction Stop
        $roles = Get-MgUserMemberOf -UserId $user.Id -ErrorAction Stop |
                 Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.directoryRole' } |
                 ForEach-Object { $_.AdditionalProperties['displayName'] }

        $privileged = $roles | Where-Object {
            $_ -match 'Administrator|Global Reader|Security Operator'
        }

        if ($privileged) {
            Add-Result 'Demo account privilege' 'WARN' "Holds elevated role(s): $($privileged -join ', ')"
        }
        elseif ($roles -contains 'Security Reader') {
            Add-Result 'Demo account privilege' 'PASS' 'Security Reader only - matches slide 20'
        }
        else {
            Add-Result 'Demo account privilege' 'WARN' "Roles: $($roles -join ', ')"
        }
    }
    catch {
        Add-Result 'Demo account privilege' 'FAIL' $_.Exception.Message
    }
}

# --- 7. Endpoint reachability ----------------------------------------------
# Expect 401. Anything else means the URL or the network is the problem.

foreach ($endpoint in $McpEndpoints) {
    $label = 'MCP ' + ($endpoint -split '/')[-1]
    try {
        $resp = Invoke-WebRequest -Uri $endpoint -Method Get -SkipHttpErrorCheck `
                    -TimeoutSec 10 -ErrorAction Stop
        switch ($resp.StatusCode) {
            401     { Add-Result $label 'PASS' '401 Unauthorized - endpoint live, auth required' }
            404     { Add-Result $label 'FAIL' '404 - endpoint URL has moved, check Microsoft Learn' }
            default { Add-Result $label 'WARN' "HTTP $($resp.StatusCode) - unexpected, investigate" }
        }
    }
    catch {
        Add-Result $label 'FAIL' "Unreachable: $($_.Exception.Message)"
    }
}

# --- Summary ---------------------------------------------------------------

Write-Host ''
$fails = @($script:Results | Where-Object Status -eq 'FAIL')
$warns = @($script:Results | Where-Object Status -eq 'WARN')

if ($fails.Count -gt 0) {
    Write-Host "PRE-FLIGHT FAILED - $($fails.Count) blocking issue(s)." -ForegroundColor Red
    Write-Host 'Queue the recorded backup before you go on stage.' -ForegroundColor Red
}
elseif ($warns.Count -gt 0) {
    Write-Host "Pre-flight passed with $($warns.Count) warning(s). Review above." -ForegroundColor Yellow
}
else {
    Write-Host 'Pre-flight clean. Mission 1 is go.' -ForegroundColor Green
}
Write-Host ''

$script:Results
