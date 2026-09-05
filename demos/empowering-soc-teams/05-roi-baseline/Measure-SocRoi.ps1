<#
.SYNOPSIS
    Baselines the four SOC metrics from slide 21 and models the ROI of
    automating one alert class.

.DESCRIPTION
    Demo 5 - "Measuring ROI: Instrument, Then Automate"
    Session:    Empowering SOC Teams
    Conference: MMS 2026 Midway Edition - San Diego, October 25-28 2026

    Slide 21 makes one demand: you cannot claim ROI without a baseline. This
    script captures it.

    The four metrics:
      1. Mean time to triage      alert created -> first disposition
      2. Uninvestigated rate      % of alerts no analyst ever touched
      3. Auto-disposition accuracy verdicts confirmed on review, no reopen
      4. Analyst hours reclaimed  time moved from triage into hunting

    Then it models:
      Benefit = alerts auto-triaged x minutes saved x loaded analyst rate
      Cost    = model tokens + platform licensing + engineering + review time

    Run it against your own workspace for 30 days BEFORE the first agent goes
    live. A number you measured after the fact is a number nobody believes.

.PARAMETER WorkspaceId
    Log Analytics workspace GUID. Omit to run against the sample data and see
    what the output looks like.

.PARAMETER Days
    Baseline window. Default 30. Slide 21 says 30 days before go-live.

.PARAMETER LoadedAnalystRate
    Fully loaded hourly cost of a Tier-1 analyst - salary, benefits, overhead,
    tooling. Default 65 USD. Use your own; finance will ask where it came from.

.PARAMETER AlertClass
    The alert class you plan to automate first. Slide 22 says pick one
    high-volume, low-risk class. Default: all classes, ranked by opportunity.

.PARAMETER AgentRunTable
    Custom table holding agent run records. Default SOCAgentRuns_CL - what
    Demo 3 writes. Accuracy is only computed if this table has data.

.EXAMPLE
    .\Measure-SocRoi.ps1
    Sample mode. No tenant needed - shows the report shape.

.EXAMPLE
    .\Measure-SocRoi.ps1 -WorkspaceId <guid> -Days 30 -LoadedAnalystRate 72

.EXAMPLE
    .\Measure-SocRoi.ps1 -WorkspaceId <guid> -AlertClass "Atypical travel"

.NOTES
    Requires Az.OperationalInsights for live mode.
    Read-only. Runs queries, writes nothing.
#>

[CmdletBinding()]
param(
    [string]   $WorkspaceId,
    [int]      $Days = 30,
    [double]   $LoadedAnalystRate = 65.0,
    [string]   $AlertClass,
    [string]   $AgentRunTable = 'SOCAgentRuns_CL',
    [string]   $ExportPath
)

$ErrorActionPreference = 'Stop'
$Sample = [string]::IsNullOrWhiteSpace($WorkspaceId)

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

function Write-Head {
    param([string] $Text)
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor DarkGray
    Write-Host " $Text" -ForegroundColor White
    Write-Host ('=' * 74) -ForegroundColor DarkGray
}

function Write-Metric {
    param(
        [string] $Name,
        [string] $Value,
        [string] $Benchmark,
        [string] $Verdict = ''
    )
    $color = switch ($Verdict) {
        'good'  { 'Green' }
        'bad'   { 'Red' }
        'watch' { 'Yellow' }
        default { 'White' }
    }
    Write-Host ('  {0,-26} ' -f $Name) -NoNewline
    Write-Host ('{0,-16}' -f $Value) -ForegroundColor $color -NoNewline
    Write-Host $Benchmark -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Queries - these are the actual metric definitions. Read them.
# ---------------------------------------------------------------------------

$Queries = @{

    MeanTimeToTriage = @"
// Metric 1: mean time to triage. Created -> first disposition.
// Industry baseline on slide 21: ~56 minutes to first action.
SecurityIncident
| where TimeGenerated > ago({0}d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where isnotempty(FirstModifiedTime)
| extend MinutesToTriage = datetime_diff('minute', FirstModifiedTime, CreatedTime)
| where MinutesToTriage between (0 .. 10080)   // drop clock-skew and stale reopens
| summarize
    Incidents   = count(),
    MeanMinutes = round(avg(MinutesToTriage), 1),
    P50         = round(percentile(MinutesToTriage, 50), 1),
    P90         = round(percentile(MinutesToTriage, 90), 1)
  by Severity
| order by Severity asc
"@

    UninvestigatedRate = @"
// Metric 2: what fraction of alerts nobody ever opened.
// Industry baseline on slide 21: 42%.
let window = {0}d;
let total = SecurityAlert | where TimeGenerated > ago(window) | count;
SecurityAlert
| where TimeGenerated > ago(window)
| join kind=leftouter (
    SecurityIncident
    | where TimeGenerated > ago(window)
    | mv-expand AlertId = AlertIds to typeof(string)
    | where isnotempty(Owner.assignedTo) or Status != "New"
    | distinct AlertId
  ) on \$left.SystemAlertId == \$right.AlertId
| summarize
    TotalAlerts    = count(),
    Touched        = countif(isnotempty(AlertId)),
    Untouched      = countif(isempty(AlertId))
| extend UninvestigatedPct = round(100.0 * Untouched / TotalAlerts, 1)
"@

    OpportunityByClass = @"
// Which alert class to automate first (slide 22: high volume, low risk).
// Opportunity = volume x mean handling time, weighted down by severity.
SecurityAlert
| where TimeGenerated > ago({0}d)
| summarize
    Volume       = count(),
    HighSeverity = countif(AlertSeverity == "High")
  by AlertName
| extend HighPct = round(100.0 * HighSeverity / Volume, 1)
| where Volume >= 20
| extend OpportunityScore = round(Volume * (1 - (HighPct / 100.0)), 0)
| top 10 by OpportunityScore desc
| project AlertName, Volume, HighPct, OpportunityScore
"@

    AgentAccuracy = @"
// Metric 3: auto-disposition accuracy. Slide 21 gate: >95% before you widen scope.
// Reads the run records the agent writes (Demo 3).
{1}
| where TimeGenerated > ago({0}d)
| extend Decision = tostring(human_decision_outcome_s),
         Disposition = tostring(disposition_s)
| summarize
    Runs      = count(),
    Approved  = countif(Decision == "approved"),
    Edited    = countif(Decision == "approved" and isnotempty(edited_disposition_s)),
    Rejected  = countif(Decision == "rejected")
  by Disposition
| extend AccuracyPct = round(100.0 * (Approved - Edited) / Runs, 1)
| order by Runs desc
"@

    HoursReclaimed = @"
// Metric 4: analyst hours reclaimed. Requires the agent run table.
{1}
| where TimeGenerated > ago({0}d)
| where tostring(human_decision_outcome_s) == "approved"
| summarize AutoTriaged = count()
| extend
    MinutesSavedPerAlert = {2},
    HoursReclaimed       = round(AutoTriaged * {2} / 60.0, 1)
"@
}

# ---------------------------------------------------------------------------
# Sample data - what a real 30-day baseline tends to look like
# ---------------------------------------------------------------------------

function Get-SampleBaseline {
    [pscustomobject]@{
        WindowDays          = $Days
        TotalAlerts         = 89760
        TotalIncidents      = 4213
        MeanMinutesToTriage = 68.4
        P50MinutesToTriage  = 41.0
        P90MinutesToTriage  = 187.0
        UninvestigatedPct   = 39.2
        AgentRuns           = 0
        Classes             = @(
            [pscustomobject]@{ AlertName = 'Atypical travel';                          Volume = 1842; HighPct = 4.1;  MeanHandleMinutes = 22 }
            [pscustomobject]@{ AlertName = 'Suspicious sign-in from unfamiliar ISP';   Volume = 1106; HighPct = 6.8;  MeanHandleMinutes = 18 }
            [pscustomobject]@{ AlertName = 'Malware detected and remediated';          Volume =   974; HighPct = 2.0;  MeanHandleMinutes = 12 }
            [pscustomobject]@{ AlertName = 'Multiple failed sign-ins then success';    Volume =   688; HighPct = 11.3; MeanHandleMinutes = 31 }
            [pscustomobject]@{ AlertName = 'Anomalous file download volume';           Volume =   402; HighPct = 14.9; MeanHandleMinutes = 44 }
            [pscustomobject]@{ AlertName = 'Suspicious inbox forwarding rule';         Volume =    97; HighPct = 62.9; MeanHandleMinutes = 55 }
        )
    }
}

function Invoke-Metric {
    param([string] $Name, [string] $Query)
    try {
        $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $Query -ErrorAction Stop
        return $result.Results
    }
    catch {
        Write-Warning "Metric '$Name' failed: $($_.Exception.Message)"
        return @()
    }
}

# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

Write-Head "SOC baseline - $Days days"

if ($Sample) {
    Write-Host '  SAMPLE MODE. No -WorkspaceId supplied, so these are illustrative' -ForegroundColor Yellow
    Write-Host '  numbers, not your tenant. Pass -WorkspaceId to measure for real.' -ForegroundColor Yellow
    $b = Get-SampleBaseline
}
else {
    if (-not (Get-Module -ListAvailable -Name Az.OperationalInsights)) {
        throw 'Az.OperationalInsights is not installed. Run: Install-Module Az.OperationalInsights -Scope CurrentUser'
    }
    Import-Module Az.OperationalInsights -ErrorAction Stop

    Write-Host "  Workspace $WorkspaceId" -ForegroundColor DarkGray
    Write-Host '  Querying...' -ForegroundColor DarkGray

    $mttt   = Invoke-Metric 'MeanTimeToTriage'   ($Queries.MeanTimeToTriage   -f $Days)
    $uninv  = Invoke-Metric 'UninvestigatedRate' ($Queries.UninvestigatedRate -f $Days)
    $classes= Invoke-Metric 'OpportunityByClass' ($Queries.OpportunityByClass -f $Days)
    $acc    = Invoke-Metric 'AgentAccuracy'      ($Queries.AgentAccuracy      -f $Days, $AgentRunTable)

    $weighted = 0.0; $totalIncidents = 0
    foreach ($row in $mttt) {
        $weighted += [double]$row.MeanMinutes * [int]$row.Incidents
        $totalIncidents += [int]$row.Incidents
    }

    $b = [pscustomobject]@{
        WindowDays          = $Days
        TotalAlerts         = if ($uninv) { [int]$uninv[0].TotalAlerts } else { 0 }
        TotalIncidents      = $totalIncidents
        MeanMinutesToTriage = if ($totalIncidents) { [math]::Round($weighted / $totalIncidents, 1) } else { 0 }
        P50MinutesToTriage  = if ($mttt) { [double]($mttt | Measure-Object P50 -Average).Average } else { 0 }
        P90MinutesToTriage  = if ($mttt) { [double]($mttt | Measure-Object P90 -Average).Average } else { 0 }
        UninvestigatedPct   = if ($uninv) { [double]$uninv[0].UninvestigatedPct } else { 0 }
        AgentRuns           = ($acc | Measure-Object Runs -Sum).Sum
        Classes             = $classes | ForEach-Object {
            [pscustomobject]@{
                AlertName         = $_.AlertName
                Volume            = [int]$_.Volume
                HighPct           = [double]$_.HighPct
                MeanHandleMinutes = 20   # substitute your own measured handling time
            }
        }
        AccuracyRows        = $acc
    }
}

# ---------------------------------------------------------------------------
# Report: the four metrics
# ---------------------------------------------------------------------------

Write-Head 'The four metrics (slide 21)'

$mtttVerdict = if ($b.MeanMinutesToTriage -le 30) { 'good' }
               elseif ($b.MeanMinutesToTriage -le 56) { 'watch' } else { 'bad' }
Write-Metric 'Mean time to triage' "$($b.MeanMinutesToTriage) min" 'industry ~56 min to first action' $mtttVerdict
Write-Metric '  p50 / p90'         "$($b.P50MinutesToTriage) / $($b.P90MinutesToTriage) min" 'p90 is where the pain actually is'

$uninvVerdict = if ($b.UninvestigatedPct -le 20) { 'good' }
                elseif ($b.UninvestigatedPct -le 42) { 'watch' } else { 'bad' }
Write-Metric 'Uninvestigated rate' "$($b.UninvestigatedPct)%" 'industry 42%' $uninvVerdict

if ($b.AgentRuns -gt 0) {
    $approved = ($b.AccuracyRows | Measure-Object Approved -Sum).Sum
    $edited   = ($b.AccuracyRows | Measure-Object Edited   -Sum).Sum
    $accuracy = [math]::Round(100.0 * ($approved - $edited) / $b.AgentRuns, 1)
    $accVerdict = if ($accuracy -ge 95) { 'good' } elseif ($accuracy -ge 85) { 'watch' } else { 'bad' }
    Write-Metric 'Auto-disposition accuracy' "$accuracy%" 'gate: >95% before widening scope' $accVerdict
}
else {
    Write-Metric 'Auto-disposition accuracy' 'no data' "no rows in $AgentRunTable yet - expected pre-agent"
}

Write-Metric 'Analyst hours reclaimed' $(if ($b.AgentRuns -gt 0) { 'see model below' } else { '0 (baseline)' }) 'target: 10 hrs/week into hunting'

# ---------------------------------------------------------------------------
# Report: where to start
# ---------------------------------------------------------------------------

Write-Head 'Where to start (slide 22: one high-volume, low-risk class)'

Write-Host ''
Write-Host ('  {0,-42} {1,8} {2,9} {3,12}' -f 'Alert class', 'Volume', 'High sev', 'Opportunity') -ForegroundColor DarkGray
Write-Host ('  ' + ('-' * 74)) -ForegroundColor DarkGray

$ranked = $b.Classes | ForEach-Object {
    $_ | Add-Member -NotePropertyName Opportunity `
                    -NotePropertyValue ([math]::Round($_.Volume * $_.MeanHandleMinutes * (1 - ($_.HighPct / 100.0)), 0)) `
                    -PassThru -Force
} | Sort-Object Opportunity -Descending

foreach ($cls in $ranked) {
    $color = if ($cls.HighPct -gt 30) { 'DarkGray' } else { 'White' }
    Write-Host ('  {0,-42} {1,8} {2,8}% {3,12}' -f
        $cls.AlertName, $cls.Volume, $cls.HighPct, $cls.Opportunity) -ForegroundColor $color
}

$pick = if ($AlertClass) { $ranked | Where-Object AlertName -eq $AlertClass | Select-Object -First 1 }
        else { $ranked | Where-Object HighPct -le 30 | Select-Object -First 1 }

if (-not $pick) {
    Write-Warning "Alert class '$AlertClass' not found in the window. Using the top-ranked class."
    $pick = $ranked | Select-Object -First 1
}

Write-Host ''
Write-Host "  Recommended first class: $($pick.AlertName)" -ForegroundColor Green
Write-Host "  $($pick.Volume) alerts in $($b.WindowDays) days, $($pick.HighPct)% high severity." -ForegroundColor DarkGray
Write-Host '  Greyed rows are high-severity classes. Do not start there.' -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Report: the ROI model
# ---------------------------------------------------------------------------

Write-Head 'ROI model (the version your CFO will accept)'

$perMonth        = [math]::Round($pick.Volume * (30.0 / $b.WindowDays), 0)
$minutesSaved    = [math]::Round($pick.MeanHandleMinutes * 0.8, 1)   # agent handles ~80% of the loop
$hoursPerMonth   = [math]::Round($perMonth * $minutesSaved / 60.0, 1)
$benefit         = [math]::Round($hoursPerMonth * $LoadedAnalystRate, 0)

# Costs. Token cost is genuinely small next to analyst time - that is usually
# the surprise. Adjust the per-run figure with your own measured usage.
$tokenCostPerRun = 0.06
$tokenCost       = [math]::Round($perMonth * $tokenCostPerRun, 0)
$platformCost    = 1200
$engineeringCost = [math]::Round((16 * $LoadedAnalystRate * 1.6) / 12, 0)   # ~16h build, amortised
$reviewMinutes   = 2.5
$reviewCost      = [math]::Round($perMonth * $reviewMinutes / 60.0 * $LoadedAnalystRate, 0)
$totalCost       = $tokenCost + $platformCost + $engineeringCost + $reviewCost
$net             = $benefit - $totalCost

Write-Host ''
Write-Host "  Class            $($pick.AlertName)"
Write-Host "  Volume           $perMonth alerts/month"
Write-Host "  Minutes saved    $minutesSaved of $($pick.MeanHandleMinutes) per alert (agent owns ~80% of the loop)"
Write-Host "  Analyst rate     `$$LoadedAnalystRate/hr fully loaded"
Write-Host ''
Write-Host '  BENEFIT' -ForegroundColor Green
Write-Host ("    {0,-34} {1,12}" -f "$hoursPerMonth analyst-hours/month", ('$' + $benefit.ToString('N0'))) -ForegroundColor Green
Write-Host ''
Write-Host '  COST' -ForegroundColor Yellow
Write-Host ("    {0,-34} {1,12}" -f 'Model tokens',        ('$' + $tokenCost.ToString('N0')))
Write-Host ("    {0,-34} {1,12}" -f 'Platform / licensing',('$' + $platformCost.ToString('N0')))
Write-Host ("    {0,-34} {1,12}" -f 'Engineering (amortised)',('$' + $engineeringCost.ToString('N0')))
Write-Host ("    {0,-34} {1,12}" -f "Human review ($reviewMinutes min/alert)", ('$' + $reviewCost.ToString('N0')))
Write-Host ("    {0,-34} {1,12}" -f 'Total',               ('$' + $totalCost.ToString('N0'))) -ForegroundColor Yellow
Write-Host ''

$netColor = if ($net -gt 0) { 'Green' } else { 'Red' }
Write-Host ("  NET {0,-32} {1,12}/month" -f '', ('$' + $net.ToString('N0'))) -ForegroundColor $netColor
if ($net -gt 0) {
    Write-Host ("      {0,-30} {1,12}/year"  -f '', ('$' + ($net * 12).ToString('N0'))) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Sanity check before you show this to anyone: does the benefit' -ForegroundColor DarkGray
    Write-Host '  line represent hours your team actually gets back, or hours' -ForegroundColor DarkGray
    Write-Host '  nobody was spending in the first place? Alerts in the 42%' -ForegroundColor DarkGray
    Write-Host '  uninvestigated bucket cost you risk, not payroll. Automating' -ForegroundColor DarkGray
    Write-Host '  those is worth doing and it is not a payroll saving - say so' -ForegroundColor DarkGray
    Write-Host '  before your CFO says it for you.' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host '  Not modelled, and real: reduced dwell time, fewer missed true' -ForegroundColor DarkGray
Write-Host '  positives, and lower attrition. Slide 6 puts junior analyst' -ForegroundColor DarkGray
Write-Host '  turnover at 70% within three years - one avoided backfill is' -ForegroundColor DarkGray
Write-Host '  worth more than everything above.' -ForegroundColor DarkGray

Write-Host ''
Write-Host '  Human review is a real, recurring cost. Any ROI model that' -ForegroundColor DarkGray
Write-Host '  omits it is selling something.' -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Gate check
# ---------------------------------------------------------------------------

Write-Head 'Scaling gate (slide 21)'

Write-Host ''
if ($b.AgentRuns -eq 0) {
    Write-Host '  No agent runs yet. That is correct for a baseline.' -ForegroundColor White
    Write-Host '  Capture these four metrics for 30 days, THEN deploy the agent' -ForegroundColor DarkGray
    Write-Host '  read-only on one class, THEN compare. In that order.' -ForegroundColor DarkGray
}
elseif ($accuracy -ge 95) {
    Write-Host "  Accuracy $accuracy% is above the 95% gate." -ForegroundColor Green
    Write-Host '  You may widen scope - one class at a time, re-measuring each time.' -ForegroundColor DarkGray
}
else {
    Write-Host "  Accuracy $accuracy% is below the 95% gate." -ForegroundColor Red
    Write-Host '  Do not widen scope and do not enable auto-close. Tune first.' -ForegroundColor DarkGray
    Write-Host '  Every rejected run in the log is a tuning signal - read them.' -ForegroundColor DarkGray
}

if ($ExportPath) {
    $report = [ordered]@{
        generated_utc = (Get-Date).ToUniversalTime().ToString('o')
        sample_mode   = $Sample
        window_days   = $b.WindowDays
        metrics       = [ordered]@{
            mean_minutes_to_triage = $b.MeanMinutesToTriage
            p90_minutes_to_triage  = $b.P90MinutesToTriage
            uninvestigated_pct     = $b.UninvestigatedPct
            agent_runs             = $b.AgentRuns
        }
        recommended_class = $pick.AlertName
        roi = [ordered]@{
            alerts_per_month   = $perMonth
            hours_per_month    = $hoursPerMonth
            benefit_usd        = $benefit
            cost_usd           = $totalCost
            net_usd            = $net
            loaded_hourly_rate = $LoadedAnalystRate
        }
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -Path $ExportPath -Encoding utf8
    Write-Host ''
    Write-Host "  Report written to $ExportPath" -ForegroundColor DarkGray
}

Write-Host ''
