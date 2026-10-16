# Pre-flight — MMS 2026 Midway Edition

Currency review of both Midway sessions against Microsoft Learn and the OWASP
LLM Top 10, run **16 October 2026** — nine days out, ahead of rehearsal week.

Sessions:
- **Empowering SOC Teams** — Monday 26 October, 3:00pm PDT, Seaport H
- **Using AI for Modern Threat Detection** — Tuesday 27 October, 10:00am PDT, Seaport G

---

## What changed in the repo

### Mission 1 would have failed on stage

`Register-SentinelMcpApp.ps1` created a **public client** with
`-IsFallbackPublicClient:$true` and no secret. Claude's custom-connector form
asks for an **Application (client) ID *and* an OAuth Client Secret**, so there
was nothing to paste into the second field — the connector could not have been
created live.

Fixed: the script now creates a **confidential client** with the redirect URI on
the **Web** platform and generates a **client secret** (`-SecretMonths`, default
6), printed once. `claude_desktop_config.example.json` previously said in so
many words *"Do not put a client secret in this file. The app registration
created by Register-SentinelMcpApp.ps1 is a public client and does not have
one."* That is gone.

Also corrected: the connector is added at **<https://claude.ai/customize/connectors>**
→ **+** → **Add a custom connector**, not *Settings → Connectors*.

`Test-SentinelMcpConnection.ps1` grew from seven checks to eight. It now fails
loudly if the Claude redirect URI is on the public-client platform instead of
Web, and warns if the client secret expires inside 14 days. Run it Monday
morning either way.

`-WhatIf` no longer hard-fails when `Microsoft.Graph.Applications` is missing —
it warns and prints the full plan, so you can rehearse the narration on any
machine.

### Mission 2 was promising something Claude cannot do

The Sentinel MCP **triage** collection is **Visual Studio Code only** today. It
is not reachable from the claude.ai connector. Slide 17's notes said Mission 2
*"uses the same Sentinel MCP connection plus the Triage collection"* — if you
say that and then someone asks to see it in Claude, there is nothing to show.

Fixed in the notes for slides 11 and 17: run Mission 2 **in VS Code**, or on the
**offline agent** in `03-triage-agent-hitl`, which is what the demo site does.

### Supported-client list was overstated

Slide 10's notes claimed the Sentinel MCP server *"officially supports Claude,
ChatGPT, VS Code, Security Copilot, Copilot Studio, Foundry, and Logic Apps."*

Two problems: **Logic Apps is not a documented MCP client**, and Claude/ChatGPT
are a separate, still-**prerelease** connector path rather than peers of the
first-party clients. Both notes rewritten. Slide 16 now says Logic Apps can
*orchestrate around* the agent — say "orchestration", not "MCP client".

### OWASP numbering was a year out of date

The **2026 edition** renumbered three entries you cite:

| Entry | Was | Now |
|-------|-----|-----|
| Excessive Agency | LLM06 | **LLM03** |
| Misinformation | LLM09 | **LLM07** |
| Improper Output Handling | LLM05 | **LLM10** |

LLM01 Prompt Injection and LLM02 Sensitive Information Disclosure are unchanged.

Updated in `injection_corpus.json`, `Invoke-HuntRedTeam.py`, both red-team
READMEs, and the **body text of hunt deck slide 20**. Slide 20's notes now carry
the renumbering so you can field it if an attendee cites the old numbers.

### Entity analyzer costs money

`analyze_user_entity` and `analyze_url_entity` need **Security Copilot
Contributor** on top of the Sentinel role, and they **consume Security Compute
Units**. Added to slide 11's notes and to the script's least-privilege step.
Security Reader is enough for everything else in Mission 1 — skip the analyzers
on stage unless you have SCUs to burn.

### Replay server tool names

`replay_mcp_server.py` exposes `list_tables`, `run_kql`, `get_ueba_baseline` and
friends. The hosted server calls them `search_tables`, `query_lake`,
`list_sentinel_workspaces`. The READMEs claimed *"the same tool shapes as the
hosted Sentinel MCP server"*, which was not true.

I did **not** rename the tools — that would invalidate the four recorded videos
and 29 baked transcripts nine days out. Instead the claim is now "analogous, not
identical", and `02-natural-language-triage/README.md` has a full mapping table.

**The line:** *"this is a stand-in so the demo runs without my tenant — the real
server calls it `query_lake`, and the shape of the conversation is the same."*
Say it once, move on.

---

## Verified correct — no change needed

- All three MCP endpoint URLs (`data-exploration`, `triage`,
  `security-copilot-agent-creation`)
- `SentinelPlatform.DelegatedAccess` as the delegated scope, and the insistence
  on delegated over application permissions
- Security Reader as the minimum role
- `https://claude.ai/api/mcp/auth_callback` as the redirect URI
- Data lake enablement as a hard prerequisite
- Every statistic in the hunt deck: Vectra's 2,992 alerts/day, and Prophet's
  49%/8% split, 38%, 72%, 57%, and 0%-full-autonomy figures
- All 13 offline suites: **passing in ~4s**, and `web/build.py --check` reports
  the site matches the committed demo code

**Pyodide stays pinned at 0.26.4.** 0.29.3 exists, but swapping the runtime out
from under five browser demos nine days before you present is risk with no
upside. The pin is stable and the CDN does not retire versions.

---

## Graph tools in Mission 1 — added 16 October 2026

Mission 1 gained **step 7: Map the blast radius**, built against the documented
preview graph tools. Tool names and parameter names were taken from Learn, not
from memory — and that caught two things my earlier note had wrong: there is a
sixth tool, `find_nodes`, and I had the descriptions of `find_walkable_paths`
and `find_connected_nodes` swapped.

| Tool | Parameters |
|------|-----------|
| `get_graph_context` | — |
| `find_nodes` | `validNodeLabel`, `validNodeProperties`, `resultsLimit` |
| `find_blastradius` | `sourceName` |
| `find_walkable_paths` | `sourceName`, `targetName` |
| `find_exposure_perimeter` | `targetName`, `minPathLength`, `maxPathLength`, `resultsCountLimit` |
| `find_connected_nodes` | `sourceNodeLabel`, `sourceNodeProperties`, `targetNodeLabel`, `targetNodeProperties`, `resultsCountLimit` |

It runs **offline**, like everything else. The replay server now serves all six
under their real names, and `--self-test` went from 13 assertions to **25**.

### The two moments to land

**"Eligible is not active."** Jordan Doe is PIM-eligible for `FIN-SOX-Approvers`,
which holds a role on `kv-contoso-fin-prod`. The edge exists, so a tool that
*counts* edges puts the key vault in the blast radius and sends you to wake up
its owner. The edge is not traversable — activation needs approval plus MFA —
so the correct answer shows the path and says why it is blocked. That is the
decoy, and it is the same discrimination test as the VPN false positive in the
earlier steps.

**"Two doors into the mailbox."** `find_exposure_perimeter` on the mailbox
returns two entry points: the account itself, and the Contoso Doc Sync OAuth
grant carrying `offline_access`. A password reset closes one of them. The
refresh token is not tied to the credential, so **revoke the grant first, then
reset**. Containment order is a graph question, and getting it backwards is how
an incident comes back three days later.

### What it costs you on stage

The UPN failure is scripted in on purpose: `find_blastradius` with
`j.doe@contoso.com` returns an error, because graph identity lookups do not
accept UPNs. Let it happen and read the error out — it is the most common
first-try failure with these tools.

Extra prerequisites beyond the rest of Mission 1:

- Data lake **onboarded to the Defender portal**
- At least **read-only access in Microsoft Security Exposure Management**
- Graph tools bill against the **Sentinel graph meter**, separately from the
  data lake, and they are **prerelease**

Mission 1 is now ~11 minutes against slide 14's 8. `prompts.md` gives you two
ways to cut it back to ~9. If the tenant misbehaves, **step 7 is the first thing
to drop** — the offline version on the demo site always works.

Slide 15 was reflowed from six cells to seven, and the Mission 1 video was
re-recorded (now 1:09, was 0:50). Slide 15 renders clean at 1600x900.

---

## Still open — your call

One thing I found but did not apply, because it changes the talk rather than
correcting it.

**Microsoft now ships what the MOA session taught.** You can build custom MCP
tools from saved KQL advanced-hunting queries. That is a genuine callback: *"last
time I showed you how to roll this yourself; Microsoft shipped it."* Costs a
slide.

---

## Fresher 2026 statistics — added 16 October 2026

Every figure below was re-verified against the publisher's own wording before it
went on a slide. One number in my earlier draft was wrong: Vectra's **63%**
refers to **alerts that go unaddressed**, not to share of workload. The slides
use the correct phrasing.

### Sources

- **Vectra AI, *2026 State of Threat Detection and Response Report*** — 1,450
  security practitioners, published 10 February 2026. "76% of defenders stating
  that AI agents and/or AI assistants now handle more than 10% of their
  workload"; "63% of alerts still go unaddressed"; "an average of 2,992 security
  alerts per day, down from 3,832 the year prior"; "71% of defenders report
  setting aside important security tasks at least two days per week."
- **Prophet Security, *State of AI in the SOC 2026*** — 250 IT and security
  professionals, surveyed by ViB. "Sixty percent said an alert they ignored or
  never investigated later proved material", and "for 34% that happened three or
  more times in twelve months"; "Forty percent have also turned off a detection
  rule, or say they might"; roughly **28%** of alerts uninvestigated on average,
  **22%** median.

### Where they landed

| Deck | Slide | Added |
|------|-------|-------|
| SOC | 6 — Drowning in Alerts | 60% ignored-alert-proved-material, as the consequence line |
| SOC | 7 — Volume Eases | "The queue shrank. The gap did not — 63% of alerts still go unaddressed." |
| SOC | 12 — Maturity Ladder | 76% already have AI handling >10% of their workload |
| SOC | 21 — Measuring ROI | second baseline for the uninvestigated rate: 28% (Prophet) beside 42% (Omdia) |
| Hunt | 6 — Hunting Works | 60% proved-material **and** 40% have turned off a detection rule |
| Hunt | 9 — Where AI Already Lives | new band: 76% already have AI handling >10% of their workload |
| Hunt | 16 — Mission 2 | the 40% rule-disabling figure, in the speaker notes, as the setup |

Speaker notes on each of those slides carry the sample size, the publication
date, and the supporting figures (34% three-or-more-times, 71% setting tasks
aside, 22% median) so you can answer a challenge without reaching for a phone.

**One more correction while I was in there:** hunt deck slide 9's *Sentinel MCP
server* card listed **Logic Apps** as a client in visible body text. Same
inaccuracy I fixed in the SOC deck's notes, but on screen. Removed, and the card
now says Claude/ChatGPT reach it via connector.

All six changed slides were rendered to PNG and checked for clipping.

---

## Monday morning checklist

```powershell
# 1. Tenant path — do this first, it is the only part that can fail on stage
cd demos/empowering-soc-teams/01-mcp-connection
./Register-SentinelMcpApp.ps1 -WhatIf          # read the plan
Connect-MgGraph -Scopes Application.ReadWrite.All
./Register-SentinelMcpApp.ps1 -Client Claude   # copy the secret immediately
# open the admin-consent URL it prints
./Test-SentinelMcpConnection.ps1 -DemoAccount analyst@contoso.com
```

```bash
# 2. Offline path — the fallback that cannot fail
python run-all-tests.py        # expect: all 13 suites passed
python web/build.py --check    # expect: up to date
```

Then open <https://mms-midway-demos.vercel.app>, set the pause mode to **every
step**, and walk both sessions once end to end. Rehearse Mission 1 step 7 twice —
it is the newest material and the one with a scripted error in it.

*Review run 16 October 2026. Re-read the
[connector article](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-chatgpt-claude-connector)
the morning of the 26th — it is prerelease and it is the part most likely to
move.*
