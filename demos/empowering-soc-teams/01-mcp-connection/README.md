# Demo 1 — Wire the Model

**Mission 1, part A** · Session: *Empowering SOC Teams* · Slides 14–15

Connect Claude (or ChatGPT, VS Code, Copilot Studio) to the hosted Microsoft
Sentinel MCP server, so the model can investigate under the analyst's own RBAC
instead of having logs pasted into it.

---

## What this demonstrates

Slide 12's **Level 2 — Connected**: the assistant reaches live data through MCP.
The point to land on stage is that the assistant is no longer the integration —
the MCP server is. Swap Claude for ChatGPT and the plumbing does not change.

## Files

| File | What it does |
|------|--------------|
| `Register-SentinelMcpApp.ps1` | Creates the Entra **confidential-client** app registration (Web redirect URI + client secret) with `SentinelPlatform.DelegatedAccess`. Prints the ID and secret Claude's connector form needs. Supports `-WhatIf`. |
| `Test-SentinelMcpConnection.ps1` | Eight-check pre-flight. Run it the morning of the session. |
| `claude_desktop_config.example.json` | Reference for the three MCP collections plus the offline replay server, and how Claude actually connects (web UI, not this file). |

## Prerequisites

- Microsoft Sentinel **data lake enabled** — the hosted MCP server will not work without it
- An Entra account with **Application Administrator** to run the registration
- A **Privileged Role Administrator** to grant admin consent (the script prints the URL)
- A demo analyst account holding **Security Reader and nothing else** (this is the point of slide 20 — check it)
- **Tenant-level administrative privileges** to add the connector, per the Learn article
- A **Claude Pro, Max, Team, or Enterprise** plan — custom connectors are not on the free tier
- `Az.Accounts`, `Az.Resources`, `Microsoft.Graph.Applications`

```powershell
Install-Module Az.Accounts, Az.Resources, Microsoft.Graph.Applications -Scope CurrentUser
```

## Run it

```powershell
# 1. Dry run first. Read the plan before it touches the tenant.
.\Register-SentinelMcpApp.ps1 -WhatIf

# 2. For real
Connect-MgGraph -Scopes Application.ReadWrite.All
.\Register-SentinelMcpApp.ps1 -Client Claude,ChatGPT

# 3. Open the admin consent URL it prints, as a Privileged Role Administrator

# 4. Verify everything before you go on stage
Connect-AzAccount
.\Test-SentinelMcpConnection.ps1 -DemoAccount analyst@contoso.com
```

Then in Claude, go to **<https://claude.ai/customize/connectors>** → **+** →
**Add a custom connector** and fill in all four fields:

| Field | Value |
|-------|-------|
| Connector name | `Microsoft Sentinel MCP` |
| MCP Server URL | `https://sentinel.microsoft.com/mcp/data-exploration` |
| Client ID | the Application (client) ID the script printed |
| OAuth Client Secret | the secret the script printed (shown once) |

Click **Connect**, complete the OAuth sign-in as the Security Reader demo
account, then **Configure** to choose which tools are allowed.

> Adding a custom connector needs a **Claude Pro, Max, Team, or Enterprise**
> plan. The connector is a **prerelease** feature — re-read
> [the Learn article](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-chatgpt-claude-connector)
> the week of the conference.

## MCP collections

| Collection | Endpoint | Used by |
|-----------|----------|---------|
| Data Exploration | `https://sentinel.microsoft.com/mcp/data-exploration` | Demo 2 (Mission 1). **The only collection the Claude / ChatGPT connector supports.** |
| Triage | `https://sentinel.microsoft.com/mcp/triage` | Demo 3 (Mission 2). **Visual Studio Code only** — not reachable from claude.ai. |
| Agent Creation | `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation` | Building Security Copilot agents |

Mission 2 therefore runs either in **VS Code** with the triage collection, or
offline through [`03-triage-agent-hitl`](../03-triage-agent-hitl/). Don't promise
triage-inside-Claude from the stage.

> Endpoint URLs for the hosted server have changed before. Re-verify against
> Microsoft Learn the week of the conference.

## Stage notes

Walkthrough order from slide 15:

1. **Register the client** — show the app registration. Point out the
   *delegated* scope: the redirect URI sits on the **Web** platform and the app
   has a **client secret** (Claude's connector form asks for one), but the
   permission is delegated, never an application permission.
2. **Add the connector** — paste the URL, sign in. Narrate the consent screen.
3. **Discover tools** — ask Claude "what tools do you have?" and let it list the
   workspace. No KQL and no schema knowledge required yet.
4. **Ask like an analyst** — continues in Demo 2.
5. **Watch it pivot** — continues in Demo 2.
6. **Check the audit** — open the Sentinel audit view so the compliance people in
   the room see the trail. Same RBAC as the portal, logged the same way.

**The line for step 1:** *delegated, not application.* An application permission
would let the client read the whole workspace with no analyst identity attached,
and the per-user RBAC story on slide 11 would be a lie. The secret authenticates
the *connector*; the delegated token still carries the *analyst*.

## If it breaks

`Test-SentinelMcpConnection.ps1` checks the things that actually fail, in the
order they fail. The most common day-of problem is not auth — it is conference
Wi-Fi blocking egress to `sentinel.microsoft.com`. The last check catches that.

Fallback for a dead network: point the client at `sentinel-local-replay` in
`claude_desktop_config.example.json`, which serves a stand-in tool surface from
`../02-natural-language-triage/sample_tenant.json` with no tenant and no
network. The tool calls look identical on screen.
