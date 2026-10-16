# Save a Hunt as an MCP Tool

**Slide 13 — *Your Best Hunts Become Tools*** · Session: *Using AI for Modern
Threat Detection*

Reference material for the callback slide. There is nothing to run here — this
is what you say, and what you show if someone asks you to prove it.

> **Prerelease.** Custom MCP tools are a preview feature. Re-read
> [the Learn article](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-create-custom-tool)
> the week of the conference.

---

## The callback

At MMS MOA, slide 16 of *Agentic Threat Hunting* was **"From KQL Query to MCP
Tool: Step-by-Step"** — seven steps. Microsoft now ships one of them as a menu
item. Here is the honest mapping:

| MOA step | Today |
|----------|-------|
| 1. Identify high-value, repeatable KQL from your runbooks | **Still yours.** Your saved-query library *is* the input. |
| 2. Parameterize the query — time range, entity values, thresholds | Put `{ParameterName}` directly in the KQL, then name and describe each one. |
| 3. Define the tool schema — name, description, parameters | The **Save tool** panel: Name, Description, Parameters. |
| 4. Implement the handler — call the API, return structured JSON | **Gone.** Microsoft runs the query. |
| 5. Add context enrichment — watchlists, threat intel, entity data | **Still yours.** It lives in the KQL. |
| 6. Test with real incidents | **Still yours.** |
| 7. Document the tool — the description is what the AI reads | **Still yours,** and now Microsoft publishes guidance for exactly this. |

**The line:** one step of seven went away, and it was the plumbing. The six that
decide whether the agent picks the right tool are still your job.

Do not oversell it. MOA's slide 16 speaker note was *"the AI doesn't need to know
KQL — it knows the tool name and parameters. KQL is abstracted away."* That is
still the whole idea; Microsoft just removed the part where you had to host it.

---

## How it actually works

1. In **Advanced hunting** in the Defender portal, open the query — authored by
   hand or from your saved library — and confirm it returns what you want the
   agent to reason over.
2. Choose **Save as tool**, from either the query's **context menu** or the
   **KQL query box menu**.
3. In the **Save tool** panel, fill in:
   - **Name** — discoverable, so the model can identify it
   - **Description** — see below; this is the field that matters
   - **Collection** — an existing tool collection, or **Create new collection**
   - **Default workspace** — the hint used when a prompt names no workspace
   - **Parameters** *(optional)* — each `{ParameterName}` from the query, with a
     name and a description so the model can populate it from context
4. **Save.** Saved tools appear on the **Tools** tab in Advanced hunting, and
   the collection gets its own MCP server URL you point a client at.

### Worked example

Take the Mission 1 hunt from
[`02-hypothesis-hunt/kql/mission1-hunt.kql`](02-hypothesis-hunt/kql/mission1-hunt.kql)
and lift the two values a hunter actually changes — the window and the naming
prefix:

```kusto
let window = {LookbackDays};
let service_accounts =
    IdentityInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by AccountUPN
    | where AccountUPN startswith "{AccountPrefix}"
        or AccountDisplayName has_any ("service account", "svc account")
    | distinct AccountUPN;
SigninLogs
| where TimeGenerated > ago(window)
| where UserPrincipalName in (service_accounts)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress,
          ASN = tostring(AutonomousSystemNumber),
          Location, City = tostring(LocationDetails.city),
          AppDisplayName, UserAgent,
          RiskLevelDuringSignIn,
          DeviceId = tostring(DeviceDetail.deviceId),
          IsCompliant = tostring(DeviceDetail.isCompliant)
| order by TimeGenerated desc
```

| Field | Value |
|-------|-------|
| Name | `find_interactive_service_account_signins` |
| Description | Retrieves successful interactive sign-ins for service accounts in a given lookback window. Use when checking whether non-human accounts are being used by a person. |
| Parameters | `LookbackDays` — how far back to search, e.g. `7d`.<br>`AccountPrefix` — the naming convention for service accounts, e.g. `svc-`. |

Note what did **not** change: the WOULD-MISS comment block in the original file
still applies. A tool does not make an empty result mean "no compromise."

---

## The description is the control surface

Microsoft's own guidance, and the thing to emphasise on stage:

- **Keep it short and action-oriented** — one or two sentences, starting with a
  verb and a resource ("Retrieves audit log data for a specific user").
- **Focus on purpose, not parameters** — the schema covers the parameters.
- **Include workflow hints only if critical** — e.g. "Call `risky_users_tool`
  first" — to prevent misuse.
- **Optimise for discoverability** — consistent naming, no ambiguous terms.

This is MOA slide 21's *"write tool descriptions in plain English — the AI reads
them, not you"* restated by the vendor. It is also an injection surface: the
name and description shape agent behaviour, so review tool definitions the way
you would review a rule, and keep each query narrowly scoped. That is the same
argument as [`05-injection-redteam`](05-injection-redteam/).

---

## Prerequisites and limits

- Microsoft Sentinel data lake **and** Microsoft Defender licenses
- **Security Operator**, **Security Admin**, or **Global Admin** to create,
  update, or delete custom tools
- **Security Reader** or **Global Reader** to list and invoke them
- Custom collections are consumed from **Security Copilot**, **Copilot Studio**,
  **Microsoft Foundry**, or **VS Code** — *not* from the claude.ai connector, so
  do not promise this one inside Claude

---

## If you are asked "should I do this?"

Yes, for the hunts you have already run more than twice and already trust. The
value is not that it is quicker to build; it is that a hunt which lives in a
tool gets run on days when nobody has two hours. That is the answer to slide 6:
*the interesting hunt is the one you never started.*

The risk is a library of half-trusted tools with vague descriptions that the
agent picks at random. Start with one.
