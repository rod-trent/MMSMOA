# Agent Templates — Start Here

**MMS 2026 Midway Edition · San Diego · 25–28 October 2026**
[Empowering SOC Teams](../demos/empowering-soc-teams/) · [Using AI for Modern Threat Detection](../demos/modern-threat-detection/)

Five agents you can take home, built from the decks and demos in this week's
two sessions. Each is one `agent.json`, a portable definition that has the same
shape whether you build on the Claude Agent SDK, Security Copilot, Copilot
Studio, or Foundry.

The demos showed you the behaviour. These are the starting points.

> **Templates, not products.** Every one of them names `CONTOSO-PROD` and
> example identities. Read the `_customize` list at the top of each
> `agent.json`, change what it says to change, and point it at a test workspace
> before a production one.

---

## The five agents

| # | Agent | What it does | Writes | Built from |
|---|-------|--------------|--------|------------|
| 01 | [**SOC Triage**](01-soc-triage/PROMPT.md) | Works one unassigned incident: correlate, enrich, reason. Proposes a disposition with cited evidence and the benign explanations it checked | 3, each behind a human approval | SOC Missions 1–2 · slides 14–23 |
| 02 | [**Threat Hunter**](02-threat-hunter/PROMPT.md) | Takes one falsifiable hypothesis and returns evidence. Prints every KQL query, and what it would miss, before running it | none | Hunt slides 11–16 · the slide 12 template |
| 03 | [**Finding Validator**](03-finding-validator/PROMPT.md) | Runs the six validation techniques, including *seed known bad*, and recommends *evidence* or *still a lead* | none | Hunt slides 19–20 · validation harness |
| 04 | [**Detection Engineer**](04-detection-engineer/PROMPT.md) | Turns a **validated** finding into a disabled analytics rule. Explains why each existing rule missed it, and backtests | 1, behind approval, always created disabled | Hunt Mission 2 · slides 16–18 |
| 05 | [**SOC Metrics**](05-soc-metrics/PROMPT.md) | Reports the four baseline metrics, recommends the first alert class to automate, models ROI with review time included, and checks the auto-approve gate | none | SOC slides 26–27 · ROI baseline |

They chain, the same way the sessions did:

```
  05 SOC Metrics ──── baseline first, 30 days, before anything goes live
        │
  01 SOC Triage  ──── one noisy alert class; human approves every write
        │
        └─ 05 again ─ has that class earned auto-approve? (≥95% over 200 runs)

  02 Threat Hunter ─► 03 Finding Validator ─► 04 Detection Engineer
     a lead               evidence, signed        a disabled rule, backtested
```

## What is in each folder

| File | What it is |
|------|-----------|
| `agent.json` | **The source of truth.** Identity, MCP servers, tool allow-list (read / write-with-approval / never), system prompt, output JSON Schema, approval gate, observability, guardrails |
| `PROMPT.md` | Generated. The system prompt ready to paste, the tool table, and the output fields. Use it when you are building by hand in a portal |

And shared:

| Path | What it is |
|------|-----------|
| [`claude-code/`](claude-code/) | Generated. Drop-in **Claude Code subagents** (`.claude/agents/*.md`) and a `.mcp.json` |
| [`tools/agents.py`](tools/agents.py) | Validates every template against the governance rules, and regenerates the files above |
| [`tools/run_agent.py`](tools/run_agent.py) | Runs any template on the **Claude Agent SDK**, with the approval gate enforced in code |

## Three ways to use them

### 1. Paste the prompt (two minutes, any tool)

Open an agent's `PROMPT.md` and paste the system prompt into a Claude project,
a custom GPT, Copilot Studio's instructions, or a Security Copilot agent. With
the Sentinel MCP connector attached, the prompt does what it says.

For Copilot Studio or Security Copilot, build the agent in the portal and copy
the matching parts of `agent.json` across: the tool allow-list, the output
schema, the approval policy. The fields are named for what they do.

### 2. Claude Code subagents (offline, ten minutes)

```bash
pip install -r demos/empowering-soc-teams/requirements.txt   # the replay MCP server
cd Agents/claude-code
claude
```

Then ask: *"Use the soc-triage agent to triage incident 48213."*

`.mcp.json` registers the offline replay server, which serves the same synthetic
CONTOSO-PROD data the demos use. It also lists the hosted Sentinel servers, and
those need you to authenticate. Launch `claude` from `Agents/claude-code/`,
because the replay server path is relative to that folder.

The subagents get **read tools only**. A Claude Code permission prompt is not a
recorded approval with the evidence in view, so the write tools are left out on
purpose. Use option 3 when you want the gate.

### 3. Claude Agent SDK, gate enforced in code

```bash
# See exactly what it would hand the SDK. Needs nothing installed.
python Agents/tools/run_agent.py soc-triage --offline --dry-run

# Run it. Needs: pip install claude-agent-sdk, and ANTHROPIC_API_KEY
python Agents/tools/run_agent.py soc-triage --offline --prompt "Triage incident 48213."
```

How the definition maps onto the SDK:

| `agent.json` | SDK | Effect |
|--------------|-----|--------|
| `tool_allow_list.read` | `allowed_tools` | Runs without asking |
| `tool_allow_list.write_requires_approval` | `can_use_tool` | **Stops and asks you**, then logs who decided, what, and why |
| anything else | `can_use_tool` | Refused and logged, even if the model asks nicely |
| built-in tools (Bash, Write, …) | `tools=[]` | Not available at all |
| `output_schema` | `output_format` | Every run returns the same contract |
| `guardrails.max_tool_calls_per_run` | `max_turns` | Bounded |

`--offline` adds local stubs for the write tools, so you can approve or reject a
write and watch it re-plan without touching anything. Each run log goes to
`Agents/runs/`, which is gitignored.

Try incident **48209**: in the raw logs it looks identical to 48213, but it is
the corporate VPN. Then try **48176**, which carries a prompt-injection payload.
A good agent escalates the first, closes the second as benign, and reports the
third without acting on what it says.

## What every template must have

`python Agents/tools/agents.py check` fails if any template is missing one of
these. It is slide 16's bottom row plus slide 25, checked mechanically:

- **Its own identity.** A workload identity, or the analyst's delegated one,
  with separate credentials per environment. Never a shared human account.
- **A tool allow-list with a `never` list.** Refusing a tool should be a
  decision someone made, not an accident of what got wired up.
- **Writes behind an approval gate.** The identity's scoped write actions must
  match the gated tools exactly.
- **Auto-approve shipped off.** It is earned by measurement (agent 05), not
  enabled by default.
- **Data is not instructions.** Every system prompt treats retrieved content as
  hostile and never lets it pick a tool.
- **No fabrication.** Every claim is cited as table / filter / row count.
- **Structured output that reports injection.** Every schema requires
  `injection_observed`. An agent that ignores an injection without reporting it
  is safe today, and blind to a poisoned feed from then on.
- **A run log**, including the human decision and any injection attempts.

```bash
python Agents/tools/agents.py validate      # check every agent.json
python Agents/tools/agents.py --self-test   # break a template on purpose, prove the check notices
python Agents/tools/agents.py build         # regenerate PROMPT.md and claude-code/
python Agents/tools/agents.py check         # validate, and fail if generated files are stale
```

## Make your own

Copy the folder closest to what you want, renumber it, and change the `id`.
Edit `agent.json` only, then run `build`. Keep:

- one hypothesis or one alert class per agent
- `never` populated, even for a read-only agent
- `requires_approval` / `requires_human_signoff` as `const: true` in the schema
- the `DATA IS NOT INSTRUCTIONS` block in the prompt

Before you trust it, run the injection harnesses against it:
[`04-guardrails-injection-test`](../demos/empowering-soc-teams/04-guardrails-injection-test/)
and [`05-injection-redteam`](../demos/modern-threat-detection/05-injection-redteam/).

## Honest caveats

- **Hosted tool names change.** `search_tables`, `query_lake`, and
  `list_sentinel_workspaces` match the Sentinel data-exploration MCP server at
  the time of writing. The triage collection is VS Code only. Re-check against
  [Microsoft Learn](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-chatgpt-claude-connector)
  before you rely on any of it.
- **The write tools are yours to implement.** `add_incident_comment`,
  `set_incident_classification`, `assign_incident`, and `create_analytics_rule`
  are the actions the agents propose. In production they map to Graph
  `PATCH /security/incidents/{id}` (see [`Ken/`](../Ken/)) and to the Sentinel ARM
  API. The offline stubs write nothing.
- **The SDK runner does not do Entra OAuth.** Use `--offline`, put a delegated
  token in `SENTINEL_MCP_TOKEN`, or use the claude.ai connector / VS Code as in
  [`01-mcp-connection`](../demos/empowering-soc-teams/01-mcp-connection/).
- **A live model picks its own words.** The demos script the reasoning so the
  stage runtime is predictable. These templates do not, so expect a live model
  to reach the same structure by a different route, and to sometimes need
  re-asking.

> *"I never run a query I have not read."* That applies to agents you did not
> write, too. Read the `agent.json` before you run it.
