# MMS Session Materials — Rod Trent

Slide decks, demo code, and walkthroughs from Rod Trent's sessions at the
Midwest Management Summit.

All demo code is meant to be read before it is run. Review and adapt before
pointing any of it at a production tenant.

---

## 🎖️ MMS 2026 Midway Edition — San Diego

**25–28 October 2026 · Manchester Grand Hyatt**

Two sessions on putting GenAI, MCP servers, and agents to work in a SOC —
without giving up control, compliance, or judgement.

> **Everything in these two folders runs offline.** No tenant, no Azure, no
> network. Clone it and run it on a locked-down corporate laptop.
>
> ```bash
> python run-all-tests.py
> ```

---

### 🛡️ Empowering SOC Teams: How Claude, Copilot, ChatGPT, MCP Servers, and Agents Drive Efficiency

**Monday 26 October, 3:00pm PDT · Seaport H**
[Rod Trent](https://linkedin.com/in/rodtrent) · Ken Goossens

Security Operations Centers are overwhelmed by alerts. Junior analysts spend most
of their time on manual triage, log correlation, enrichment, and investigation.
This session shows how GenAI tools, MCP servers, and AI agents autonomously
handle triage, enrichment, and disposition — reducing alert fatigue and mean time
to triage, and turning junior analysts into power users focused on threat hunting
and proactive defense.

**What you will learn**

- **Connect** — one Entra app registration, and Claude, Copilot, or ChatGPT can
  investigate live Sentinel data under the analyst's own RBAC. Stop pasting logs
  into chat.
- **Automate** — build the triage → correlate → enrich → reason → approve → act
  loop as a production agent. Start with one noisy alert class.
- **Control** — least privilege, approval gates, prompt-injection defence, and
  full audit make agents deployable in regulated environments.
- **Measure and scale** — baseline mean-time-to-triage and uninvestigated rate
  first; expand scope only when accuracy earns it.

📁 **[Demos →](demos/empowering-soc-teams/)**

| # | Demo | What it does |
|---|------|--------------|
| 1 | [Wire the Model](demos/empowering-soc-teams/01-mcp-connection/) | Entra app registration for the hosted Sentinel MCP server, plus a seven-check pre-flight that tests the things that actually break |
| 2 | [Ask Like an Analyst](demos/empowering-soc-teams/02-natural-language-triage/) | A working MCP server over stdio plus a replayable investigation — the model discovers tables, writes the KQL, and separates a real compromise from a VPN false positive |
| 3 | [Auto-Triage with a Human on the Trigger](demos/empowering-soc-teams/03-triage-agent-hitl/) | A six-stage triage agent that cannot write anything without a recorded human approval — and re-plans when you reject it |
| 4 | [Prove the Guardrails Hold](demos/empowering-soc-teams/04-guardrails-injection-test/) | Ten prompt-injection payloads and two benign controls, scored, with an honest report of what screening misses |
| 5 | [Instrument, Then Automate](demos/empowering-soc-teams/05-roi-baseline/) | The four baseline metrics and an ROI model that includes human review time — because omitting it is how these projects lose credibility |

---

### 🔍 Using AI for Modern Threat Detection

**Tuesday 27 October, 10:00am PDT · Seaport G**
[Rod Trent](https://linkedin.com/in/rodtrent) · Chris Sires

Traditional threat hunting relies on queries, dashboards, and time-consuming log
review. AI changes the game. This session covers how security teams surface
anomalies, accelerate investigations, and uncover patterns SIEM rules miss —
plus the validation techniques and guardrails that reduce false positives and
prevent blind trust.

**What you will learn**

- **Tools** — UEBA, Copilot in Advanced Hunting, the Sentinel MCP server, and
  Claude/ChatGPT already cover the hunt loop. Connect them.
- **Prompt patterns** — scope and role, query-first, fixed schema, one hypothesis
  per thread, paste nothing. Prompt for evidence and disproof, not a verdict.
- **Guardrails** — query under the analyst's RBAC, log everything, treat data as
  hostile, never let retrieved content pick a tool.
- **Validate, then trust** — re-query, cross-source, baseline, seed known bad.
  A model finding is a lead until a human makes it evidence.

📁 **[Demos →](demos/modern-threat-detection/)**

| # | Demo | What it does |
|---|------|--------------|
| 1 | [Prompts That Produce Evidence](demos/modern-threat-detection/01-prompt-patterns/) | The hunting prompt template as text, plus a linter that tells you when your hypothesis is not falsifiable |
| 2 | [Speed the Investigation](demos/modern-threat-detection/02-hypothesis-hunt/) | Hypothesis to evidence with no hand-written KQL — including a decoy the hunt must correctly dismiss |
| 3 | [What the Rules Missed](demos/modern-threat-detection/03-anomaly-to-detection/) | UEBA anomalies → validated finding → a generated Sentinel analytics rule, and it refuses to generate the rule if you skip validation |
| 4 | [Validate Before You Believe](demos/modern-threat-detection/04-validation-harness/) | The six validation techniques, ending in a verdict. Includes seed-known-bad, the one everyone forgets |
| 5 | [Red-Team Your Own Hunt](demos/modern-threat-detection/05-injection-redteam/) | Leakage and injection testing for a hunting workflow, mapped to the OWASP LLM Top 10 |

---

### Quick start

```bash
git clone https://github.com/rod-trent/MMSMOA.git
cd MMSMOA
python run-all-tests.py          # 13 suites, ~4 seconds, no dependencies
```

Then pick a demo:

```bash
python demos/empowering-soc-teams/03-triage-agent-hitl/soc_triage_agent.py --incident 48213
python demos/modern-threat-detection/02-hypothesis-hunt/hunt_service_accounts.py
```

Only one thing needs installing, and only if you want to drive the replay MCP
server from Claude yourself:

```bash
pip install -r demos/empowering-soc-teams/requirements.txt   # just `mcp`
```

### What is real and what is scripted

Worth stating plainly, because these are demos and demos lie by omission:

| Real | Scripted |
|------|----------|
| Tool calls, data, correlation, and scoring | The model's reasoning *narration* — a live model picks its own words; a stage demo needs a known runtime |
| Every guardrail: tool allow-lists, approval gates, injection screening, read-only enforcement | — |
| The run logs, the JSON contracts, the generated analytics rule | — |
| All 13 self-test suites, which assert behaviour rather than output | — |

Swap the scripted reasoning for a real model call (Claude Agent SDK, Security
Copilot, Copilot Studio) and nothing else changes. The shape is the product.

Two results are deliberately **not** perfect, because a demo that scores 100% on
everything is not teaching you anything:

- The SOC injection scorecard misses one base64-encoded payload
- The hunt red-team misses the same class

Keyword screening caught 5–7 of 8. **Tool design caught 8 of 8.** That gap is the
lesson, and both demos say so on screen.

---

## 🏟️ MMS MOA 2026 — Mall of America

Sessions with [Sergey Chubarov](https://linkedin.com/in/schubarov). These demos
require a real Microsoft 365 / Azure tenant.

### Agentic Threat Hunting with Microsoft Sentinel: From MCP Server to Graph Insights

Transform common KQL queries into reusable MCP tools, connect them to Copilot or
custom agents, and navigate entity relationships (Account ↔ Device ↔ IP ↔ App)
with UEBA.

📁 **[Demos →](demos/agentic-threat-hunting/)**

| # | Demo | Script |
|---|------|--------|
| 1 | Building Your First MCP Tool | [`sentinel_mcp_server.py`](demos/agentic-threat-hunting/01-mcp-server/sentinel_mcp_server.py) |
| 2 | Natural Language Threat Hunt | [`demo_hunt.py`](demos/agentic-threat-hunting/02-natural-language-hunt/demo_hunt.py) |
| 3 | Graph Investigation Walkthrough | [`graph_investigation.py`](demos/agentic-threat-hunting/03-graph-investigation/graph_investigation.py) |
| 4 | Autonomous Threat Hunter Agent | [`sentinel_threat_hunter_agent.py`](demos/agentic-threat-hunting/UnifiedAgent/sentinel_threat_hunter_agent.py) |

### Governing GenAI: Monitoring and Securing Copilot with Microsoft Purview

Map GenAI and Copilot risks — sensitive prompts, data exfiltration, insider
misuse — to Purview controls: sensitivity labels, DLP policies, insider risk
signals, audit, and eDiscovery.

📁 **[Demos →](demos/governing-genai/)**

| # | Demo | Script |
|---|------|--------|
| 5 | Sensitivity Labels for AI Content | [`Create-SensitivityLabels.ps1`](demos/governing-genai/01-sensitivity-labels/Create-SensitivityLabels.ps1) |
| 6 | DLP Policy for Microsoft 365 Copilot | [`Create-CopilotDLPPolicy.ps1`](demos/governing-genai/02-dlp-policy/Create-CopilotDLPPolicy.ps1) |
| 7 | Copilot Audit Log Analysis | [`Analyze-CopilotAuditLogs.ps1`](demos/governing-genai/03-audit-log-analysis/Analyze-CopilotAuditLogs.ps1) |
| 8 | Blocking Sensitive Prompts | [`Test-DLPEnforcement.ps1`](demos/governing-genai/04-blocking-sensitive-prompts/Test-DLPEnforcement.ps1) |
| 9 | Governance Autopilot Agent | [`Invoke-GovernanceAutopilot.ps1`](demos/governing-genai/Agent/Invoke-GovernanceAutopilot.ps1) |

Each MOA demo folder includes an MP4 walkthrough with narration, also embedded in
the slide decks.

> ⚠️ The MOA PowerShell demos touch real tenant configuration. They start in
> simulation / read-only mode where they can. Read each script and its README
> before running against a production tenant.

---

## Repository structure

```
MMSMOA/
├── README.md
├── run-all-tests.py                    ← runs all 13 Midway demo suites offline
│
├── SlideDecks/
│   ├── Empowering SOC Teams - MMS Midway 2026.pptx
│   ├── Using AI for Modern Threat Detection - MMS Midway 2026.pptx
│   ├── Agentic Threat Hunting - MMS MOA 2026.pptx
│   └── Governing GenAI - MMS MOA 2026.pptx
│
└── demos/
    ├── empowering-soc-teams/           ← MMS Midway 2026, offline
    │   ├── 01-mcp-connection/
    │   ├── 02-natural-language-triage/
    │   ├── 03-triage-agent-hitl/
    │   ├── 04-guardrails-injection-test/
    │   └── 05-roi-baseline/
    │
    ├── modern-threat-detection/        ← MMS Midway 2026, offline
    │   ├── 01-prompt-patterns/
    │   ├── 02-hypothesis-hunt/
    │   ├── 03-anomaly-to-detection/
    │   ├── 04-validation-harness/
    │   └── 05-injection-redteam/
    │
    ├── agentic-threat-hunting/         ← MMS MOA 2026, needs a tenant
    └── governing-genai/                ← MMS MOA 2026, needs a tenant
```

## Prerequisites

**MMS Midway demos** — Python 3.10+. That is it. PowerShell 7+ for the two
`.ps1` scripts (`Register-SentinelMcpApp.ps1`, `Measure-SocRoi.ps1`), which have
sample modes that need no tenant.

For the **live** versions on stage you additionally need:

- Microsoft Sentinel with the **data lake enabled** — the hosted MCP server will
  not work without it
- An Entra app registration with `SentinelPlatform.DelegatedAccess`, admin-consented
- A demo account holding **Security Reader and nothing more**
- **UEBA with at least 14 days of baseline** — the prerequisite most likely to be
  missing, and without it two of the four missions lose their punchline
- `Az.Accounts`, `Az.Resources`, `Az.OperationalInsights`, `Microsoft.Graph.Applications`

**MMS MOA demos** — see [`demos/agentic-threat-hunting/`](demos/agentic-threat-hunting/)
and [`demos/governing-genai/`](demos/governing-genai/).

## Speakers

<table>
<tr>
<td align="center" width="210">
<strong>Rod Trent</strong><br/>
Senior Product Manager, Microsoft Security<br/>
Security MVP Program Lead<br/>
Author · Speaker · Community Lead<br/>
<a href="https://x.com/rodtrent">@rodtrent</a> · <a href="https://linkedin.com/in/rodtrent">LinkedIn</a>
</td>
<td align="center" width="210">
<strong>Ken Goossens</strong><br/>
Co-presenter<br/>
<em>Empowering SOC Teams</em><br/>
MMS 2026 Midway Edition
</td>
<td align="center" width="210">
<strong>Chris Sires</strong><br/>
Co-presenter<br/>
<em>Using AI for Modern Threat Detection</em><br/>
MMS 2026 Midway Edition
</td>
<td align="center" width="210">
<strong>Sergey Chubarov</strong><br/>
Microsoft MVP · Cloud Security Architect<br/>
Speaker · Trainer<br/>
MMS MOA 2026<br/>
<a href="https://x.com/SergeyTheMVP">@SergeyTheMVP</a> · <a href="https://linkedin.com/in/schubarov">LinkedIn</a>
</td>
</tr>
</table>

## Resources

| Topic | Link |
|-------|------|
| MMS 2026 Midway Edition | [mmsmoa.com/mms2026midway](https://mmsmoa.com/mms2026midway) |
| Microsoft Sentinel documentation | [aka.ms/sentineldocs](https://aka.ms/sentineldocs) |
| Microsoft Sentinel MCP server | [aka.ms/sentinel-mcp](https://aka.ms/sentinel-mcp) |
| Security Copilot | [aka.ms/securitycopilot](https://aka.ms/securitycopilot) |
| Microsoft Purview documentation | [aka.ms/purviewdocs](https://aka.ms/purviewdocs) |
| Model Context Protocol specification | [modelcontextprotocol.io](https://modelcontextprotocol.io) |
| Claude Agent SDK | [docs.claude.com](https://docs.claude.com) |
| OWASP Top 10 for LLM Applications | [genai.owasp.org](https://genai.owasp.org) |

## License

Code and scripts are provided under the [MIT License](LICENSE). Slide decks and
session materials are © the respective speakers, shared for educational use.

All tenant data in the Midway demos is **synthetic**. "CONTOSO-PROD", its users,
its incidents, and the IP addresses in it are fabricated for teaching. No real
organisation, person, or system is represented.

---

*#MMS2026 · #MMSMidway · Questions? Open an issue or connect on LinkedIn.*
