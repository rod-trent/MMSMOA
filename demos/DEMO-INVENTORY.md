# Demo Inventory

Every demo in this repository, across four sessions and two events, with the
slide it belongs to and what it actually does.

*Last updated: 5 September 2026*

> Replaces `MMS MOA 2026 - Demo Inventory.docx`. That file was IRM
> rights-protected, so although it sat in a public repo nobody could open it —
> not GitHub's preview, not pandoc, not anyone who cloned it. Markdown renders
> for everyone, diffs in pull requests, and cannot rot the same way.

---

## MMS 2026 Midway Edition — San Diego, 25–28 October 2026

Everything in these two sessions runs **offline**: no tenant, no Azure, no
network. `python run-all-tests.py` from the repo root exercises all 13 suites in
about four seconds. They also run in a browser at
**[mms-midway-demos.vercel.app](https://mms-midway-demos.vercel.app)**.

### 🛡️ Empowering SOC Teams

*Monday 26 October, 3:00pm PDT · Seaport H · Rod Trent · Ken Goossens*

| # | Slide | Demo | File | What it does |
|---|-------|------|------|--------------|
| 1 | 14–15 | Wire the Model | [`Register-SentinelMcpApp.ps1`](empowering-soc-teams/01-mcp-connection/Register-SentinelMcpApp.ps1) | Creates the Entra public-client app with `SentinelPlatform.DelegatedAccess` and the right redirect URIs. Supports `-WhatIf`. Delegated, never application — the per-user RBAC story depends on it. |
| 1b | 14–15 | Pre-flight | [`Test-SentinelMcpConnection.ps1`](empowering-soc-teams/01-mcp-connection/Test-SentinelMcpConnection.ps1) | Seven checks in the order things actually break. Check 7 catches the conference network blocking egress to `sentinel.microsoft.com`, which is the most common day-of failure. |
| 2 | 15 | The Tool Layer | [`replay_mcp_server.py`](empowering-soc-teams/02-natural-language-triage/replay_mcp_server.py) | A real MCP server over stdio serving synthetic tenant data with the same tool shapes as the hosted Sentinel MCP server. `--self-test` asserts 13 guardrails: read-only, table allow-list, row cap, untrusted-data wrapping. |
| 3 | 15 | Ask Like an Analyst | [`triage_walkthrough.py`](empowering-soc-teams/02-natural-language-triage/triage_walkthrough.py) | Mission 1 replayed as a transcript. The model discovers tables, writes the KQL, then declines to answer until it has the UEBA baseline — which is what separates the real compromise from the VPN false positive. |
| 4 | 16–18 | Auto-Triage + Human on the Trigger | [`soc_triage_agent.py`](empowering-soc-teams/03-triage-agent-hitl/soc_triage_agent.py) | The six-stage loop with an approval gate the agent cannot pass without a recorded human decision — enforced in `AgentIdentity.check()`, not by convention. `--reject` shows the re-plan. |
| 5 | 20 | Prove the Guardrails Hold | [`test_injection_defense.py`](empowering-soc-teams/04-guardrails-injection-test/test_injection_defense.py) | Ten prompt-injection payloads and two benign controls, scored on detected / acted-on / reported. Reports one payload it does **not** detect, on purpose. |
| 6 | 21–22 | Instrument, Then Automate | [`Measure-SocRoi.ps1`](empowering-soc-teams/05-roi-baseline/Measure-SocRoi.ps1) | The four baseline metrics, which alert class to automate first, and an ROI model that includes human review time — the largest cost line. Sample mode needs no tenant. |

**Supporting files:** [`agent_config.json`](empowering-soc-teams/03-triage-agent-hitl/agent_config.json) (portable agent definition — identity, tool allow-list, output schema, approval policy), [`injection_corpus.json`](empowering-soc-teams/04-guardrails-injection-test/injection_corpus.json), [`kql/`](empowering-soc-teams/02-natural-language-triage/kql/) query sets, [`prompts.md`](empowering-soc-teams/02-natural-language-triage/prompts.md).

### 🔍 Using AI for Modern Threat Detection

*Tuesday 27 October, 10:00am PDT · Seaport G · Rod Trent · Chris Sires*

| # | Slide | Demo | File | What it does |
|---|-------|------|------|--------------|
| 7 | 11–12 | Prompts That Produce Evidence | [`Build-HuntPrompt.py`](modern-threat-detection/01-prompt-patterns/Build-HuntPrompt.py) | Renders the slide-12 hunting template for a hypothesis, and lints the hypothesis first — "find anything suspicious" gets three warnings. Six built-in presets, all falsifiable. |
| 8 | 14–15 | Speed the Investigation | [`hunt_service_accounts.py`](modern-threat-detection/02-hypothesis-hunt/hunt_service_accounts.py) | Mission 1. Two service accounts match the hypothesis; only one is a finding. The other is a documented break-glass on a compliant jump host, and the hunt must dismiss it. |
| 9 | 16–17 | What the Rules Missed | [`anomaly_to_detection.py`](modern-threat-detection/03-anomaly-to-detection/anomaly_to_detection.py) | Mission 2. UEBA anomalies → validated finding → a generated Sentinel analytics rule, and a flat refusal to generate that rule if you skip validation. |
| 10 | 19 | Validate Before You Believe | [`validate_finding.py`](modern-threat-detection/04-validation-harness/validate_finding.py) | The six validation techniques, ending in a verdict: still a lead, or now evidence. Includes seed-known-bad — a failed canary forces confidence to `none`. |
| 11 | 20 | Red-Team Your Own Hunt | [`Invoke-HuntRedTeam.py`](modern-threat-detection/05-injection-redteam/Invoke-HuntRedTeam.py) | Leakage and injection testing for a hunting workflow, mapped to the OWASP LLM Top 10. The highest-value injection against a hunt is not "do something" — it is "find nothing". |

**Supporting files:** [`hunting-prompt-template.md`](modern-threat-detection/01-prompt-patterns/hunting-prompt-template.md) (the slide the room photographs, as pasteable text), [`sample_hunt_data.json`](modern-threat-detection/02-hypothesis-hunt/sample_hunt_data.json), [`kql/mission1-hunt.kql`](modern-threat-detection/02-hypothesis-hunt/kql/mission1-hunt.kql), [`generated/`](modern-threat-detection/03-anomaly-to-detection/generated/) ARM + YAML analytics rule.

### Recordings

Silent screen recordings of the four missions, rendered from the demo scripts
themselves by [`record-demos.py`](../record-demos.py). They pause on the same
beats the live demo does.

| Recording | Mission | Length |
|-----------|---------|--------|
| [demo-08-mission1-triage.mp4](../web/public/video/demo-08-mission1-triage.mp4) | SOC Mission 1 | 0:31 |
| [demo-09-triage-agent-hitl.mp4](../web/public/video/demo-09-triage-agent-hitl.mp4) | SOC Mission 2 — clean run **and** the rejection | 1:26 |
| [demo-10-hypothesis-hunt.mp4](../web/public/video/demo-10-hypothesis-hunt.mp4) | Hunt Mission 1 — includes the decoy | 0:52 |
| [demo-11-anomaly-to-detection.mp4](../web/public/video/demo-11-anomaly-to-detection.mp4) | Hunt Mission 2 | 0:53 |

**No narration.** The MOA videos below are `-voiced` because someone talked over
them; these are not.

### Shared datasets

Both sessions use synthetic tenants built so the model has to do real work —
each contains a true positive **and** a near-identical benign twin that must be
correctly dismissed. Self-tests assert the dismissals.

| Dataset | True positive | The decoy that makes it a demo |
|---------|---------------|-------------------------------|
| [`sample_tenant.json`](empowering-soc-teams/02-natural-language-triage/sample_tenant.json) | Incident 48213 — Nairobi sign-in → new MFA method → OAuth consent to an unverified publisher → 218 mail items read | Incident 48209, identical in the raw logs, is a corporate VPN egress already in the account's 90-day baseline |
| [`sample_hunt_data.json`](modern-threat-detection/02-hypothesis-hunt/sample_hunt_data.json) | `svc-datasync` interactive from AS202425, then directory enumeration via Graph | `svc-reporting` does the same thing from an approved jump host inside change window CHG-88901 |

Both carry inert prompt-injection payloads in free-text fields. "CONTOSO-PROD",
its users and its incidents are fabricated.

---

## MMS MOA 2026 — Mall of America

*Rod Trent · Sergey Chubarov.* These require a real Microsoft 365 / Azure
tenant.

### Agentic Threat Hunting with Microsoft Sentinel

| # | Slide | Demo | File | What it does |
|---|-------|------|------|--------------|
| 1 | S14 | MCP Server for Sentinel | [`sentinel_mcp_server.py`](agentic-threat-hunting/01-mcp-server/sentinel_mcp_server.py) | Python MCP server exposing 5 KQL/Sentinel tools (`run_kql_query`, `get_failed_signins`, `get_incident_details`, `search_entities`, `get_ueba_insights`). Supports stdio and SSE transports. |
| 2 | S17 | Natural Language Threat Hunt | [`demo_hunt.py`](agentic-threat-hunting/02-natural-language-hunt/demo_hunt.py) | Animated AI agent investigation replay. Chains 4 tool calls to investigate a suspicious sign-in. Works offline using `sample_incident.json`. |
| 3 | S24 | Graph Investigation Walkthrough | [`graph_investigation.py`](agentic-threat-hunting/03-graph-investigation/graph_investigation.py) | Multi-stage attack chain walkthrough (password spray → OAuth persistence → exfiltration). MITRE ATT&CK mapping, plus `--export-html` for a standalone report. |
| 3b | — | Autonomous Threat Hunter Agent | [`sentinel_threat_hunter_agent.py`](agentic-threat-hunting/UnifiedAgent/sentinel_threat_hunter_agent.py) | Ties demos 1–3 into one agentic loop: plans, gathers evidence via MCP tools, maps to MITRE, reaches a verdict, writes an HTML report. `--replay` needs no Azure. |

### Governing GenAI: Monitoring and Securing Copilot with Microsoft Purview

| # | Slide | Demo | File | What it does |
|---|-------|------|------|--------------|
| 4 | S17 | Creating Sensitivity Labels for AI Content | [`Create-SensitivityLabels.ps1`](governing-genai/01-sensitivity-labels/Create-SensitivityLabels.ps1) | Four-tier label taxonomy (Public → Highly Confidential) with sublabels. Publishes a label policy and creates an auto-labeling simulation policy targeting SharePoint. |
| 5 | S18 | DLP Policy for Microsoft 365 Copilot | [`Create-CopilotDLPPolicy.ps1`](governing-genai/02-dlp-policy/Create-CopilotDLPPolicy.ps1) | Four rules on the `Microsoft365Copilot` workload: block PII, block PHI, block financial identifiers, warn on credentials. Defaults to `TestWithNotifications`. |
| 6 | S24 | Copilot Audit Log Analysis | [`Analyze-CopilotAuditLogs.ps1`](governing-genai/03-audit-log-analysis/Analyze-CopilotAuditLogs.ps1) | Queries the Unified Audit Log for `CopilotInteraction` and `DLPRuleMatch`. Reports daily volume, top users, workload distribution, DLP hits, after-hours activity. Exports CSV and HTML. |
| 7 | S31 | Blocking Sensitive Prompts in Practice | [`Test-DLPEnforcement.ps1`](governing-genai/04-blocking-sensitive-prompts/Test-DLPEnforcement.ps1) | Test patterns that trigger each rule. `-SimulateMode` shows a realistic enforcement report with no tenant; live mode queries actual blocked and warned Copilot events. |
| 7b | — | Governance Autopilot Agent | [`Invoke-GovernanceAutopilot.ps1`](governing-genai/Agent/Invoke-GovernanceAutopilot.ps1) | Runs the governance loop end to end and produces a scorecard. |

### Recordings

Narrated walkthroughs, embedded on the corresponding demo slide in each deck.

| Video | Demo |
|-------|------|
| [`demo-01-mcp-server-voiced.mp4`](agentic-threat-hunting/01-mcp-server/demo-01-mcp-server-voiced.mp4) | MCP server setup and first query |
| [`demo-02-nl-threat-hunt-voiced.mp4`](agentic-threat-hunting/02-natural-language-hunt/demo-02-nl-threat-hunt-voiced.mp4) | Natural language → KQL → lateral movement |
| [`demo-03-graph-investigation-voiced.mp4`](agentic-threat-hunting/03-graph-investigation/demo-03-graph-investigation-voiced.mp4) | Incident entity graph walkthrough |
| [`demo-04-sensitivity-labels-voiced.mp4`](governing-genai/01-sensitivity-labels/demo-04-sensitivity-labels-voiced.mp4) | Copilot-aware sensitivity labels |
| [`demo-05-dlp-policy-voiced.mp4`](governing-genai/02-dlp-policy/demo-05-dlp-policy-voiced.mp4) | DLP policy deployment |
| [`demo-06-audit-log-analysis-voiced.mp4`](governing-genai/03-audit-log-analysis/demo-06-audit-log-analysis-voiced.mp4) | Audit log analysis and reporting |
| [`demo-07-blocking-prompts-voiced.mp4`](governing-genai/04-blocking-sensitive-prompts/demo-07-blocking-prompts-voiced.mp4) | DLP enforcement validation |

The two agent demos have no recording — both run offline in replay mode, so the
terminal transcript is the walkthrough.

---

## Notes

- **Midway demos** need Python 3.10+ and nothing else. PowerShell 7+ for the two
  `.ps1` files, both of which have sample modes that need no tenant.
- **MOA demos** touch real tenant configuration. They start in simulation or
  read-only mode where they can. Read each script and its README first.
- All PowerShell demos support `-WhatIf` or `-SimulateMode` for safe dry runs.
- Every demo folder has a `README.md` with presenter talking points, timings,
  and the line worth saying out loud.
- Demo files live under `demos/` relative to the repository root.
- Governing GenAI needs `ExchangeOnlineManagement`
  (`Install-Module ExchangeOnlineManagement`); Agentic Threat Hunting needs the
  packages in its `requirements.txt`.

## Honest notes

Worth knowing before presenting any of it:

- In the Midway agent demos the **reasoning narration is scripted** so the stage
  runtime is predictable. The tool calls, guardrails, approval gate, scoring and
  logging are real, and the self-tests assert behaviour rather than output.
- Two demos deliberately report a payload they do **not** detect. Keyword
  screening catches 5–7 of 8; the tool allow-list catches 8 of 8. That gap is
  the lesson, and both print it on screen.
- The generated analytics rule's threshold was chosen against one synthetic
  campaign. Backtest 90 days in your own tenant before enabling it.
- Hosted Sentinel MCP endpoint URLs have changed before. Re-verify against
  Microsoft Learn the week of the conference.
