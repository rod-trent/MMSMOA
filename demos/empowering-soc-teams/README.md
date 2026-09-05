# Empowering SOC Teams

**How Claude, Copilot, ChatGPT, MCP Servers, and Agents Drive Efficiency**

MMS 2026 Midway Edition · Monday 26 October, 3:00pm PDT · Seaport H
Rod Trent · Ken Goossens

---

Security Operations Centers are overwhelmed by alerts. Junior analysts spend
most of their time on manual triage, log correlation, enrichment, and
investigation. These demos show how GenAI tools, MCP servers, and agents take
over the repetitive 80 percent — so the people can hunt.

Everything here runs **offline**. No tenant, no Azure, no network. The two live
missions use a real Sentinel tenant on stage; each has a replay path that looks
close enough to recover with.

## The demos

| # | Demo | Maps to | Runs offline |
|---|------|---------|:---:|
| 1 | [Wire the Model](01-mcp-connection/) | Mission 1, slides 14–15 | ✅ |
| 2 | [Ask Like an Analyst](02-natural-language-triage/) | Mission 1, slide 15 | ✅ |
| 3 | [Auto-Triage with a Human on the Trigger](03-triage-agent-hitl/) | Mission 2, slides 16–18 | ✅ |
| 4 | [Prove the Guardrails Hold](04-guardrails-injection-test/) | Slide 20 | ✅ |
| 5 | [Instrument, Then Automate](05-roi-baseline/) | Slides 21–22 | ✅ |

Demos 1–3 are the stage content. Demos 4–5 are the take-home answers to the two
questions that always come up in Q&A: *how do you keep it safe* and *how do you
prove it worked*.

## Quick start

```bash
pip install -r requirements.txt

# Session 1, end to end, no tenant required
cd 02-natural-language-triage && python replay_mcp_server.py --self-test
cd 02-natural-language-triage && python triage_walkthrough.py
cd 03-triage-agent-hitl      && python soc_triage_agent.py --incident 48213
cd 04-guardrails-injection-test && python test_injection_defense.py
cd 05-roi-baseline           && pwsh ./Measure-SocRoi.ps1
```

## The shared scenario

All the Python demos read `02-natural-language-triage/sample_tenant.json` — a
synthetic CONTOSO-PROD tenant built so the model has to do real work:

- **48213** is the true positive. Nairobi sign-in (first-time country and ASN)
  → new MFA method at +4 min → OAuth consent to an unverified publisher with
  `offline_access` at +11 min → 218 mail items read by that app at +13 min.
- **48209** looks identical in the raw logs and is **benign** — a corporate VPN
  egress that is already in the account's 90-day baseline. Without it, the demo
  would prove nothing.
- **48201** is a benign credential-attack lookalike with a change record.
- **48176** carries a prompt-injection payload in its description.

## Stage running order

| Block | Slides | Demo | Minutes |
|-------|--------|------|---------|
| Problem | 5–8 | — | 12 |
| Stack | 9–12 | — | 6 |
| **Mission 1** | 14–15 | 1 + 2 | 8 |
| Agent anatomy | 16 | — | 3 |
| **Mission 2** | 17–18 | 3 | 10 |
| Ship it | 19–23 | (4, 5 as reference) | rest |

## Recordings

Silent screen recordings of both missions, for when the live version cannot run.
They pause on the same beats the live demo does, so you can talk over them with
the rhythm you had planned.

| Recording | Mission | Length |
|-----------|---------|--------|
| [▶ demo-08-mission1-triage.mp4](../../web/public/video/demo-08-mission1-triage.mp4) | Mission 1 — ask like an analyst | 0:31 |
| [▶ demo-09-triage-agent-hitl.mp4](../../web/public/video/demo-09-triage-agent-hitl.mp4) | Mission 2 — the clean run **and** the rejection re-plan | 1:26 |

Both also play from their cards on the [demo site](https://mms-midway-demos.vercel.app/?s=soc). Re-render with
`python record-demos.py` from the repo root.

## Pre-flight

The morning of the session:

```powershell
cd 01-mcp-connection
Connect-AzAccount; Connect-MgGraph -Scopes Application.ReadWrite.All
.\Test-SentinelMcpConnection.ps1 -DemoAccount analyst@contoso.com
```

Seven checks, in the order things break. The most common day-of failure is not
auth — it is the conference network blocking egress to `sentinel.microsoft.com`,
which is check 7.

If it fails: point Claude at `02-natural-language-triage/replay_mcp_server.py`
and run the same prompts. Same tool names, same shape on screen.

## Prerequisites for the live version

- Sentinel **data lake enabled** — the hosted MCP server will not work without it
- Entra app registration with `SentinelPlatform.DelegatedAccess`, admin-consented
- A demo account with **Security Reader and nothing more**
- Python 3.10+ and PowerShell 7+
- `Az.Accounts`, `Az.Resources`, `Microsoft.Graph.Applications`,
  `Az.OperationalInsights`

## Honest notes

Things worth knowing before you demo this, and worth saying if asked:

- The agent's **reasoning narration is scripted** so the stage runtime is
  predictable. The tool calls, guardrails, approval gate, scoring, and logging
  are real, and `--self-test` proves the guardrails on both Demo 3 and Demo 4.
- `run_kql` in the replay layer is a **small evaluator, not a KQL engine**. It
  handles the queries these demos make and refuses everything dangerous.
- Demo 4 reports **one attack it does not detect** (base64-encoded), on purpose.
  Keyword screening is the weakest layer; the tool allow-list is what protects
  you. A scorecard showing 100% would be lying.
- Hosted Sentinel MCP endpoint URLs have changed before. Re-verify against
  Microsoft Learn the week of the conference.
