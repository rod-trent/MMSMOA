# Demos

Demo code for Rod Trent's MMS sessions. Two events, four sessions.

---

## MMS 2026 Midway Edition — San Diego, 25–28 October 2026

| Session | Demos |
|---------|-------|
| [Empowering SOC Teams](empowering-soc-teams/) | Sentinel MCP connection, natural-language triage, an auto-triage agent with a human approval gate, prompt-injection testing, ROI baselining |
| [Using AI for Modern Threat Detection](modern-threat-detection/) | Hunting prompt patterns, hypothesis-driven hunting, anomaly-to-detection, a validation harness, hunt red-teaming |

**Everything in these two folders runs offline.** No tenant, no Azure, no
network. Clone it and run it on a locked-down laptop.

```bash
python run-all-tests.py     # from the repo root
```

## MMS MOA 2026 — Mall of America

| Session | Demos |
|---------|-------|
| [Agentic Threat Hunting with Microsoft Sentinel](agentic-threat-hunting/) | Building an MCP server, natural-language hunting, graph investigation, a unified autonomous agent |
| [Governing GenAI with Microsoft Purview](governing-genai/) | Sensitivity labels, DLP policy, audit log analysis, blocking sensitive prompts, a governance autopilot agent |

These need a real tenant. See each folder's README for prerequisites.

---

## Which demo answers which question

| "How do I…" | Go to |
|-------------|-------|
| connect Claude/ChatGPT to Sentinel data | [empowering-soc-teams/01-mcp-connection](empowering-soc-teams/01-mcp-connection/) |
| build my own MCP server instead of using the hosted one | [agentic-threat-hunting/01-mcp-server](agentic-threat-hunting/01-mcp-server/) |
| get an agent to triage alerts without losing control | [empowering-soc-teams/03-triage-agent-hitl](empowering-soc-teams/03-triage-agent-hitl/) |
| write prompts that produce evidence instead of prose | [modern-threat-detection/01-prompt-patterns](modern-threat-detection/01-prompt-patterns/) |
| turn a hunch into a hunt into a detection rule | [modern-threat-detection/03-anomaly-to-detection](modern-threat-detection/03-anomaly-to-detection/) |
| prove my agent resists prompt injection | [empowering-soc-teams/04-guardrails-injection-test](empowering-soc-teams/04-guardrails-injection-test/) and [modern-threat-detection/05-injection-redteam](modern-threat-detection/05-injection-redteam/) |
| know whether a model finding is real | [modern-threat-detection/04-validation-harness](modern-threat-detection/04-validation-harness/) |
| justify any of this to a CFO | [empowering-soc-teams/05-roi-baseline](empowering-soc-teams/05-roi-baseline/) |
| govern Copilot usage with Purview | [governing-genai](governing-genai/) |

---

> ⚠️ Review every script before running it against a production tenant. The
> Midway demos are read-only and offline by default; the MOA demos touch real
> tenant configuration and start in simulation mode where they can.
