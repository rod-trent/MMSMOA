# MMS MOA 2026 — Session Materials

> **Midwest Management Summit — Mall of America 2026**

This repository contains the slide decks, demo scripts, and walkthrough videos for two sessions presented at MMS MOA 2026. All demo code is intended to be run in your own Microsoft 365 / Azure environment and is provided as a starting point — review and adapt before deploying in production.

---

## Sessions

### 🛡️ Agentic Threat Hunting with Microsoft Sentinel: From MCP Server to Graph Insights

**Speakers:** [Rod Trent](https://linkedin.com/in/rodtrent) · [Sergey Chubarov](https://linkedin.com/in/schubarov)

Develop a comprehensive threat-hunting strategy that integrates MCP Server for natural-language analysis with graph-driven investigations in Microsoft Sentinel. Learn to transform KQL queries into reusable MCP tools and connect them with Copilot or custom agents. Use entity mapping and User and Entity Behavior Analytics (UEBA) to uncover connections between identities, hosts, IPs, and apps while navigating through realistic incident scenarios.

**What you will learn:**

- **Operationalize agentic hunting** — Transform your team's common KQL queries into reusable MCP tools, enhancing efficiency with Copilot integration.
- **Think in graphs, not tables** — Navigate complex relationships (Account ↔ Device ↔ IP ↔ App) to speed up triage and root-cause analysis.
- **Fortify your ingestion pipeline** — Gain insights on normalization (ASIM), enrichment, and cost control within the Sentinel data lake.
- **Implement a rollout checklist** — Covering roles, permissions, change management, and metrics to ensure successful adoption of graph and MCP.

---

### 🔒 Governing GenAI: Monitoring and Securing Copilot with Microsoft Purview

**Speakers:** [Rod Trent](https://linkedin.com/in/rodtrent) · [Sergey Chubarov](https://linkedin.com/in/schubarov)

GenAI enhances productivity but introduces new data security and compliance challenges. Utilize Microsoft Purview as the control plane to address these risks. Explore strategies for mapping issues like sensitive prompts, data exfiltration, and insider misuse to Purview controls, including sensitivity labels, DLP policies, and insider risk signals. Develop a comprehensive approach to safeguarding sensitive data while maximizing the benefits of GenAI and Copilot.

**What you will learn:**

- **A practical blueprint** — Align GenAI and Copilot risks with Purview controls such as Labels, DLP, Insider Risk, Audit, and eDiscovery.
- **Build a monitoring view** — Use Purview Audit to track Copilot activity, policy hits, and identify false positives.
- **Implement policy patterns** — Prevent sensitive data exposure in prompts and outputs while stopping exfiltration avenues.
- **Develop a phased rollout plan** — Incorporating cohorts, simulation modes, and metrics to balance productivity and security.

---

## Demos

### Agentic Threat Hunting

| # | Demo | Script | Description |
|---|------|--------|-------------|
| 1 | Building Your First MCP Tool | [`sentinel_mcp_server.py`](demos/agentic-threat-hunting/01-mcp-server/sentinel_mcp_server.py) | A working MCP server that registers 5 Sentinel capabilities — KQL execution, failed sign-in analysis, incident retrieval, entity search, and UEBA insights — accessible from any MCP-compatible AI model. |
| 2 | Natural Language Threat Hunt | [`demo_hunt.py`](demos/agentic-threat-hunting/02-natural-language-hunt/demo_hunt.py) | Translates natural language threat-hunting queries into KQL, executes them against Sentinel, and surfaces lateral movement patterns across the entity graph. |
| 3 | Graph Investigation Walkthrough | [`graph_investigation.py`](demos/agentic-threat-hunting/03-graph-investigation/graph_investigation.py) | Loads a Sentinel incident, traces the full entity relationship graph (accounts → hosts → IPs), scores risk via UEBA, and produces a timeline-based investigation report. |

### Governing GenAI

| # | Demo | Script | Description |
|---|------|--------|-------------|
| 4 | Creating Sensitivity Labels for AI Content | [`Create-SensitivityLabels.ps1`](demos/governing-genai/01-sensitivity-labels/Create-SensitivityLabels.ps1) | Creates a hierarchical set of Purview sensitivity labels optimized for Microsoft 365 Copilot, including Copilot-aware protection settings. |
| 5 | DLP Policy for Microsoft 365 Copilot | [`Create-CopilotDLPPolicy.ps1`](demos/governing-genai/02-dlp-policy/Create-CopilotDLPPolicy.ps1) | Deploys a DLP policy targeting the Microsoft 365 Copilot location with SIT-based rules for PII, credentials, and proprietary data — starts in simulation mode. |
| 6 | Copilot Audit Log Analysis | [`Analyze-CopilotAuditLogs.ps1`](demos/governing-genai/03-audit-log-analysis/Analyze-CopilotAuditLogs.ps1) | Queries `CopilotInteraction` events from the Unified Audit Log, identifies policy hits and anomalous prompt patterns, and exports a summary report. |
| 7 | Blocking Sensitive Prompts in Practice | [`Test-DLPEnforcement.ps1`](demos/governing-genai/04-blocking-sensitive-prompts/Test-DLPEnforcement.ps1) | Simulates prompt submissions containing SSNs, health IDs, Azure secrets, and clean business queries to validate DLP enforcement is working as expected. |

---

## Demo Walkthrough Videos

Each demo folder includes an MP4 walkthrough with narration. Videos are also embedded directly in the slide decks on each demo slide.

| Video | Demo |
|-------|------|
| [`demo-01-mcp-server-voiced.mp4`](demos/agentic-threat-hunting/01-mcp-server/demo-01-mcp-server-voiced.mp4) | Sentinel MCP Server setup and first query |
| [`demo-02-nl-threat-hunt-voiced.mp4`](demos/agentic-threat-hunting/02-natural-language-hunt/demo-02-nl-threat-hunt-voiced.mp4) | Natural language → KQL → lateral movement detection |
| [`demo-03-graph-investigation-voiced.mp4`](demos/agentic-threat-hunting/03-graph-investigation/demo-03-graph-investigation-voiced.mp4) | Incident entity graph walkthrough |
| [`demo-04-sensitivity-labels-voiced.mp4`](demos/governing-genai/01-sensitivity-labels/demo-04-sensitivity-labels-voiced.mp4) | Creating Copilot-aware sensitivity labels |
| [`demo-05-dlp-policy-voiced.mp4`](demos/governing-genai/02-dlp-policy/demo-05-dlp-policy-voiced.mp4) | DLP policy deployment for M365 Copilot |
| [`demo-06-audit-log-analysis-voiced.mp4`](demos/governing-genai/03-audit-log-analysis/demo-06-audit-log-analysis-voiced.mp4) | Copilot audit log analysis and reporting |
| [`demo-07-blocking-prompts-voiced.mp4`](demos/governing-genai/04-blocking-sensitive-prompts/demo-07-blocking-prompts-voiced.mp4) | DLP enforcement validation |

---

## Repository Structure

```
📁 MMSMOA/
├── README.md                                   ← You are here
├── SlideDecks/Agentic Threat Hunting - MMS MOA 2026.pptx  ← Session 1 slide deck (44 slides)
├── SlideDecksGoverning GenAI - MMS MOA 2026.pptx         ← Session 2 slide deck (49 slides)
├── MMS MOA 2026 - Demo Inventory.docx          ← Full demo reference table
│
└── demos/
    ├── agentic-threat-hunting/
    │   ├── 01-mcp-server/
    │   │   ├── sentinel_mcp_server.py          ← MCP server implementation
    │   │   ├── requirements.txt
    │   │   ├── .env.example                    ← Required environment variables
    │   │   └── README.md
    │   ├── 02-natural-language-hunt/
    │   │   ├── demo_hunt.py
    │   │   ├── sample_incident.json            ← Sample incident for offline testing
    │   │   └── README.md
    │   └── 03-graph-investigation/
    │       ├── graph_investigation.py
    │       └── README.md
    │
    └── governing-genai/
        ├── 01-sensitivity-labels/
        │   ├── Create-SensitivityLabels.ps1
        │   └── README.md
        ├── 02-dlp-policy/
        │   ├── Create-CopilotDLPPolicy.ps1
        │   └── README.md
        ├── 03-audit-log-analysis/
        │   ├── Analyze-CopilotAuditLogs.ps1
        │   └── README.md
        └── 04-blocking-sensitive-prompts/
            ├── Test-DLPEnforcement.ps1
            └── README.md
```

---

## Prerequisites

### Agentic Threat Hunting demos (Python)

- Python 3.10+
- Microsoft Sentinel workspace with Log Analytics
- Azure service principal with **Microsoft Sentinel Reader** role
- An MCP-compatible AI client (Claude Desktop, Microsoft Copilot for Security, or compatible)

```bash
cd demos/agentic-threat-hunting/01-mcp-server
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your workspace ID, subscription, and credentials
python sentinel_mcp_server.py
```

### Governing GenAI demos (PowerShell)

- PowerShell 7+ (or Windows PowerShell 5.1)
- `ExchangeOnlineManagement` module (`Install-Module ExchangeOnlineManagement`)
- Microsoft 365 account with:
  - **Compliance Administrator** role (sensitivity labels, DLP, audit)
  - **Purview Audit** (Standard or Premium) enabled

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Connect-IPPSSession   # or Connect-ExchangeOnline
.\Create-SensitivityLabels.ps1
```

> ⚠️ **Important:** All demo scripts start in **simulation / read-only mode** by default. Review each script and its README before running in a production tenant.

---

## Speakers

<table>
<tr>
<td align="center" width="200">
<strong>Rod Trent</strong><br/>
Senior Product Manager, Microsoft Security<br/>
· Security MVP Program Lead<br/>
Author · Speaker · Security Community Lead<br/>
<a href="https://x.com/rodtrent">@rodtrent</a> · <a href="https://linkedin.com/in/rodtrent">LinkedIn</a>
</td>
<td align="center" width="200">
<strong>Sergey Chubarov</strong><br/>
Microsoft MVP · Cloud Security Architect<br/>
Speaker · Trainer<br/>
<a href="https://x.com/SergeyTheMVP">@SergeyTheMVP</a> · <a href="https://linkedin.com/in/schubarov">LinkedIn</a>
</td>
</tr>
</table>

---

## Resources

| Topic | Link |
|-------|------|
| Microsoft Sentinel documentation | [aka.ms/sentineldocs](https://aka.ms/sentineldocs) |
| MCP Server for Security Copilot | [aka.ms/securitycopilot](https://aka.ms/securitycopilot) |
| Microsoft Purview documentation | [aka.ms/purviewdocs](https://aka.ms/purviewdocs) |
| Microsoft 365 Copilot documentation | [aka.ms/m365copilotdocs](https://aka.ms/m365copilotdocs) |
| Model Context Protocol (MCP) specification | [modelcontextprotocol.io](https://modelcontextprotocol.io) |

---

## License

The code and scripts in this repository are provided under the [MIT License](LICENSE). Slide decks and session materials are © Rod Trent and Sergey Chubarov, shared for educational use at MMS MOA 2026.

---

*#MMSMOA2026 · Questions? Open an issue or connect with us on LinkedIn.*
