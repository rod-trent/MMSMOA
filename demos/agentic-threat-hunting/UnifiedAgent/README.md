# Demo: Autonomous Threat Hunter Agent

## What This Demonstrates

This is the culmination demo that ties together all three previous demos into a **single autonomous agent**:

1. **MCP Server** (Demo 01) — The agent calls Sentinel MCP tools to gather evidence
2. **Natural Language Hunting** (Demo 02) — The agent reasons about findings in natural language
3. **Graph Investigation** (Demo 03) — The agent builds entity graphs and generates HTML reports

## How It Works

The agent operates as a full **agentic loop**:

```
┌─────────────────────────────────────────────────────────┐
│  ANALYST PROMPT                                         │
│  "Investigate incident INC-2847"                        │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  AGENT PLANNING                                         │
│  • Identify investigation steps                         │
│  • Determine which MCP tools to call                    │
│  • Set evidence thresholds for verdict                  │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  EVIDENCE GATHERING (MCP Tool Calls)                    │
│  Step 1: get_incident_details → scope & entities        │
│  Step 2: get_failed_signins → credential attack pattern │
│  Step 3: search_entities → post-compromise timeline     │
│  Step 4: get_ueba_insights → behavioral anomalies       │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  ANALYSIS & SYNTHESIS                                   │
│  • Build entity relationship graph                      │
│  • Map to MITRE ATT&CK framework                        │
│  • Determine verdict & confidence                       │
│  • Generate response actions                            │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  REPORT GENERATION                                      │
│  • Interactive terminal display                         │
│  • Standalone HTML investigation report                 │
│  • CISO escalation recommendation                       │
└─────────────────────────────────────────────────────────┘
```

## Usage

```bash
# Offline replay mode (no Azure needed — default)
python sentinel_threat_hunter_agent.py --replay

# With a natural language prompt
python sentinel_threat_hunter_agent.py --prompt "Is jsmith@contoso.com compromised?"

# Live mode (requires running MCP server + Azure credentials)
python sentinel_threat_hunter_agent.py --live --incident-id INC-2847

# Skip HTML report generation
python sentinel_threat_hunter_agent.py --replay --no-html
```

## Key Talking Points for the Demo

- **Autonomous reasoning** — The agent explains *why* it's calling each tool
- **Evidence correlation** — Multiple data sources are combined for high-confidence verdicts
- **Speed** — Full investigation in ~15 seconds vs. 45-90 minutes manually
- **MITRE ATT&CK mapping** — Automatic technique identification across kill chain
- **Actionable output** — Prioritized response actions, not just data
- **Report generation** — Production-ready HTML report for stakeholders

## Architecture

```
sentinel_threat_hunter_agent.py
├── InvestigationState     — Tracks all evidence during investigation
├── AGENT_PLAN             — Defines the reasoning steps
├── Step functions          — Each implements one investigation phase
├── Graph construction      — Builds entity relationships + MITRE mapping
├── Verdict synthesis       — Determines true/false positive with confidence
└── HTML report generator   — Standalone visual report for stakeholders
```

## Requirements

Same as Demo 01 (for live mode). Replay mode has no dependencies beyond Python 3.10+.
