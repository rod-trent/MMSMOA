# Demo 2: Natural Language Threat Hunt
## Using MCP Tools to Investigate a Suspicious Sign-In Incident

This demo shows an AI agent using the MCP tools from Demo 1 to investigate
a suspicious sign-in incident the way an analyst would — but with natural language.

## What This Demonstrates
- An AI receiving an alert about a suspicious sign-in
- The AI calling `get_failed_signins`, `get_incident_details`, `search_entities`,
  and `get_ueba_insights` in sequence to build a complete investigation
- The AI producing a structured triage report with a recommended action

## Running the Demo

### Option A: Live agent against your MCP server
```bash
# First start the MCP server (Demo 1)
python ../01-mcp-server/sentinel_mcp_server.py &

# Then run the demo client
python demo_hunt.py --incident-id <your-incident-id>
```

### Option B: Replay mode (uses sample_incident.json — no Azure required)
```bash
python demo_hunt.py --replay
```

## Demo Narrative for Presenters
> "An analyst just got paged at 2 AM. Instead of logging into five portals,
> they ask Copilot: 'Investigate incident INC-2847 and tell me if it's real.'
> Here's what happens behind the scenes..."

The script prints each tool call + result in real time, then produces the
final investigation report, simulating exactly what Copilot for Security
would do with these tools connected.
