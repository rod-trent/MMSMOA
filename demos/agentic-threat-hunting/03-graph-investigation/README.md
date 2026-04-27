# Demo 3: Graph Investigation Walkthrough
## Multi-Stage Attack Investigation Using Sentinel Graph + UEBA

This demo walks an audience through a complete multi-stage attack investigation:
password spray → initial access → OAuth persistence → mass download → exfiltration.

## What You'll See
- **Entity graph**: accounts, IPs, OAuth apps, and their relationships
- **MITRE-mapped timeline**: each step tagged to ATT&CK technique
- **UEBA insights**: risk scores and behavioral anomalies
- **Response playbook**: prioritized containment actions

## Running the Demo
```bash
# Terminal walkthrough (works offline — no Azure required)
python graph_investigation.py

# Export a standalone HTML report
python graph_investigation.py --export-html
```

## Live Mode (Requires Sentinel Access)
For a live demo, replace `ATTACK_CHAIN` in the script with calls to the
MCP server tools from Demo 1. The query pattern is:

```python
# 1. Get incident
incident = call_tool("get_incident_details", {"incident_id": "INC-2847"})

# 2. Build entity timeline
for entity in incident["entities"]:
    timeline = call_tool("search_entities", {"entity_value": entity["friendly_name"]})

# 3. Get UEBA for compromised account
ueba = call_tool("get_ueba_insights", {"user_upn": "jsmith@contoso.com"})
```

## Presenter Notes
> "This is the investigation graph that a Sentinel agent would build automatically
> from the same tool calls we saw in Demo 2 — but now visualized as a kill chain."
>
> Walk through each phase: point out how UEBA spotted the anomaly before
> the analyst even looked, and how the OAuth persistence would have survived
> a simple password reset.
