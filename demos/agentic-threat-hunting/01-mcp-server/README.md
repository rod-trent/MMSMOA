# Demo 1: Building Your First MCP Tool
## Transforming a KQL query into a callable MCP tool

This demo shows how to expose Microsoft Sentinel capabilities as MCP (Model Context Protocol)
tools that any AI assistant — including Copilot for Security — can call with natural language.

## What You'll Build
A Python MCP server that exposes four Sentinel tools:
- `run_kql_query` — execute arbitrary KQL against your Log Analytics workspace
- `get_incident_details` — fetch incident metadata, entities, and tactics
- `search_entities` — look up user/IP/host entity timeline across log sources
- `get_ueba_insights` — retrieve UEBA risk scores and behavior anomalies

## Prerequisites
```
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in your Azure/Sentinel details.

## Running the MCP Server

### Stdio transport (for Claude Desktop / local testing)
```bash
python sentinel_mcp_server.py
```

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "sentinel": {
      "command": "python",
      "args": ["/path/to/sentinel_mcp_server.py"],
      "env": {
        "AZURE_TENANT_ID": "...",
        "AZURE_CLIENT_ID": "...",
        "AZURE_CLIENT_SECRET": "...",
        "SENTINEL_WORKSPACE_ID": "...",
        "SENTINEL_SUBSCRIPTION_ID": "...",
        "SENTINEL_RESOURCE_GROUP": "...",
        "SENTINEL_WORKSPACE_NAME": "..."
      }
    }
  }
}
```

### SSE transport (for remote/Copilot for Security plugin)
```bash
uvicorn sentinel_mcp_server:app --host 0.0.0.0 --port 8080
```

## The Demo Scenario
The demo shows a KQL query for failed sign-in detections:

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| where ResultType in ("50126", "50053", "50055", "50056")
| summarize
    FailedAttempts = count(),
    DistinctIPs    = dcount(IPAddress),
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated)
    by UserPrincipalName, IPAddress, Location
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

**Step 1**: Show this query running directly in Log Analytics — it works but isn't AI-callable.

**Step 2**: Show the MCP server exposing `run_kql_query` — the AI can now call it.

**Step 3**: Show the richer `get_failed_signins` specialized tool that wraps this exact query
         with opinionated parameters and structured output.

## Azure App Registration Required Permissions
- **Microsoft Sentinel Reader** on the Sentinel workspace
- **Log Analytics Reader** on the Log Analytics workspace
- Microsoft Graph: `AuditLog.Read.All`, `User.Read.All` (for entity enrichment)
