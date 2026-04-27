"""
sentinel_mcp_server.py
======================
MCP server exposing Microsoft Sentinel as callable tools for AI agents.

Demo: "Building Your First MCP Tool"
Session: Agentic Threat Hunting with Microsoft Sentinel
Conference: MMS MOA 2026

Transport: stdio (default) or SSE (set MCP_TRANSPORT=sse)
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    TextContent,
    Tool,
)

# Azure SDKs
from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.mgmt.securityinsight import SecurityInsights
from azure.core.exceptions import HttpResponseError

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TENANT_ID       = os.environ["AZURE_TENANT_ID"]
CLIENT_ID       = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET   = os.environ["AZURE_CLIENT_SECRET"]
WORKSPACE_ID    = os.environ["SENTINEL_WORKSPACE_ID"]
SUBSCRIPTION_ID = os.environ["SENTINEL_SUBSCRIPTION_ID"]
RESOURCE_GROUP  = os.environ["SENTINEL_RESOURCE_GROUP"]
WORKSPACE_NAME  = os.environ["SENTINEL_WORKSPACE_NAME"]

# Tables the AI is allowed to query (security guardrail)
_ALLOWLIST_RAW = os.getenv("KQL_TABLE_ALLOWLIST", "")
KQL_TABLE_ALLOWLIST: list[str] = (
    [t.strip() for t in _ALLOWLIST_RAW.split(",") if t.strip()]
    if _ALLOWLIST_RAW
    else []
)

# ---------------------------------------------------------------------------
# Azure credential + clients  (lazy init at first use)
# ---------------------------------------------------------------------------

_credential: ClientSecretCredential | None = None
_logs_client: LogsQueryClient | None = None
_sentinel_client: SecurityInsights | None = None


def _get_credential() -> ClientSecretCredential:
    global _credential
    if _credential is None:
        _credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    return _credential


def _get_logs_client() -> LogsQueryClient:
    global _logs_client
    if _logs_client is None:
        _logs_client = LogsQueryClient(_get_credential())
    return _logs_client


def _get_sentinel_client() -> SecurityInsights:
    global _sentinel_client
    if _sentinel_client is None:
        _sentinel_client = SecurityInsights(_get_credential(), SUBSCRIPTION_ID)
    return _sentinel_client


# ---------------------------------------------------------------------------
# KQL safety check
# ---------------------------------------------------------------------------

_DANGEROUS_KQL = re.compile(
    r"\b(set\s+|\.set\b|\.drop\b|\.delete\b|\.purge\b|\.export\b|\.ingest\b)",
    re.IGNORECASE,
)


def _validate_kql(query: str) -> str | None:
    """Return an error string if the query looks unsafe, else None."""
    if _DANGEROUS_KQL.search(query):
        return "Query contains write/management operations — only read queries are permitted."
    if KQL_TABLE_ALLOWLIST:
        first_table = re.match(r"^\s*(\w+)", query)
        if first_table and first_table.group(1) not in KQL_TABLE_ALLOWLIST:
            return (
                f"Table '{first_table.group(1)}' is not in the allowed list: "
                f"{', '.join(KQL_TABLE_ALLOWLIST)}"
            )
    return None


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def _run_kql_query(query: str, timespan_hours: int = 24) -> dict[str, Any]:
    """Execute a KQL query against the Sentinel Log Analytics workspace."""
    err = _validate_kql(query)
    if err:
        return {"error": err}

    from datetime import timedelta

    client = _get_logs_client()
    timespan = timedelta(hours=timespan_hours)

    try:
        response = client.query_workspace(
            workspace_id=WORKSPACE_ID,
            query=query,
            timespan=timespan,
        )
    except HttpResponseError as exc:
        return {"error": str(exc)}

    if response.status == LogsQueryStatus.PARTIAL:
        tables = response.partial_data
        warning = "Partial results returned."
    elif response.status == LogsQueryStatus.SUCCESS:
        tables = response.tables
        warning = None
    else:
        return {"error": "Query failed", "details": str(response.error)}

    results = []
    for table in tables:
        columns = [col.name for col in table.columns]
        for row in table.rows:
            results.append(dict(zip(columns, row)))

    return {
        "row_count": len(results),
        "columns": list(results[0].keys()) if results else [],
        "rows": results[:200],  # cap at 200 rows for token safety
        "warning": warning,
    }


def _get_failed_signins(
    lookback_hours: int = 1,
    min_failures: int = 5,
    upn_filter: str | None = None,
) -> dict[str, Any]:
    """
    DEMO TOOL: Detect brute-force / password spray from failed sign-in logs.
    Wraps the canonical KQL query from the slide deck.
    """
    upn_clause = f'| where UserPrincipalName =~ "{upn_filter}"' if upn_filter else ""
    query = f"""
SigninLogs
| where TimeGenerated > ago({lookback_hours}h)
| where ResultType != "0"
| where ResultType in ("50126", "50053", "50055", "50056")
{upn_clause}
| summarize
    FailedAttempts = count(),
    DistinctIPs    = dcount(IPAddress),
    Locations      = make_set(Location, 10),
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated),
    ErrorCodes     = make_set(ResultType, 5)
    by UserPrincipalName, IPAddress
| where FailedAttempts >= {min_failures}
| order by FailedAttempts desc
"""
    return _run_kql_query(query.strip(), timespan_hours=lookback_hours + 1)


def _get_incident_details(incident_id: str) -> dict[str, Any]:
    """Fetch a Sentinel incident with its entities and tactics."""
    client = _get_sentinel_client()

    try:
        incident = client.incidents.get(RESOURCE_GROUP, WORKSPACE_NAME, incident_id)
    except HttpResponseError as exc:
        return {"error": str(exc)}

    # Entities attached to the incident
    try:
        entities_page = client.incidents.list_entities(
            RESOURCE_GROUP, WORKSPACE_NAME, incident_id
        )
        entities = [
            {
                "kind": e.kind,
                "friendly_name": getattr(e, "friendly_name", None),
                "properties": (
                    {k: v for k, v in vars(e).items() if not k.startswith("_")}
                    if e else {}
                ),
            }
            for e in (entities_page.entities or [])
        ]
    except Exception:
        entities = []

    return {
        "incident_id": incident_id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "created_time": str(incident.created_time_utc),
        "last_modified": str(incident.last_modified_time_utc),
        "description": incident.description,
        "tactics": list(incident.tactics or []),
        "alert_count": incident.additional_data.alert_count if incident.additional_data else 0,
        "entities": entities,
        "labels": [lbl.label_name for lbl in (incident.labels or [])],
    }


def _search_entities(
    entity_value: str,
    entity_type: str = "Account",
    lookback_hours: int = 24,
) -> dict[str, Any]:
    """
    Search for an entity (account, IP, host) across log sources.
    Returns a cross-table timeline of events.
    """
    entity_type = entity_type.lower()

    if entity_type in ("account", "user", "upn"):
        query = f"""
let target = "{entity_value}";
let window = {lookback_hours}h;
union withsource=SourceTable
    (SigninLogs          | where TimeGenerated > ago(window) | where UserPrincipalName =~ target
     | project TimeGenerated, SourceTable, EventType="SignIn",
               Detail=strcat(ResultType, " from ", IPAddress, " (", Location, ")")),
    (AuditLogs           | where TimeGenerated > ago(window) | where InitiatedBy has target
     | project TimeGenerated, SourceTable, EventType="AuditEvent",
               Detail=strcat(OperationName, " on ", tostring(TargetResources[0].displayName))),
    (SecurityAlert       | where TimeGenerated > ago(window) | where Entities has target
     | project TimeGenerated, SourceTable, EventType="SecurityAlert",
               Detail=AlertName)
| order by TimeGenerated asc
"""
    elif entity_type in ("ip", "ipaddress"):
        query = f"""
let target = "{entity_value}";
let window = {lookback_hours}h;
union withsource=SourceTable
    (SigninLogs    | where TimeGenerated > ago(window) | where IPAddress == target
     | project TimeGenerated, SourceTable, EventType="SignIn",
               Detail=strcat(UserPrincipalName, " ResultType=", ResultType)),
    (SecurityAlert | where TimeGenerated > ago(window) | where Entities has target
     | project TimeGenerated, SourceTable, EventType="SecurityAlert",
               Detail=AlertName),
    (CommonSecurityLog | where TimeGenerated > ago(window)
     | where SourceIP == target or DestinationIP == target
     | project TimeGenerated, SourceTable, EventType="NetworkEvent",
               Detail=strcat(Activity, " ", SourceIP, "->", DestinationIP))
| order by TimeGenerated asc
"""
    else:
        return {"error": f"Unsupported entity_type '{entity_type}'. Use: account, ip, host"}

    return _run_kql_query(query.strip(), timespan_hours=lookback_hours + 1)


def _get_ueba_insights(user_upn: str, lookback_days: int = 7) -> dict[str, Any]:
    """Retrieve UEBA risk scores and behavior anomalies for a user."""
    query = f"""
BehaviorAnalytics
| where TimeGenerated > ago({lookback_days}d)
| where UserName =~ "{user_upn}" or UserPrincipalName =~ "{user_upn}"
| project
    TimeGenerated,
    ActivityType,
    ActionType,
    ActivityInsights,
    InvestigationPriority,
    DevicesInsights,
    UsersInsights,
    SourceIPLocation,
    SourceIPAddress,
    SourceDevice
| order by InvestigationPriority desc, TimeGenerated desc
"""
    result = _run_kql_query(query.strip(), timespan_hours=lookback_days * 24)

    # Also pull the UserPeerAnalytics score if available
    peer_query = f"""
UserPeerAnalytics
| where TimeGenerated > ago({lookback_days}d)
| where UserName =~ "{user_upn}" or UserPrincipalName =~ "{user_upn}"
| project TimeGenerated, UserName, Anomalies, Insights
| order by TimeGenerated desc
| take 10
"""
    peer_result = _run_kql_query(peer_query.strip(), timespan_hours=lookback_days * 24)

    return {
        "behavior_analytics": result,
        "peer_analytics": peer_result,
        "user": user_upn,
        "lookback_days": lookback_days,
    }


# ---------------------------------------------------------------------------
# MCP Server definition
# ---------------------------------------------------------------------------

server = Server("sentinel-mcp-server")

TOOLS = [
    Tool(
        name="run_kql_query",
        description=(
            "Execute a read-only KQL (Kusto Query Language) query against the "
            "Microsoft Sentinel Log Analytics workspace. Returns up to 200 rows. "
            "Use this for custom queries not covered by the specialized tools."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Valid KQL query. Must be read-only (no set/drop/delete/export).",
                },
                "timespan_hours": {
                    "type": "integer",
                    "description": "How far back to look in hours (default 24, max 720).",
                    "default": 24,
                },
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="get_failed_signins",
        description=(
            "Detect brute-force or password spray attacks by finding accounts with "
            "repeated sign-in failures. Queries SigninLogs for error codes "
            "50126 (bad password), 50053 (locked), 50055 (expired), 50056 (no password)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "lookback_hours": {
                    "type": "integer",
                    "description": "Time window to search (default 1 hour).",
                    "default": 1,
                },
                "min_failures": {
                    "type": "integer",
                    "description": "Minimum failed attempts to report (default 5).",
                    "default": 5,
                },
                "upn_filter": {
                    "type": "string",
                    "description": "Optional: filter to a specific user UPN.",
                },
            },
        },
    ),
    Tool(
        name="get_incident_details",
        description=(
            "Retrieve full details of a Microsoft Sentinel incident including "
            "title, severity, status, tactics, and all attached entities "
            "(accounts, IPs, hosts, URLs)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "The Sentinel incident ID (GUID or numeric ARM ID).",
                },
            },
            "required": ["incident_id"],
        },
    ),
    Tool(
        name="search_entities",
        description=(
            "Search for an entity (user account, IP address, or host) across "
            "multiple Sentinel log tables and build a cross-source timeline of events."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "entity_value": {
                    "type": "string",
                    "description": "The entity to search for (UPN, IP address, hostname).",
                },
                "entity_type": {
                    "type": "string",
                    "enum": ["account", "ip", "host"],
                    "description": "Type of entity.",
                    "default": "account",
                },
                "lookback_hours": {
                    "type": "integer",
                    "description": "How far back to search (default 24 hours).",
                    "default": 24,
                },
            },
            "required": ["entity_value"],
        },
    ),
    Tool(
        name="get_ueba_insights",
        description=(
            "Retrieve Microsoft Sentinel UEBA (User and Entity Behavior Analytics) "
            "risk insights for a specific user: anomalous behavior, investigation "
            "priority score, peer comparison, and device anomalies."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "user_upn": {
                    "type": "string",
                    "description": "The user's UPN (email address).",
                },
                "lookback_days": {
                    "type": "integer",
                    "description": "Days of UEBA history to retrieve (default 7).",
                    "default": 7,
                },
            },
            "required": ["user_upn"],
        },
    ),
]


@server.list_tools()
async def list_tools(request: ListToolsRequest) -> ListToolsResult:
    return ListToolsResult(tools=TOOLS)


@server.call_tool()
async def call_tool(request: CallToolRequest) -> CallToolResult:
    name = request.params.name
    args = request.params.arguments or {}

    try:
        if name == "run_kql_query":
            result = _run_kql_query(
                query=args["query"],
                timespan_hours=int(args.get("timespan_hours", 24)),
            )
        elif name == "get_failed_signins":
            result = _get_failed_signins(
                lookback_hours=int(args.get("lookback_hours", 1)),
                min_failures=int(args.get("min_failures", 5)),
                upn_filter=args.get("upn_filter"),
            )
        elif name == "get_incident_details":
            result = _get_incident_details(incident_id=args["incident_id"])
        elif name == "search_entities":
            result = _search_entities(
                entity_value=args["entity_value"],
                entity_type=args.get("entity_type", "account"),
                lookback_hours=int(args.get("lookback_hours", 24)),
            )
        elif name == "get_ueba_insights":
            result = _get_ueba_insights(
                user_upn=args["user_upn"],
                lookback_days=int(args.get("lookback_days", 7)),
            )
        else:
            result = {"error": f"Unknown tool: {name}"}
    except Exception as exc:
        result = {"error": type(exc).__name__, "message": str(exc)}

    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _main_stdio():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()

    if transport == "sse":
        # SSE transport for remote / Copilot for Security plugin use
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route
        import uvicorn

        sse_transport = SseServerTransport("/messages")

        async def handle_sse(request):
            async with sse_transport.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await server.run(
                    streams[0], streams[1], server.create_initialization_options()
                )

        app = Starlette(
            routes=[
                Route("/sse", endpoint=handle_sse),
                Mount("/messages", app=sse_transport.handle_post_message),
            ]
        )
        host = os.getenv("MCP_SSE_HOST", "0.0.0.0")
        port = int(os.getenv("MCP_SSE_PORT", "8080"))
        print(f"Starting SSE MCP server on {host}:{port}", file=sys.stderr)
        uvicorn.run(app, host=host, port=port)
    else:
        import asyncio
        print("Starting stdio MCP server...", file=sys.stderr)
        asyncio.run(_main_stdio())


if __name__ == "__main__":
    main()
