"""
replay_mcp_server.py
====================
An offline stand-in for the hosted Microsoft Sentinel MCP server.

Demo 2, Mission 1 - "Ask like an analyst"
Session:    Empowering SOC Teams
Conference: MMS Midway 2026 (San Diego)

Why this exists
---------------
Mission 1 on stage uses the real hosted MCP server at
https://sentinel.microsoft.com/mcp/data-exploration. That needs a tenant, a
data lake, admin consent, and working egress from the conference network.
Any one of those can be missing at 9am on a Tuesday.

This server exposes the same *tool names and shapes* over stdio, backed by
sample_tenant.json. Point Claude Desktop or Claude Code at it and the
conversation looks the same on the projector: the model discovers tools,
picks tables, runs queries, and correlates. Only the data is synthetic.

It is also the safest way to rehearse. Nothing here can touch a real tenant.

Usage
-----
    pip install -r requirements.txt
    python replay_mcp_server.py                 # stdio, for an MCP client

    python replay_mcp_server.py --self-test     # no client needed; exercises
                                                # every tool and prints results

Register it with Claude Code:

    claude mcp add sentinel-replay -- python /abs/path/replay_mcp_server.py

Tool surface
------------
Mirrors the Data Exploration collection closely enough for the demo:

    list_tables              what is in the workspace
    describe_table           columns and a sample row
    run_kql                  read-only query, restricted to the allow-list
    list_incidents           incidents, filterable by age/severity/status
    get_incident             one incident with its entities
    get_signin_activity      sign-ins for a user
    get_audit_activity       directory audit events for a user
    get_ueba_baseline        UEBA baseline and deviations for a user

Guardrails (slide 25), enforced here the same way you would enforce them
against the real server:

  * Read-only. There is no tool that writes anything.
  * Table allow-list. run_kql refuses tables outside ALLOWED_TABLES.
  * Row cap. No single call returns more than MAX_ROWS.
  * Data is never instructions. Free-text fields from the sample data are
    returned wrapped in an explicit untrusted-content marker so a well-built
    client can tell content apart from directives. Demo 4 tests this.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATA_PATH = Path(
    os.getenv("REPLAY_DATA", Path(__file__).parent / "sample_tenant.json")
).resolve()

MAX_ROWS = 200

ALLOWED_TABLES = {
    "SecurityIncident",
    "SecurityAlert",
    "SigninLogs",
    "AADNonInteractiveUserSignInLogs",
    "AuditLogs",
    "CloudAppEvents",
    "IdentityInfo",
    "BehaviorAnalytics",
    "DeviceLogonEvents",
}

# Anything that writes, exports, or reconfigures. The hosted server would
# reject these too; we reject them locally so the demo behaves identically.
DANGEROUS_KQL = re.compile(
    r"(?:^|\s|\.)(set|drop|delete|purge|export|ingest|alter|rename|append)\b",
    re.IGNORECASE,
)

UNTRUSTED_OPEN = "<untrusted-data source=\"tenant-record\">"
UNTRUSTED_CLOSE = "</untrusted-data>"

# Fields that hold free text an attacker could have written into.
FREE_TEXT_FIELDS = {"description", "title", "summary", "ResultDescription", "_note"}


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_tenant() -> dict[str, Any]:
    if not DATA_PATH.exists():
        raise SystemExit(f"Sample data not found: {DATA_PATH}")
    with DATA_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


TENANT = load_tenant()


def _strip_meta(obj: Any) -> Any:
    """Remove the underscore-prefixed authoring notes before returning data.

    Keeps _ground_truth out of the model's view - otherwise the demo answers
    itself and the correlation looks like magic instead of work.
    """
    if isinstance(obj, dict):
        return {k: _strip_meta(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [_strip_meta(v) for v in obj]
    return obj


def _wrap_untrusted(obj: Any) -> Any:
    """Mark free-text fields so a client can tell content from instructions.

    This is the concrete form of 'separate the instruction channel from the
    data channel' on slide 25. The marker is not magic - it works because the
    system prompt tells the model that anything inside it is content to be
    reported, never a directive to follow.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in FREE_TEXT_FIELDS and isinstance(v, str):
                out[k] = f"{UNTRUSTED_OPEN}{v}{UNTRUSTED_CLOSE}"
            else:
                out[k] = _wrap_untrusted(v)
        return out
    if isinstance(obj, list):
        return [_wrap_untrusted(v) for v in obj]
    return obj


def clean(obj: Any) -> Any:
    return _wrap_untrusted(_strip_meta(obj))


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _now() -> datetime:
    """'Now' is pinned to the sample data so age filters stay meaningful."""
    return _parse_ts(TENANT["tenant"]["as_of"])


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def tool_list_tables() -> dict[str, Any]:
    return {
        "workspace": TENANT["tenant"]["workspace"],
        "tenant": TENANT["tenant"]["display_name"],
        "as_of": TENANT["tenant"]["as_of"],
        "tables": TENANT["tables"],
        "note": "Row counts are workspace totals. Replay data holds a curated subset.",
    }


_TABLE_SOURCES: dict[str, str] = {
    "SecurityIncident": "incidents",
    "SigninLogs": "signin_logs",
    "AuditLogs": "audit_logs",
    "CloudAppEvents": "cloud_app_events",
    "IdentityInfo": "identity_info",
    "BehaviorAnalytics": "ueba",
}


def _table_rows(table: str) -> list[dict[str, Any]]:
    key = _TABLE_SOURCES.get(table)
    if key is None:
        return []
    return TENANT.get(key, [])


def tool_describe_table(table: str) -> dict[str, Any]:
    if table not in ALLOWED_TABLES:
        return {
            "error": f"Table '{table}' is not in the allow-list.",
            "allowed": sorted(ALLOWED_TABLES),
        }

    rows = _table_rows(table)
    if not rows:
        return {
            "table": table,
            "columns": [],
            "note": "No replay rows for this table. It exists in the workspace but is not part of the sample scenario.",
        }

    columns = sorted({k for row in rows for k in row if not k.startswith("_")})
    return {
        "table": table,
        "columns": columns,
        "replay_row_count": len(rows),
        "sample_row": clean(rows[0]),
    }


def tool_run_kql(query: str, timespan_hours: int = 24) -> dict[str, Any]:
    """Very small KQL evaluator.

    It is not a KQL engine and does not pretend to be. It resolves the source
    table, applies a time filter, and honours a handful of `where` predicates
    on equality and `contains`. That is enough for the queries the model
    writes during Mission 1, and it keeps the demo honest: the model still has
    to pick the right table and the right filter.
    """
    err = _validate_kql(query)
    if err:
        return {"error": err}

    match = re.match(r"^\s*(\w+)", query)
    if not match:
        return {"error": "Could not determine the source table from the query."}

    table = match.group(1)
    if table not in ALLOWED_TABLES:
        return {
            "error": f"Table '{table}' is not in the allow-list.",
            "allowed": sorted(ALLOWED_TABLES),
        }

    rows = [dict(r) for r in _table_rows(table)]

    # Time filter
    cutoff = _now() - timedelta(hours=min(max(timespan_hours, 1), 720))
    time_field = next(
        (f for f in ("TimeGenerated", "Timestamp", "created_time") if rows and f in rows[0]),
        None,
    )
    if time_field:
        rows = [r for r in rows if _parse_ts(r[time_field]) >= cutoff]

    # `where Field == "value"` / `where Field contains "value"`
    for field, op, value in re.findall(
        r"where\s+(\w+)\s*(==|=~|contains)\s*[\"']([^\"']+)[\"']", query, re.IGNORECASE
    ):
        if op == "contains":
            rows = [r for r in rows if value.lower() in str(r.get(field, "")).lower()]
        else:
            rows = [r for r in rows if str(r.get(field, "")).lower() == value.lower()]

    truncated = len(rows) > MAX_ROWS
    rows = rows[:MAX_ROWS]

    return {
        "table": table,
        "query": query,
        "timespan_hours": timespan_hours,
        "row_count": len(rows),
        "truncated": truncated,
        "rows": clean(rows),
    }


def _validate_kql(query: str) -> str | None:
    if DANGEROUS_KQL.search(query):
        return (
            "Rejected: query contains a write or management operation. "
            "This connection is read-only."
        )
    if len(query) > 8000:
        return "Rejected: query exceeds 8000 characters."
    return None


def tool_list_incidents(
    max_age_hours: int = 24,
    min_severity: str = "Low",
    status: str | None = None,
    unassigned_only: bool = False,
) -> dict[str, Any]:
    order = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
    floor = order.get(min_severity, 0)
    cutoff = _now() - timedelta(hours=max_age_hours)

    results = []
    for inc in TENANT["incidents"]:
        if _parse_ts(inc["created_time"]) < cutoff:
            continue
        if order.get(inc["severity"], 0) < floor:
            continue
        if status and inc["status"].lower() != status.lower():
            continue
        if unassigned_only and inc.get("owner"):
            continue
        results.append(inc)

    results.sort(key=lambda i: i["created_time"])
    return {
        "filters": {
            "max_age_hours": max_age_hours,
            "min_severity": min_severity,
            "status": status,
            "unassigned_only": unassigned_only,
        },
        "row_count": len(results),
        "incidents": clean(results),
    }


def tool_get_incident(incident_number: int) -> dict[str, Any]:
    for inc in TENANT["incidents"]:
        if inc["incident_number"] == incident_number:
            return {"incident": clean(inc)}
    return {"error": f"Incident {incident_number} not found."}


def tool_get_signin_activity(upn: str, lookback_hours: int = 24) -> dict[str, Any]:
    cutoff = _now() - timedelta(hours=lookback_hours)
    rows = [
        r
        for r in TENANT["signin_logs"]
        if r["UserPrincipalName"].lower() == upn.lower()
        and _parse_ts(r["TimeGenerated"]) >= cutoff
    ]
    rows.sort(key=lambda r: r["TimeGenerated"])

    findings = []
    for prev, cur in zip(rows, rows[1:]):
        if prev.get("Location") != cur.get("Location"):
            gap = (_parse_ts(cur["TimeGenerated"]) - _parse_ts(prev["TimeGenerated"])).total_seconds() / 60
            findings.append(
                {
                    "type": "location_change",
                    "at": cur["TimeGenerated"],
                    "from": f"{prev.get('City')}, {prev.get('Location')}",
                    "to": f"{cur.get('City')}, {cur.get('Location')}",
                    "minutes_between": round(gap, 1),
                    "from_asn": prev.get("AutonomousSystemNumber"),
                    "to_asn": cur.get("AutonomousSystemNumber"),
                }
            )

    return {
        "upn": upn,
        "lookback_hours": lookback_hours,
        "row_count": len(rows),
        "rows": clean(rows),
        "derived_findings": findings,
        "note": "derived_findings flags location changes only. Whether one is impossible travel or a VPN is a judgement call - check the ASN against asset inventory.",
    }


def tool_get_audit_activity(upn: str, lookback_hours: int = 24) -> dict[str, Any]:
    cutoff = _now() - timedelta(hours=lookback_hours)
    rows = [
        r
        for r in TENANT["audit_logs"]
        if r.get("InitiatedBy", "").lower() == upn.lower()
        and _parse_ts(r["TimeGenerated"]) >= cutoff
    ]
    rows.sort(key=lambda r: r["TimeGenerated"])
    return {
        "upn": upn,
        "lookback_hours": lookback_hours,
        "row_count": len(rows),
        "rows": clean(rows),
    }


def tool_get_ueba_baseline(upn: str) -> dict[str, Any]:
    for entry in TENANT["ueba"]:
        if entry["UserPrincipalName"].lower() == upn.lower():
            return {"baseline": clean(entry)}
    return {"error": f"No UEBA baseline for {upn}. The account may be too new to have one."}


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Graph tools (preview)
#
# These six use the REAL tool names and the REAL parameter names from the
# hosted data-exploration collection, unlike the stand-in names above. If you
# are reading this to learn the actual API surface, this section is accurate:
#
#   get_graph_context()
#   find_nodes(validNodeLabel, validNodeProperties, resultsLimit)
#   find_blastradius(sourceName)
#   find_walkable_paths(sourceName, targetName)
#   find_exposure_perimeter(targetName, minPathLength, maxPathLength, resultsCountLimit)
#   find_connected_nodes(sourceNodeLabel, sourceNodeProperties,
#                        targetNodeLabel, targetNodeProperties, resultsCountLimit)
#
# Two documented behaviours are reproduced on purpose because they bite on
# stage: identity lookups reject user principal names, and the graph tools are
# preview and metered separately from the rest of the collection.
# ---------------------------------------------------------------------------

GRAPH_PREVIEW_NOTE = (
    "Graph tools are in PREVIEW and bill against the Sentinel graph meter, "
    "separately from the data lake."
)


def _graph() -> dict[str, Any]:
    g = TENANT.get("graph")
    if not g:
        raise ValueError("No graph data in the sample tenant.")
    return g


def _reject_upn(value: str, parameter: str) -> None:
    """The hosted graph tools do not accept UPNs for identity lookups."""
    if "@" in value:
        raise ValueError(
            f"{parameter}={value!r} looks like a user principal name. Graph "
            "identity lookups do not accept UPNs - use the display name or the "
            "object ID. Try find_nodes(validNodeLabel='Identity') to list them."
        )


def _find_node(keywords: str, parameter: str) -> dict[str, Any]:
    """Match a node by keywords, the way the hosted tools describe it."""
    _reject_upn(keywords, parameter)
    needle = keywords.strip().lower()
    nodes = _graph()["nodes"]

    # Callers are told to put the type before the name ("user Jordan Doe"), so
    # strip a leading label word before matching.
    for node in nodes:
        if needle.startswith(node["label"].lower() + " "):
            needle = needle[len(node["label"]) + 1:].strip()
            break
    for alias in ("user ", "identity ", "app ", "group "):
        if needle.startswith(alias):
            needle = needle[len(alias):].strip()
            break

    exact = [n for n in nodes if n["name"].lower() == needle]
    if exact:
        return exact[0]
    partial = [n for n in nodes if needle and needle in n["name"].lower()]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        raise ValueError(
            f"{parameter}={keywords!r} matched {len(partial)} nodes: "
            + ", ".join(n["name"] for n in partial)
        )
    raise ValueError(
        f"{parameter}={keywords!r} matched no node in the graph. "
        "Use get_graph_context() for supported labels."
    )


def _edges_from(name: str) -> list[dict[str, Any]]:
    return [e for e in _graph()["edges"] if e["source"] == name]


def _walk(start: str, target: str | None = None,
          max_hops: int = 6) -> list[list[dict[str, Any]]]:
    """Depth-first path enumeration. Returns paths as lists of edges.

    Untraversable edges are included as a final hop so the caller can SEE the
    blocked path and say why, rather than silently pretending it is not there.
    That distinction is the whole point of the demo beat.
    """
    paths: list[list[dict[str, Any]]] = []

    def step(node: str, trail: list[dict[str, Any]], seen: set[str]) -> None:
        if len(trail) >= max_hops:
            return
        for edge in _edges_from(node):
            if edge["target"] in seen:
                continue
            extended = trail + [edge]
            if target is None or edge["target"] == target:
                paths.append(extended)
            # Recurse through blocked edges too. A path that is only blocked by
            # one hop still has to be SHOWN, with the reason, or the analyst
            # cannot tell "you cannot get there" from "I did not look".
            step(edge["target"], extended, seen | {edge["target"]})

    step(start, [], {start})
    return paths


def _path_view(path: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = [e for e in path if not e.get("traversable", True)]
    return {
        "hops": len(path),
        "route": " -> ".join([path[0]["source"]] + [e["target"] for e in path]),
        "edges": [
            {k: v for k, v in e.items() if not k.startswith("_") and k != "id"}
            for e in path
        ],
        "traversable": not blocked,
        "blocked_by": blocked[0]["blocked_by"] if blocked else None,
    }


def tool_get_graph_context() -> dict[str, Any]:
    ctx = dict(_graph()["context"])
    ctx["preview_note"] = GRAPH_PREVIEW_NOTE
    return ctx


def tool_find_nodes(validNodeLabel: str, validNodeProperties: str | None = None,
                    resultsLimit: int = 25) -> dict[str, Any]:
    labels = {n["label"] for n in _graph()["nodes"]}
    if validNodeLabel not in labels:
        raise ValueError(
            f"validNodeLabel={validNodeLabel!r} is not a label in this graph. "
            f"Supported: {', '.join(sorted(labels))}"
        )
    hits = [n for n in _graph()["nodes"] if n["label"] == validNodeLabel]

    if validNodeProperties:
        wanted = [p.strip() for p in validNodeProperties.split(",") if p.strip()]
        for prop in wanted:
            if "=" in prop:
                key, _, val = prop.partition("=")
                hits = [n for n in hits
                        if str(n.get(key.strip(), "")).lower() == val.strip().lower()]
            else:
                hits = [n for n in hits if prop in n]

    return clean({
        "preview": True,
        "label": validNodeLabel,
        "match_count": len(hits),
        "nodes": hits[:resultsLimit],
    })


def tool_find_blastradius(sourceName: str) -> dict[str, Any]:
    node = _find_node(sourceName, "sourceName")
    critical = set(_graph()["critical_assets"])
    paths = _walk(node["name"])

    reachable, blocked = [], []
    for path in paths:
        if path[-1]["target"] not in critical:
            continue
        view = _path_view(path)
        (reachable if view["traversable"] else blocked).append(view)

    # Non-critical but sensitive endpoints still belong in the answer.
    collateral = sorted({
        p[-1]["target"] for p in paths
        if p[-1]["target"] not in critical
        and all(e.get("traversable", True) for e in p)
    })

    recommendations = []
    oauth = [e for e in _graph()["edges"]
             if e["type"] == "HAS_OAUTH_GRANT_ON" and e.get("traversable", True)]
    if oauth:
        recommendations.append(
            "Revoke the OAuth grant before resetting the credential. "
            "offline_access refresh tokens are not tied to the password, so a "
            "reset on its own leaves this path open."
        )
    if blocked:
        recommendations.append(
            "Keep the blocked path blocked: confirm PIM activation still "
            "requires approval and MFA for FIN-SOX-Approvers."
        )
    recommendations.append(
        "Scope containment to the reachable critical assets above, not to "
        "every asset the account is nominally associated with."
    )

    return {
        "preview": True,
        "preview_note": GRAPH_PREVIEW_NOTE,
        "source": {"label": node["label"], "name": node["name"]},
        "critical_assets_reachable_now": sorted(
            {p["route"].split(" -> ")[-1] for p in reachable}
        ),
        "paths_to_critical_assets": reachable,
        "paths_blocked": blocked,
        "other_reachable_nodes": collateral,
        "recommendations": recommendations,
    }


def tool_find_walkable_paths(sourceName: str, targetName: str) -> dict[str, Any]:
    src = _find_node(sourceName, "sourceName")
    dst = _find_node(targetName, "targetName")
    views = [_path_view(p) for p in _walk(src["name"], dst["name"])]
    return {
        "preview": True,
        "source": src["name"],
        "target": dst["name"],
        "path_count": len(views),
        "walkable_now": [v for v in views if v["traversable"]],
        "not_walkable": [v for v in views if not v["traversable"]],
    }


def tool_find_exposure_perimeter(targetName: str, minPathLength: int | None = None,
                                 maxPathLength: int | None = None,
                                 resultsCountLimit: int = 25) -> dict[str, Any]:
    dst = _find_node(targetName, "targetName")
    views: list[dict[str, Any]] = []
    for node in _graph()["nodes"]:
        if node["name"] == dst["name"]:
            continue
        for path in _walk(node["name"], dst["name"]):
            view = _path_view(path)
            if minPathLength is not None and view["hops"] < minPathLength:
                continue
            if maxPathLength is not None and view["hops"] > maxPathLength:
                continue
            view["entry_point"] = node["name"]
            view["entry_label"] = node["label"]
            views.append(view)

    views.sort(key=lambda v: (not v["traversable"], v["hops"]))
    walkable = [v for v in views if v["traversable"]]
    return {
        "preview": True,
        "target": {"label": dst["label"], "name": dst["name"],
                   "criticality": dst.get("criticality")},
        "incoming_path_count": len(views),
        "entry_points_now": sorted({v["entry_point"] for v in walkable}),
        "paths": views[:resultsCountLimit],
        "recommendation": (
            "Reduce the perimeter by cutting the shortest walkable path first - "
            "it is almost always a group membership, not a direct assignment."
        ),
    }


def tool_find_connected_nodes(sourceNodeLabel: str, targetNodeLabel: str,
                              sourceNodeProperties: str | None = None,
                              targetNodeProperties: str | None = None,
                              resultsCountLimit: int = 25) -> dict[str, Any]:
    sources = tool_find_nodes(sourceNodeLabel, sourceNodeProperties, 100)["nodes"]
    targets = {n["name"] for n in
               tool_find_nodes(targetNodeLabel, targetNodeProperties, 100)["nodes"]}

    views: list[dict[str, Any]] = []
    for src in sources:
        for path in _walk(src["name"]):
            if path[-1]["target"] not in targets:
                continue
            view = _path_view(path)
            view["from"] = src["name"]
            view["to"] = path[-1]["target"]
            views.append(view)

    views.sort(key=lambda v: (not v["traversable"], v["hops"]))
    return {
        "preview": True,
        "source_label": sourceNodeLabel,
        "target_label": targetNodeLabel,
        "path_count": len(views),
        "paths": views[:resultsCountLimit],
    }


TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_tables",
        "description": "List the tables available in the Sentinel workspace, with row counts.",
        "handler": tool_list_tables,
        "schema": {"type": "object", "properties": {}},
    },
    {
        "name": "describe_table",
        "description": "Return the column names and a sample row for one table.",
        "handler": tool_describe_table,
        "schema": {
            "type": "object",
            "properties": {"table": {"type": "string"}},
            "required": ["table"],
        },
    },
    {
        "name": "run_kql",
        "description": (
            "Run a read-only KQL query against the workspace. Write and management "
            "operations are rejected. Returns at most 200 rows."
        ),
        "handler": tool_run_kql,
        "schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Read-only KQL."},
                "timespan_hours": {"type": "integer", "default": 24},
            },
            "required": ["query"],
        },
    },
    {
        "name": "list_incidents",
        "description": "List incidents, filtered by age, minimum severity, status, and assignment.",
        "handler": tool_list_incidents,
        "schema": {
            "type": "object",
            "properties": {
                "max_age_hours": {"type": "integer", "default": 24},
                "min_severity": {
                    "type": "string",
                    "enum": ["Informational", "Low", "Medium", "High"],
                    "default": "Low",
                },
                "status": {"type": "string"},
                "unassigned_only": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "get_incident",
        "description": "Fetch one incident by number, including its entities and alert ids.",
        "handler": tool_get_incident,
        "schema": {
            "type": "object",
            "properties": {"incident_number": {"type": "integer"}},
            "required": ["incident_number"],
        },
    },
    {
        "name": "get_signin_activity",
        "description": (
            "Sign-in history for one user, with location changes surfaced as derived "
            "findings. Does not decide whether a change is malicious."
        ),
        "handler": tool_get_signin_activity,
        "schema": {
            "type": "object",
            "properties": {
                "upn": {"type": "string"},
                "lookback_hours": {"type": "integer", "default": 24},
            },
            "required": ["upn"],
        },
    },
    {
        "name": "get_audit_activity",
        "description": "Directory audit events initiated by one user - MFA registration, app consent, role changes.",
        "handler": tool_get_audit_activity,
        "schema": {
            "type": "object",
            "properties": {
                "upn": {"type": "string"},
                "lookback_hours": {"type": "integer", "default": 24},
            },
            "required": ["upn"],
        },
    },
    {
        "name": "get_ueba_baseline",
        "description": "UEBA baseline for one user - usual countries, ASNs, and apps, plus first-time flags.",
        "handler": tool_get_ueba_baseline,
        "schema": {
            "type": "object",
            "properties": {"upn": {"type": "string"}},
            "required": ["upn"],
        },
    },
    # --- Graph tools (preview) ------------------------------------------
    # Real names, real parameter names. See the implementations above.
    {
        "name": "get_graph_context",
        "description": (
            "PREVIEW. Return the labels, properties, and edge types this graph "
            "supports, plus the usage rules for the other graph tools."
        ),
        "handler": tool_get_graph_context,
        "schema": {"type": "object", "properties": {}},
    },
    {
        "name": "find_nodes",
        "description": (
            "PREVIEW. Find entities the graph represents as nodes, by label and "
            "optional properties."
        ),
        "handler": tool_find_nodes,
        "schema": {
            "type": "object",
            "properties": {
                "validNodeLabel": {"type": "string"},
                "validNodeProperties": {
                    "type": "string",
                    "description": "Comma-separated properties, e.g. 'criticality=Critical'.",
                },
                "resultsLimit": {"type": "integer", "default": 25},
            },
            "required": ["validNodeLabel"],
        },
    },
    {
        "name": "find_blastradius",
        "description": (
            "PREVIEW. Evaluate the blast radius of a node by exploring "
            "propagation paths toward critical assets. Identity lookups do not "
            "accept UPNs - use the display name."
        ),
        "handler": tool_find_blastradius,
        "schema": {
            "type": "object",
            "properties": {
                "sourceName": {
                    "type": "string",
                    "description": "Keywords matching a node. Not a UPN.",
                }
            },
            "required": ["sourceName"],
        },
    },
    {
        "name": "find_walkable_paths",
        "description": (
            "PREVIEW. Enumerate the connections between a source and a target "
            "and decide whether they can be traversed for lateral movement."
        ),
        "handler": tool_find_walkable_paths,
        "schema": {
            "type": "object",
            "properties": {
                "sourceName": {"type": "string"},
                "targetName": {"type": "string"},
            },
            "required": ["sourceName", "targetName"],
        },
    },
    {
        "name": "find_exposure_perimeter",
        "description": (
            "PREVIEW. List the incoming connections from other entities to the "
            "specified entity, to show the risk it faces."
        ),
        "handler": tool_find_exposure_perimeter,
        "schema": {
            "type": "object",
            "properties": {
                "targetName": {"type": "string"},
                "minPathLength": {"type": "integer"},
                "maxPathLength": {"type": "integer"},
                "resultsCountLimit": {"type": "integer", "default": 25},
            },
            "required": ["targetName"],
        },
    },
    {
        "name": "find_connected_nodes",
        "description": (
            "PREVIEW. List traversable paths between two sets of entities "
            "selected by label and properties rather than by name."
        ),
        "handler": tool_find_connected_nodes,
        "schema": {
            "type": "object",
            "properties": {
                "sourceNodeLabel": {"type": "string"},
                "sourceNodeProperties": {"type": "string"},
                "targetNodeLabel": {"type": "string"},
                "targetNodeProperties": {"type": "string"},
                "resultsCountLimit": {"type": "integer", "default": 25},
            },
            "required": ["sourceNodeLabel", "targetNodeLabel"],
        },
    },
]

TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Dispatch a tool call. Used by the MCP server and by --self-test."""
    tool = TOOLS_BY_NAME.get(name)
    if tool is None:
        return {"error": f"Unknown tool '{name}'. Available: {', '.join(TOOLS_BY_NAME)}"}
    try:
        return tool["handler"](**(arguments or {}))
    except TypeError as exc:
        return {"error": f"Bad arguments for {name}: {exc}"}
    except ValueError as exc:
        # Graph tools raise these for UPN lookups and unknown labels. They are
        # expected, actionable errors - hand them back rather than crashing.
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------


async def serve_stdio() -> None:
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import TextContent, Tool
    except ImportError:
        raise SystemExit(
            "The 'mcp' package is not installed.\n"
            "  pip install -r requirements.txt\n"
            "Or run without a client:  python replay_mcp_server.py --self-test"
        )

    server = Server("sentinel-replay")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(name=t["name"], description=t["description"], inputSchema=t["schema"])
            for t in TOOLS
        ]

    @server.call_tool()
    async def handle_call(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        result = call_tool(name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


# ---------------------------------------------------------------------------
# Self-test - proves the tools work without an MCP client attached
# ---------------------------------------------------------------------------


def self_test() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        checks.append((label, ok, detail))

    tables = tool_list_tables()
    check("list_tables returns the workspace", len(tables["tables"]) == 9, f"{len(tables['tables'])} tables")

    desc = tool_describe_table("SigninLogs")
    check("describe_table SigninLogs", "UserPrincipalName" in desc["columns"], f"{len(desc['columns'])} columns")

    denied = tool_describe_table("Nonexistent")
    check("describe_table rejects unknown table", "error" in denied)

    recent = tool_list_incidents(max_age_hours=24, min_severity="Medium", unassigned_only=True)
    numbers = [i["incident_number"] for i in recent["incidents"]]
    check(
        "list_incidents filters age/severity/assignment",
        48213 in numbers and 48198 not in numbers and 48187 not in numbers,
        f"returned {numbers}",
    )

    signins = tool_get_signin_activity("j.doe@contoso.com")
    travel = [f for f in signins["derived_findings"] if f["type"] == "location_change"]
    check(
        "get_signin_activity surfaces the Columbus -> Nairobi jump",
        any(f["to"].endswith("KE") and f["minutes_between"] < 60 for f in travel),
        f"{len(travel)} location change(s)",
    )

    audit = tool_get_audit_activity("j.doe@contoso.com")
    ops = [r["OperationName"] for r in audit["rows"]]
    check(
        "get_audit_activity finds MFA registration and consent",
        any("security info" in o for o in ops) and any("Consent" in o for o in ops),
        str(ops),
    )

    baseline = tool_get_ueba_baseline("j.doe@contoso.com")
    check("get_ueba_baseline flags first-time country", baseline["baseline"]["FirstTimeCountry"] is True)

    benign = tool_get_ueba_baseline("m.okafor@contoso.com")
    check(
        "benign user's baseline already contains IE",
        "IE" in benign["baseline"]["UsualCountries"],
        "this is what kills the false positive",
    )

    kql = tool_run_kql('SigninLogs | where Location == "KE"', timespan_hours=24)
    check("run_kql executes a filtered read", kql["row_count"] == 2, f"{kql['row_count']} rows")

    blocked = tool_run_kql(".drop table SigninLogs")
    check("run_kql rejects write operations", "error" in blocked, blocked.get("error", "")[:60])

    off_list = tool_run_kql("Usage | take 10")
    check("run_kql enforces the table allow-list", "error" in off_list)

    injected = tool_get_incident(48176)
    desc_field = injected["incident"]["description"]
    check(
        "free text is returned inside an untrusted-data marker",
        desc_field.startswith(UNTRUSTED_OPEN) and desc_field.endswith(UNTRUSTED_CLOSE),
        "see ../04-guardrails-injection-test/",
    )

    leaked = json.dumps(injected)
    check("authoring notes are stripped from tool output", "_ground_truth" not in leaked)

    # --- graph tools (preview) ------------------------------------------

    ctx = tool_get_graph_context()
    check(
        "get_graph_context advertises labels and the UPN rule",
        "Identity" in ctx["node_labels"]
        and any("principal name" in n for n in ctx["usage_notes"]),
        f"{len(ctx['node_labels'])} labels",
    )

    upn_attempt = call_tool("find_blastradius", {"sourceName": "j.doe@contoso.com"})
    check(
        "graph identity lookup rejects a UPN, as the hosted tools do",
        "error" in upn_attempt and "principal name" in upn_attempt["error"],
    )

    blast = tool_find_blastradius("user Jordan Doe")
    check(
        "find_blastradius reaches both SOX crown jewels",
        blast["critical_assets_reachable_now"]
        == ["sql-sox-reporting-01", "stcontosofinarchive"],
        ", ".join(blast["critical_assets_reachable_now"]),
    )
    check(
        "find_blastradius excludes the PIM-gated key vault from the live radius",
        "kv-contoso-fin-prod" not in blast["critical_assets_reachable_now"],
    )
    check(
        "find_blastradius still SHOWS the blocked path, with the reason",
        len(blast["paths_blocked"]) == 1
        and "kv-contoso-fin-prod" in blast["paths_blocked"][0]["route"]
        and "PIM" in blast["paths_blocked"][0]["blocked_by"],
    )
    check(
        "find_blastradius leads with revoking the grant, not resetting the password",
        "evoke" in blast["recommendations"][0]
        and "offline_access" in blast["recommendations"][0],
    )

    vault = tool_find_walkable_paths("Jordan Doe", "kv-contoso-fin-prod")
    check(
        "find_walkable_paths marks the key vault unreachable right now",
        not vault["walkable_now"] and len(vault["not_walkable"]) == 1,
        f"{len(vault['walkable_now'])} walkable",
    )

    mailbox = tool_find_exposure_perimeter("Jordan Doe mailbox")
    check(
        "find_exposure_perimeter finds BOTH doors into the mailbox",
        mailbox["entry_points_now"] == ["Contoso Doc Sync", "Jordan Doe"],
        ", ".join(mailbox["entry_points_now"]),
    )

    criticals = tool_find_nodes("StorageAccount", "criticality=Critical")
    check(
        "find_nodes filters on a property",
        criticals["match_count"] == 1
        and criticals["nodes"][0]["name"] == "stcontosofinarchive",
    )

    bad_label = call_tool("find_nodes", {"validNodeLabel": "Mainframe"})
    check("find_nodes rejects an unsupported label", "error" in bad_label)

    id_to_vault = tool_find_connected_nodes("Identity", "KeyVault")
    check(
        "find_connected_nodes selects by label, not by name",
        id_to_vault["path_count"] == 1
        and id_to_vault["paths"][0]["traversable"] is False,
    )

    graph_leak = json.dumps([blast, mailbox, vault, criticals])
    check(
        "graph output carries no authoring notes",
        '"_note"' not in graph_leak and "_ground_truth" not in graph_leak,
    )


    print()
    print("replay_mcp_server self-test")
    print("-" * 68)
    failed = 0
    for label, ok, detail in checks:
        mark = "ok  " if ok else "FAIL"
        if not ok:
            failed += 1
        suffix = f"   ({detail})" if detail else ""
        print(f"  [{mark}] {label}{suffix}")
    print("-" * 68)
    print(f"  {len(checks) - failed}/{len(checks)} passed")
    print()
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[2])
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Exercise every tool and print results. No MCP client needed.",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    asyncio.run(serve_stdio())
    return 0


if __name__ == "__main__":
    sys.exit(main())
