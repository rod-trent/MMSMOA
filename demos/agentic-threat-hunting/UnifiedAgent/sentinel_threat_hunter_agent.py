"""
sentinel_threat_hunter_agent.py
================================
Autonomous Threat Hunting Agent for Microsoft Sentinel

This agent ties together all three demo capabilities:
  1. MCP Server connectivity (Sentinel tools)
  2. Natural Language Threat Hunting (AI-driven investigation)
  3. Graph Investigation & Report Generation (visual attack chain)

The agent operates as a full agentic loop:
  - Accepts an incident ID or natural language prompt
  - Autonomously calls Sentinel MCP tools to gather evidence
  - Builds an entity relationship graph
  - Maps events to MITRE ATT&CK
  - Generates a comprehensive HTML investigation report
  - Provides a verdict and recommended response actions

Demo: "Putting It All Together — The Autonomous Agent"
Session: Agentic Threat Hunting with Microsoft Sentinel
Conference: MMS MOA 2026

Usage:
    python sentinel_threat_hunter_agent.py --replay                  # Offline demo
    python sentinel_threat_hunter_agent.py --incident-id INC-2847    # Live mode
    python sentinel_threat_hunter_agent.py --prompt "Investigate jsmith@contoso.com"
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BLUE   = "\033[94m"
MAGENTA = "\033[95m"

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def banner(text: str) -> None:
    width = 72
    print(f"\n{BOLD}{CYAN}{'═' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * width}{RESET}\n")


def section(text: str) -> None:
    print(f"\n{BOLD}{BLUE}── {text} {'─' * (60 - len(text))}{RESET}\n")


def agent_says(text: str, delay: float = 0.012) -> None:
    """Simulate the agent 'thinking' and typing."""
    sys.stdout.write(f"  {MAGENTA}🤖 Agent:{RESET} ")
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def tool_call(name: str, args: dict) -> None:
    print(f"  {YELLOW}⚡ MCP Tool Call:{RESET} {BOLD}{name}{RESET}")
    for k, v in args.items():
        display_val = v if len(str(v)) < 80 else str(v)[:77] + "..."
        print(f"  {GRAY}   {k}: {display_val}{RESET}")
    print()


def tool_result(data: dict, max_rows: int = 3) -> None:
    if "error" in data:
        print(f"  {RED}✗ Error: {data['error']}{RESET}\n")
        return
    if "rows" in data:
        print(f"  {GREEN}✓ {data.get('row_count', len(data['rows']))} row(s) returned{RESET}")
        for row in data["rows"][:max_rows]:
            summary = " | ".join(f"{k}: {v}" for k, v in list(row.items())[:4])
            print(f"  {GRAY}    → {summary}{RESET}")
        if data.get("row_count", 0) > max_rows:
            print(f"  {GRAY}    ... and {data['row_count'] - max_rows} more{RESET}")
    print()


def verdict_display(verdict: str, confidence: str, is_true_positive: bool) -> None:
    color = RED if is_true_positive else GREEN
    icon = "🚨" if is_true_positive else "✓"
    print(f"\n  {BOLD}{color}{icon} VERDICT: {verdict}{RESET}")
    print(f"  {BOLD}   Confidence: {confidence}{RESET}\n")


def pause(seconds: float = 0.8) -> None:
    time.sleep(seconds)


# ---------------------------------------------------------------------------
# Agent State — tracks the investigation as it proceeds
# ---------------------------------------------------------------------------

class InvestigationState:
    """Holds all evidence collected during the agent's investigation."""

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self.incident: dict = {}
        self.failed_signins: dict = {}
        self.entity_timeline: dict = {}
        self.ueba_insights: dict = {}
        self.entities: list[dict] = []
        self.graph_edges: list[tuple[str, str, str]] = []
        self.mitre_techniques: list[str] = []
        self.attack_phases: list[dict] = []
        self.verdict: str = ""
        self.confidence: str = ""
        self.is_true_positive: bool = False
        self.recommended_actions: list[tuple[str, str]] = []
        self.start_time = datetime.now(timezone.utc)

    @property
    def elapsed_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()


# ---------------------------------------------------------------------------
# Agent Reasoning Engine — decides what to do next
# ---------------------------------------------------------------------------

AGENT_PLAN = [
    {
        "step": "gather_incident",
        "description": "Pull full incident details from Sentinel",
        "tool": "get_incident_details",
        "reasoning": "I need to understand the incident scope, severity, and attached entities before I can plan the investigation.",
    },
    {
        "step": "check_signins",
        "description": "Analyze sign-in failure patterns around the incident",
        "tool": "get_failed_signins",
        "reasoning": "Failed sign-in bursts before a successful auth are the hallmark of credential attacks. Let me check.",
    },
    {
        "step": "build_timeline",
        "description": "Build entity timeline for the compromised account",
        "tool": "search_entities",
        "reasoning": "Now I'll trace what the attacker did post-compromise by building a cross-table event timeline.",
    },
    {
        "step": "ueba_analysis",
        "description": "Check UEBA risk profile and behavioral anomalies",
        "tool": "get_ueba_insights",
        "reasoning": "UEBA detects deviations from normal behavior — this will tell me how anomalous the activity truly is.",
    },
    {
        "step": "graph_construction",
        "description": "Construct investigation graph and map MITRE ATT&CK",
        "tool": None,
        "reasoning": "I have enough evidence. Let me reconstruct the attack graph, map techniques to MITRE, and determine the verdict.",
    },
    {
        "step": "report_generation",
        "description": "Generate investigation report with recommendations",
        "tool": None,
        "reasoning": "Time to synthesize everything into a clear report with response actions.",
    },
]


# ---------------------------------------------------------------------------
# Replay data loader (offline demo mode)
# ---------------------------------------------------------------------------

def load_replay_data() -> dict:
    """Load sample data for offline demo from sibling demo folders."""
    sample_file = Path(__file__).parent.parent / "02-natural-language-hunt" / "sample_incident.json"
    if sample_file.exists():
        with open(sample_file) as f:
            return json.load(f)

    # Fallback inline minimal data if file not found
    return _get_fallback_data()


def _get_fallback_data() -> dict:
    """Minimal inline data so the demo works even without sample files."""
    return {
        "incident": {
            "incident_id": "INC-2847",
            "title": "Suspicious Sign-in Activity - Multiple Failed Attempts Followed by Success",
            "severity": "High",
            "status": "New",
            "created_time": "2026-04-27T01:47:33Z",
            "description": "Password spray attack followed by account compromise.",
            "tactics": ["CredentialAccess", "InitialAccess"],
            "alert_count": 3,
            "entities": [
                {"kind": "Account", "friendly_name": "jsmith@contoso.com"},
                {"kind": "Ip", "friendly_name": "185.220.101.45"},
                {"kind": "Host", "friendly_name": "DESKTOP-CORP-114"},
            ],
            "labels": [],
        },
        "failed_signins": {
            "row_count": 3,
            "rows": [
                {"UserPrincipalName": "jsmith@contoso.com", "IPAddress": "185.220.101.45", "FailedAttempts": 47, "DistinctIPs": 1, "Locations": ["Netherlands"], "FirstSeen": "2026-04-27T01:47:33Z", "LastSeen": "2026-04-27T01:59:12Z", "ErrorCodes": ["50126"]},
                {"UserPrincipalName": "agarcia@contoso.com", "IPAddress": "185.220.101.45", "FailedAttempts": 12, "DistinctIPs": 1, "Locations": ["Netherlands"], "FirstSeen": "2026-04-27T01:48:01Z", "LastSeen": "2026-04-27T01:55:44Z", "ErrorCodes": ["50126"]},
                {"UserPrincipalName": "mwilliams@contoso.com", "IPAddress": "185.220.101.45", "FailedAttempts": 8, "DistinctIPs": 1, "Locations": ["Netherlands"], "FirstSeen": "2026-04-27T01:48:22Z", "LastSeen": "2026-04-27T01:54:01Z", "ErrorCodes": ["50126"]},
            ],
        },
        "entity_timeline": {
            "row_count": 8,
            "rows": [
                {"TimeGenerated": "2026-04-27T01:47:33Z", "SourceTable": "SigninLogs", "EventType": "SignIn", "Detail": "50126 from 185.220.101.45 (Netherlands)"},
                {"TimeGenerated": "2026-04-27T01:59:12Z", "SourceTable": "SigninLogs", "EventType": "SignIn", "Detail": "0 from 185.220.101.45 (Netherlands) — SUCCESS"},
                {"TimeGenerated": "2026-04-27T02:02:44Z", "SourceTable": "AuditLogs", "EventType": "AuditEvent", "Detail": "Update user on jsmith@contoso.com"},
                {"TimeGenerated": "2026-04-27T02:03:18Z", "SourceTable": "AuditLogs", "EventType": "AuditEvent", "Detail": "Add app role assignment on Microsoft Graph connector"},
                {"TimeGenerated": "2026-04-27T02:04:55Z", "SourceTable": "AuditLogs", "EventType": "AuditEvent", "Detail": "Add registered owner to ServicePrincipal"},
                {"TimeGenerated": "2026-04-27T02:07:33Z", "SourceTable": "SecurityAlert", "EventType": "SecurityAlert", "Detail": "Mass download activity detected"},
                {"TimeGenerated": "2026-04-27T02:11:02Z", "SourceTable": "SecurityAlert", "EventType": "SecurityAlert", "Detail": "Anomalous OAuth app registered"},
                {"TimeGenerated": "2026-04-27T02:14:19Z", "SourceTable": "AuditLogs", "EventType": "AuditEvent", "Detail": "Add member to role: Global Administrator"},
            ],
        },
        "ueba_insights": {
            "behavior_analytics": {
                "row_count": 4,
                "rows": [
                    {"TimeGenerated": "2026-04-27T02:00:00Z", "ActivityType": "LogOn", "ActionType": "InteractiveLogon", "InvestigationPriority": 9, "ActivityInsights": "First logon from this country in 90 days", "SourceIPLocation": "Netherlands", "SourceIPAddress": "185.220.101.45"},
                    {"TimeGenerated": "2026-04-27T02:03:00Z", "ActivityType": "ResourceAccess", "ActionType": "FileDownload", "InvestigationPriority": 8, "ActivityInsights": "Downloaded 14x more files than peer average", "SourceIPLocation": "Netherlands", "SourceIPAddress": "185.220.101.45"},
                    {"TimeGenerated": "2026-04-27T02:07:00Z", "ActivityType": "AppConsent", "ActionType": "OAuthAppConsent", "InvestigationPriority": 10, "ActivityInsights": "First OAuth app registration for this user", "SourceIPLocation": "Netherlands", "SourceIPAddress": "185.220.101.45"},
                    {"TimeGenerated": "2026-04-27T02:14:00Z", "ActivityType": "PrivilegeEscalation", "ActionType": "AddMemberToRole", "InvestigationPriority": 10, "ActivityInsights": "Role assignment to Global Admin — extremely rare", "SourceIPLocation": "Netherlands", "SourceIPAddress": "185.220.101.45"},
                ],
            }
        },
    }


# ---------------------------------------------------------------------------
# Agent Steps — each step implements one phase of the investigation
# ---------------------------------------------------------------------------

def step_gather_incident(state: InvestigationState, data: dict) -> None:
    """Step 1: Pull incident details."""
    section("STEP 1: Gathering Incident Details")
    agent_says(AGENT_PLAN[0]["reasoning"])
    pause()

    tool_call("get_incident_details", {"incident_id": state.incident_id})
    state.incident = data["incident"]
    tool_result({"rows": state.incident["entities"], "row_count": len(state.incident["entities"])})

    # Agent interprets
    entities_str = ", ".join(e["friendly_name"] for e in state.incident["entities"])
    agent_says(
        f"Incident {state.incident['incident_id']}: {state.incident['title']}. "
        f"Severity: {state.incident['severity']}. "
        f"Entities: {entities_str}. Tactics: {', '.join(state.incident['tactics'])}."
    )
    pause()


def step_check_signins(state: InvestigationState, data: dict) -> None:
    """Step 2: Analyze sign-in failures."""
    section("STEP 2: Analyzing Sign-In Patterns")
    agent_says(AGENT_PLAN[1]["reasoning"])
    pause()

    tool_call("get_failed_signins", {"lookback_hours": 1, "min_failures": 5})
    state.failed_signins = data["failed_signins"]
    tool_result(state.failed_signins)

    top = state.failed_signins["rows"][0]
    agent_says(
        f"Confirmed password spray: {top['FailedAttempts']} failures for "
        f"{top['UserPrincipalName']} from {top['IPAddress']} ({top['Locations'][0]}). "
        f"{state.failed_signins['row_count']} accounts targeted from the same IP — "
        f"this is a coordinated attack."
    )
    pause()


def step_build_timeline(state: InvestigationState, data: dict) -> None:
    """Step 3: Build entity timeline."""
    section("STEP 3: Building Entity Timeline")
    agent_says(AGENT_PLAN[2]["reasoning"])
    pause()

    pivot_entity = state.failed_signins["rows"][0]["UserPrincipalName"]
    tool_call("search_entities", {
        "entity_value": pivot_entity,
        "entity_type": "account",
        "lookback_hours": 2,
    })
    state.entity_timeline = data["entity_timeline"]
    tool_result(state.entity_timeline, max_rows=4)

    # Identify post-compromise events
    post_events = [r for r in state.entity_timeline["rows"]
                   if r["EventType"] in ("AuditEvent", "SecurityAlert")]
    agent_says(
        f"CRITICAL FINDING: {len(post_events)} post-authentication events detected. "
        f"The attacker modified the account, registered an OAuth app, triggered "
        f"security alerts, and escalated privileges — all within 15 minutes."
    )

    # Display critical events
    for evt in post_events:
        icon = "🚨" if evt["EventType"] == "SecurityAlert" else "📋"
        print(f"  {RED}  {icon} [{evt['TimeGenerated'][11:19]}] {evt['Detail']}{RESET}")
    print()
    pause()


def step_ueba_analysis(state: InvestigationState, data: dict) -> None:
    """Step 4: UEBA risk profiling."""
    section("STEP 4: UEBA Behavioral Analysis")
    agent_says(AGENT_PLAN[3]["reasoning"])
    pause()

    pivot_entity = state.failed_signins["rows"][0]["UserPrincipalName"]
    tool_call("get_ueba_insights", {"user_upn": pivot_entity, "lookback_days": 7})
    state.ueba_insights = data["ueba_insights"]

    ba_rows = state.ueba_insights["behavior_analytics"]["rows"]
    print(f"  {GREEN}✓ {len(ba_rows)} behavioral anomalies detected{RESET}")
    for row in ba_rows:
        priority = row["InvestigationPriority"]
        color = RED if priority >= 9 else YELLOW
        print(f"  {color}  [{priority}/10] {row['ActivityInsights']}{RESET}")
    print()

    max_priority = max(r["InvestigationPriority"] for r in ba_rows)
    agent_says(
        f"UEBA confirms extreme anomaly: maximum investigation priority {max_priority}/10. "
        f"Every single action in this session has no historical precedent for this user. "
        f"This is definitively not normal behavior."
    )
    pause()


def step_graph_construction(state: InvestigationState) -> None:
    """Step 5: Build investigation graph and MITRE mapping."""
    section("STEP 5: Constructing Investigation Graph")
    agent_says(AGENT_PLAN[4]["reasoning"])
    pause()

    # Build entities
    state.entities = [
        {"type": "account", "name": "jsmith@contoso.com", "risk": "CRITICAL", "role": "Pivot Entity"},
        {"type": "account", "name": "agarcia@contoso.com", "risk": "MEDIUM", "role": "Spray Target"},
        {"type": "account", "name": "mwilliams@contoso.com", "risk": "LOW", "role": "Spray Target"},
        {"type": "ip", "name": "185.220.101.45", "risk": "CRITICAL", "role": "Tor Exit Node (NL)"},
        {"type": "app", "name": "GraphExplorer-Sync", "risk": "CRITICAL", "role": "Malicious OAuth App"},
        {"type": "role", "name": "Global Administrator", "risk": "CRITICAL", "role": "Escalation Target"},
    ]

    # Build graph edges
    state.graph_edges = [
        ("185.220.101.45", "jsmith@contoso.com", "password spray → success"),
        ("185.220.101.45", "agarcia@contoso.com", "password spray → failed"),
        ("185.220.101.45", "mwilliams@contoso.com", "password spray → failed"),
        ("jsmith@contoso.com", "GraphExplorer-Sync", "registered OAuth app"),
        ("GraphExplorer-Sync", "Mail.Read", "granted permission"),
        ("GraphExplorer-Sync", "Files.ReadWrite.All", "granted permission"),
        ("jsmith@contoso.com", "Global Administrator", "added to role"),
        ("GraphExplorer-Sync", "External OneDrive", "exfiltrated 47 MB"),
    ]

    # MITRE ATT&CK mapping
    state.mitre_techniques = [
        "T1110.003 — Password Spraying",
        "T1078     — Valid Accounts",
        "T1098     — Account Manipulation",
        "T1137     — Office Application Startup (OAuth Persistence)",
        "T1098.001 — Additional Cloud Credentials",
        "T1213.002 — SharePoint Collection",
        "T1114.002 — Remote Email Collection",
        "T1078.004 — Cloud Accounts (Privilege Escalation)",
        "T1567.002 — Exfiltration to Cloud Storage",
    ]

    # Attack phases
    state.attack_phases = [
        {"time": "01:47:33", "phase": "RECON", "event": "Password spray begins — 67 attempts across 3 accounts from Tor IP"},
        {"time": "01:59:12", "phase": "INITIAL ACCESS", "event": "✗ BREACH: jsmith@contoso.com compromised via password spray"},
        {"time": "02:00:44", "phase": "INITIAL ACCESS", "event": "UEBA: First logon from Netherlands — InvestigationPriority 9/10"},
        {"time": "02:02:44", "phase": "PERSISTENCE", "event": "Account profile modified (alternate email added for persistence)"},
        {"time": "02:03:18", "phase": "PERSISTENCE", "event": "✗ Malicious OAuth app 'GraphExplorer-Sync' registered with admin consent"},
        {"time": "02:04:55", "phase": "PERSISTENCE", "event": "Attacker added as Service Principal owner — persistent API access"},
        {"time": "02:07:33", "phase": "COLLECTION", "event": "✗ Mass download: 847 files from SharePoint (14x peer average)"},
        {"time": "02:11:02", "phase": "COLLECTION", "event": "OAuth app accessing Exchange mailbox via Graph API"},
        {"time": "02:14:19", "phase": "PRIVILEGE ESCALATION", "event": "✗✗ jsmith added to Global Administrator role"},
        {"time": "02:19:07", "phase": "EXFILTRATION", "event": "✗ 47 MB uploaded to external OneDrive via OAuth app token"},
    ]

    # Display the graph
    print(f"  {BOLD}Entity Relationship Graph:{RESET}")
    for entity in state.entities:
        risk_color = RED if entity["risk"] == "CRITICAL" else (YELLOW if entity["risk"] == "MEDIUM" else GREEN)
        icon = {"account": "👤", "ip": "🌐", "app": "🔑", "role": "👑"}.get(entity["type"], "•")
        print(f"  {risk_color}  {icon} {entity['name']}  [{entity['risk']}] — {entity['role']}{RESET}")

    print(f"\n  {BOLD}Edges:{RESET}")
    for src, dst, rel in state.graph_edges:
        print(f"  {GRAY}    {src}  —[{rel}]→  {dst}{RESET}")

    print(f"\n  {BOLD}MITRE ATT&CK Techniques ({len(state.mitre_techniques)}):{RESET}")
    for tech in state.mitre_techniques:
        print(f"  {YELLOW}    • {tech}{RESET}")
    print()
    pause()


def step_generate_verdict(state: InvestigationState) -> None:
    """Step 6: Synthesize verdict and generate report."""
    section("STEP 6: Synthesizing Verdict & Generating Report")
    agent_says(AGENT_PLAN[5]["reasoning"])
    pause()

    # Determine verdict
    state.is_true_positive = True
    state.verdict = "CONFIRMED COMPROMISE — TRUE POSITIVE"
    state.confidence = "HIGH (5 independent corroborating signals)"
    state.recommended_actions = [
        ("IMMEDIATE", "Revoke all active sessions for jsmith@contoso.com"),
        ("IMMEDIATE", "Remove jsmith from Global Administrator role"),
        ("IMMEDIATE", "Revoke and delete OAuth app 'GraphExplorer-Sync'"),
        ("IMMEDIATE", "Block IP 185.220.101.45 at Conditional Access + firewall"),
        ("URGENT", "Audit 847 downloaded files — identify sensitive data exposure"),
        ("URGENT", "Investigate 47 MB external upload destination and content"),
        ("URGENT", "Force password reset for jsmith, agarcia, mwilliams"),
        ("URGENT", "Check if OAuth app token was used for additional lateral movement"),
        ("FOLLOW-UP", "Enable Conditional Access: block Tor/anonymous proxy access"),
        ("FOLLOW-UP", "Restrict OAuth app consent to admin-approved apps only"),
        ("FOLLOW-UP", "Enable Privileged Identity Management for all admin roles"),
        ("FOLLOW-UP", "Deploy token protection / continuous access evaluation"),
    ]

    # Display verdict
    verdict_display(state.verdict, state.confidence, state.is_true_positive)

    # Display timeline
    print(f"  {BOLD}Reconstructed Attack Timeline:{RESET}")
    for phase in state.attack_phases:
        is_critical = "✗" in phase["event"]
        color = RED if is_critical else GRAY
        print(f"  {color}  [{phase['time']}] {phase['phase']:20s} {phase['event']}{RESET}")
    print()

    # Display actions
    print(f"  {BOLD}Recommended Response Actions:{RESET}")
    for priority, action in state.recommended_actions:
        color = RED if priority == "IMMEDIATE" else (YELLOW if priority == "URGENT" else CYAN)
        print(f"  {color}  [{priority}] {action}{RESET}")
    print()

    # CISO escalation
    print(f"  {RED}{BOLD}  ⚠ CISO ESCALATION: YES — Global Admin compromise with active data exfiltration{RESET}")
    print()

    agent_says(
        f"Investigation complete in {state.elapsed_seconds:.1f} seconds. "
        f"This is a confirmed multi-stage attack spanning credential access through "
        f"exfiltration. Immediate containment is required."
    )


# ---------------------------------------------------------------------------
# HTML Report Generation
# ---------------------------------------------------------------------------

def generate_html_report(state: InvestigationState) -> Path:
    """Generate a comprehensive standalone HTML investigation report."""
    timeline_rows = "".join(
        f"<tr class='{'critical' if '✗' in p['event'] else ''}'>"
        f"<td>{p['time']}</td><td><span class='phase-badge'>{p['phase']}</span></td>"
        f"<td>{p['event']}</td></tr>"
        for p in state.attack_phases
    )

    entity_cards = "".join(
        f"<div class='entity-card risk-{e['risk'].lower()}'>"
        f"<span class='entity-icon'>{'👤' if e['type'] == 'account' else '🌐' if e['type'] == 'ip' else '🔑' if e['type'] == 'app' else '👑'}</span>"
        f"<strong>{e['name']}</strong><br><small>{e['role']} — {e['risk']}</small></div>"
        for e in state.entities
    )

    graph_edges_html = "".join(
        f"<tr><td>{src}</td><td class='edge-label'>{rel}</td><td>{dst}</td></tr>"
        for src, dst, rel in state.graph_edges
    )

    mitre_html = "".join(
        f"<span class='mitre-badge'>{t}</span>" for t in state.mitre_techniques
    )

    actions_html = "".join(
        f"<li class='action-{p.lower()}'><strong>[{p}]</strong> {a}</li>"
        for p, a in state.recommended_actions
    )

    ueba_html = ""
    if state.ueba_insights and "behavior_analytics" in state.ueba_insights:
        for row in state.ueba_insights["behavior_analytics"]["rows"]:
            score = row["InvestigationPriority"]
            ueba_html += (
                f"<div class='ueba-item score-{'critical' if score >= 9 else 'high'}'>"
                f"<span class='score'>{score}/10</span> {row['ActivityInsights']}</div>"
            )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat Hunt Report — {state.incident_id}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --text-muted: #8b949e;
    --blue: #58a6ff; --green: #3fb950; --yellow: #d29922;
    --red: #f85149; --purple: #a371f7; --cyan: #79c0ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 40px; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ color: var(--blue); font-size: 28px; margin-bottom: 8px; }}
  h2 {{ color: var(--cyan); font-size: 20px; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  .meta {{ color: var(--text-muted); margin-bottom: 24px; }}
  .verdict-box {{ background: #1c0a0a; border: 2px solid var(--red); border-radius: 8px; padding: 20px; margin: 24px 0; }}
  .verdict-box h3 {{ color: var(--red); font-size: 18px; }}
  .verdict-box .confidence {{ color: var(--yellow); margin-top: 4px; }}

  .entity-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 12px; }}
  .entity-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px; }}
  .entity-card.risk-critical {{ border-color: var(--red); }}
  .entity-card.risk-high {{ border-color: var(--yellow); }}
  .entity-card.risk-medium {{ border-color: var(--yellow); }}
  .entity-card.risk-low {{ border-color: var(--green); }}
  .entity-icon {{ font-size: 20px; margin-right: 4px; }}

  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
  th {{ background: var(--surface); color: var(--text-muted); padding: 10px 12px; text-align: left; font-size: 13px; text-transform: uppercase; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 14px; }}
  tr.critical td {{ color: var(--red); font-weight: 600; }}
  .edge-label {{ color: var(--purple); font-style: italic; }}
  .phase-badge {{ background: var(--surface); padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; color: var(--yellow); }}

  .mitre-section {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .mitre-badge {{ background: #1c1229; border: 1px solid var(--purple); color: var(--purple); padding: 4px 10px; border-radius: 4px; font-size: 13px; }}

  .ueba-item {{ background: var(--surface); border-radius: 6px; padding: 10px 14px; margin: 8px 0; border-left: 4px solid var(--yellow); }}
  .ueba-item.score-critical {{ border-left-color: var(--red); }}
  .ueba-item .score {{ font-weight: 700; color: var(--red); margin-right: 8px; }}

  ul {{ list-style: none; padding: 0; }}
  li {{ padding: 8px 0; border-bottom: 1px solid var(--border); }}
  .action-immediate {{ color: var(--red); }}
  .action-urgent {{ color: var(--yellow); }}
  .action-follow-up {{ color: var(--cyan); }}

  .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 13px; }}
</style>
</head>
<body>
<div class="container">

<h1>🔍 Autonomous Threat Hunt Report</h1>
<p class="meta">
  <strong>Incident:</strong> {state.incident_id} — {state.incident.get('title', 'N/A')}<br>
  <strong>Severity:</strong> {state.incident.get('severity', 'High')}<br>
  <strong>Generated:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
  <strong>Investigation Duration:</strong> {state.elapsed_seconds:.1f} seconds
</p>

<div class="verdict-box">
  <h3>🚨 {state.verdict}</h3>
  <div class="confidence">{state.confidence}</div>
</div>

<h2>Entity Relationship Graph</h2>
<div class="entity-grid">{entity_cards}</div>

<h3 style="color: var(--cyan); margin-top: 20px;">Graph Edges</h3>
<table>
<tr><th>Source</th><th>Relationship</th><th>Target</th></tr>
{graph_edges_html}
</table>

<h2>Attack Timeline</h2>
<table>
<tr><th>Time (UTC)</th><th>Phase</th><th>Event</th></tr>
{timeline_rows}
</table>

<h2>MITRE ATT&CK Coverage</h2>
<div class="mitre-section">{mitre_html}</div>

<h2>UEBA Risk Profile</h2>
{ueba_html}

<h2>Recommended Response Actions</h2>
<ul>{actions_html}</ul>

<div class="footer">
  <p>Generated by <strong>Sentinel Threat Hunter Agent</strong> — Agentic Threat Hunting with Microsoft Sentinel<br>
  MMS MOA 2026 | Powered by MCP + Azure OpenAI</p>
</div>

</div>
</body>
</html>"""

    output_path = Path(__file__).parent / f"investigation_report_{state.incident_id}.html"
    output_path.write_text(html, encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# Main Agent Loop
# ---------------------------------------------------------------------------

def run_agent(incident_id: str, replay: bool = True, export_html: bool = True) -> None:
    """Execute the full autonomous threat hunting agent loop."""

    banner("SENTINEL THREAT HUNTER AGENT")
    print(f"  {BOLD}Mode:{RESET}        {'Replay (Offline)' if replay else 'Live (MCP Connected)'}")
    print(f"  {BOLD}Incident:{RESET}    {incident_id}")
    print(f"  {BOLD}Started:{RESET}     {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  {BOLD}Agent:{RESET}       Autonomous Threat Hunter v1.0")
    print()

    state = InvestigationState(incident_id)

    if replay:
        data = load_replay_data()
    else:
        # In live mode, we'd connect to the MCP server
        print(f"{YELLOW}  Live mode requires a running Sentinel MCP server.")
        print(f"  Start with: python ../01-mcp-server/sentinel_mcp_server.py{RESET}")
        print(f"  Falling back to replay mode...\n")
        data = load_replay_data()

    # Display the agent's plan
    section("AGENT PLAN")
    agent_says("I'll investigate this incident autonomously. Here's my plan:")
    pause(0.3)
    for i, step in enumerate(AGENT_PLAN, 1):
        tool_name = step["tool"] or "reasoning"
        print(f"  {CYAN}  {i}. {step['description']}{RESET} {GRAY}[{tool_name}]{RESET}")
    print()
    pause()

    # Execute each step
    step_gather_incident(state, data)
    step_check_signins(state, data)
    step_build_timeline(state, data)
    step_ueba_analysis(state, data)
    step_graph_construction(state)
    step_generate_verdict(state)

    # Generate HTML report
    if export_html:
        section("REPORT EXPORT")
        report_path = generate_html_report(state)
        print(f"  {GREEN}✓ HTML investigation report saved:{RESET}")
        print(f"  {BOLD}  {report_path}{RESET}\n")

    # Final summary
    banner("INVESTIGATION COMPLETE")
    print(f"  {BOLD}Incident:{RESET}        {state.incident_id}")
    print(f"  {BOLD}Verdict:{RESET}         {RED}{state.verdict}{RESET}")
    print(f"  {BOLD}Confidence:{RESET}      {state.confidence}")
    print(f"  {BOLD}MITRE Techniques:{RESET} {len(state.mitre_techniques)} mapped")
    print(f"  {BOLD}Entities:{RESET}        {len(state.entities)} identified")
    print(f"  {BOLD}Duration:{RESET}        {state.elapsed_seconds:.1f} seconds")
    print(f"  {BOLD}CISO Escalation:{RESET} {RED}YES{RESET}")
    print()
    print(f"  {GRAY}(Traditional investigation: 45-90 minutes | Agent: {state.elapsed_seconds:.0f} seconds){RESET}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel Threat Hunter Agent — Autonomous Investigation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sentinel_threat_hunter_agent.py --replay
  python sentinel_threat_hunter_agent.py --incident-id INC-2847
  python sentinel_threat_hunter_agent.py --prompt "Is jsmith compromised?"
        """,
    )
    parser.add_argument("--replay", action="store_true", default=True,
                        help="Run in offline replay mode (default)")
    parser.add_argument("--live", action="store_true",
                        help="Connect to live MCP server")
    parser.add_argument("--incident-id", default="INC-2847",
                        help="Incident ID to investigate")
    parser.add_argument("--prompt", type=str, default=None,
                        help="Natural language investigation prompt")
    parser.add_argument("--no-html", action="store_true",
                        help="Skip HTML report generation")
    args = parser.parse_args()

    replay = not args.live
    export_html = not args.no_html

    if args.prompt:
        print(f"\n  {BOLD}Analyst Prompt:{RESET} \"{args.prompt}\"")
        print(f"  {GRAY}(Agent interpreting prompt and mapping to incident...){RESET}\n")
        pause(0.5)

    run_agent(
        incident_id=args.incident_id,
        replay=replay,
        export_html=export_html,
    )


if __name__ == "__main__":
    main()
