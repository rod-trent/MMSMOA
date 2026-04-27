"""
graph_investigation.py
======================
Graph Investigation Walkthrough Demo
Walks through a multi-stage attack using the Sentinel Investigation Graph
and UEBA insights, reconstructing the full attack chain.

Demo: "Graph Investigation Walkthrough"
Session: Agentic Threat Hunting with Microsoft Sentinel
Conference: MMS MOA 2026

Usage:
    python graph_investigation.py --replay           # No Azure needed
    python graph_investigation.py --incident-id <id> # Live mode
    python graph_investigation.py --export-html      # Save visual report
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
R, B, C, Y, G, RED, GR = "\033[0m", "\033[1m", "\033[96m", "\033[93m", "\033[92m", "\033[91m", "\033[90m"

def h(t):  sys.stdout.write(f"\n{B}{C}{'═'*68}\n  {t}\n{'═'*68}{R}\n\n")
def p(t, c=""): print(f"  {c}{t}{R}")


# ---------------------------------------------------------------------------
# Attack chain: multi-stage breach scenario for the demo
# ---------------------------------------------------------------------------

ATTACK_CHAIN = {
    "title": "Multi-Stage Attack: Password Spray → OAuth Persistence → Exfil",
    "incident_id": "INC-2847",
    "severity": "High",
    "mitre_phases": [
        "TA0006 Credential Access",
        "TA0001 Initial Access",
        "TA0003 Persistence",
        "TA0009 Collection",
        "TA0010 Exfiltration",
    ],
    "entities": {
        "accounts": [
            {"name": "jsmith@contoso.com", "risk": "CRITICAL", "is_pivot": True},
            {"name": "agarcia@contoso.com", "risk": "MEDIUM",   "is_pivot": False},
            {"name": "mwilliams@contoso.com", "risk": "LOW",    "is_pivot": False},
        ],
        "ips": [
            {"address": "185.220.101.45", "label": "Tor Exit Node", "country": "Netherlands", "threat_intel": True},
        ],
        "apps": [
            {"name": "GraphExplorer-Sync", "id": "9f4c2a1b-...", "permissions": ["Mail.Read", "Files.ReadWrite.All", "User.ReadBasic.All"]},
        ],
        "hosts": [
            {"name": "DESKTOP-CORP-114", "risk": "LOW"},
        ],
    },
    "timeline": [
        {"time": "01:47:33", "phase": "RECON",   "mitre": "T1110.003", "event": "Password spray starts — 185.220.101.45 attempts 47 passwords against jsmith@contoso.com", "severity": "MEDIUM"},
        {"time": "01:48:01", "phase": "RECON",   "mitre": "T1110.003", "event": "Same IP also sprays agarcia@contoso.com (12 attempts) and mwilliams@contoso.com (8 attempts)", "severity": "MEDIUM"},
        {"time": "01:59:12", "phase": "ACCESS",  "mitre": "T1078",     "event": "✗ BREACH: jsmith@contoso.com authenticated successfully from Tor IP", "severity": "CRITICAL"},
        {"time": "02:00:44", "phase": "ACCESS",  "mitre": "T1078",     "event": "UEBA: First logon from Netherlands in 90 days — InvestigationPriority=9", "severity": "HIGH"},
        {"time": "02:02:44", "phase": "PERSIST", "mitre": "T1098",     "event": "Account modification: jsmith profile updated (alternate email added)", "severity": "HIGH"},
        {"time": "02:03:18", "phase": "PERSIST", "mitre": "T1137",     "event": "OAuth app 'GraphExplorer-Sync' registered with admin consent grant", "severity": "CRITICAL"},
        {"time": "02:04:55", "phase": "PERSIST", "mitre": "T1098.001", "event": "Attacker added as owner of new Service Principal — enables persistent API access", "severity": "CRITICAL"},
        {"time": "02:07:33", "phase": "COLLECT", "mitre": "T1213.002", "event": "Mass download: 847 files from SharePoint in 4 minutes (14x peer avg)", "severity": "CRITICAL"},
        {"time": "02:11:02", "phase": "COLLECT", "mitre": "T1114.002", "event": "Alert: Anomalous OAuth app accessing Exchange mailbox via Graph API", "severity": "HIGH"},
        {"time": "02:14:19", "phase": "ESCALATE","mitre": "T1078.004", "event": "✗ PRIVILEGE ESCALATION: jsmith added to Global Administrator role", "severity": "CRITICAL"},
        {"time": "02:19:07", "phase": "EXFIL",   "mitre": "T1567.002", "event": "47 MB uploaded to external OneDrive via OAuth app token — still active", "severity": "CRITICAL"},
    ],
    "graph_edges": [
        ("jsmith@contoso.com", "185.220.101.45", "signed in from"),
        ("185.220.101.45", "agarcia@contoso.com", "attempted spray"),
        ("185.220.101.45", "mwilliams@contoso.com", "attempted spray"),
        ("jsmith@contoso.com", "GraphExplorer-Sync", "registered app"),
        ("GraphExplorer-Sync", "Mail.Read", "granted permission"),
        ("GraphExplorer-Sync", "Files.ReadWrite.All", "granted permission"),
        ("jsmith@contoso.com", "Global Administrator", "added to role"),
        ("GraphExplorer-Sync", "External Storage", "exfiltrated to"),
    ],
    "ueba_summary": {
        "user": "jsmith@contoso.com",
        "overall_score": 96,
        "anomalies": [
            {"score": 9,  "description": "First logon from Netherlands in 90 days"},
            {"score": 8,  "description": "Downloaded 14x more files than peer average"},
            {"score": 10, "description": "First OAuth app registration — no historical precedent"},
            {"score": 10, "description": "Added to privileged role — extremely rare for this department"},
        ],
        "peer_comparison": "jsmith's activity this session represents top 0.1% of all users by risk score",
    },
    "recommended_actions": [
        ("IMMEDIATE", "Revoke all active sessions for jsmith@contoso.com"),
        ("IMMEDIATE", "Remove jsmith from Global Administrator role"),
        ("IMMEDIATE", "Revoke and delete OAuth app 'GraphExplorer-Sync'"),
        ("IMMEDIATE", "Block IP 185.220.101.45 at Conditional Access"),
        ("URGENT",    "Audit 847 downloaded files — identify sensitive data exposure"),
        ("URGENT",    "Investigate 47 MB external upload destination"),
        ("URGENT",    "Force password reset: jsmith, agarcia, mwilliams"),
        ("FOLLOW-UP", "Enable Conditional Access: block Tor/VPN for corporate access"),
        ("FOLLOW-UP", "Restrict OAuth app consent — require admin approval"),
        ("FOLLOW-UP", "Enable Privileged Identity Management for Global Admin role"),
    ],
}

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

PHASE_COLORS = {
    "RECON":   Y,
    "ACCESS":  RED,
    "PERSIST": RED,
    "COLLECT": RED,
    "ESCALATE": RED,
    "EXFIL":   RED,
}

SEVERITY_ICONS = {
    "CRITICAL": f"{RED}🔴{R}",
    "HIGH":     f"{Y}🟡{R}",
    "MEDIUM":   f"{Y}⚠ {R}",
    "LOW":      f"{G}🟢{R}",
}


def render_entity_graph(data: dict) -> None:
    h("INVESTIGATION GRAPH — ENTITY RELATIONSHIPS")

    print(f"  {B}Accounts:{R}")
    for acct in data["entities"]["accounts"]:
        color = RED if acct["risk"] == "CRITICAL" else (Y if acct["risk"] == "MEDIUM" else G)
        pivot = " ← PIVOT ENTITY" if acct["is_pivot"] else ""
        p(f"👤 {acct['name']}  [{acct['risk']}]{pivot}", color)

    print(f"\n  {B}IPs:{R}")
    for ip in data["entities"]["ips"]:
        ti = "  ⚑ THREAT INTEL MATCH" if ip["threat_intel"] else ""
        p(f"🌐 {ip['address']}  ({ip['label']}, {ip['country']}){ti}", RED)

    print(f"\n  {B}OAuth Applications:{R}")
    for app in data["entities"]["apps"]:
        p(f"🔑 {app['name']}  (ID: {app['id']})", RED)
        p(f"   Permissions: {', '.join(app['permissions'])}", Y)

    print(f"\n  {B}Graph Edges (Relationships):{R}")
    for src, dst, rel in data["graph_edges"]:
        p(f"  {src}  —[{rel}]→  {dst}", GR)


def render_attack_timeline(data: dict) -> None:
    h("ATTACK TIMELINE — MITRE ATT&CK MAPPED")

    prev_phase = None
    for event in data["timeline"]:
        if event["phase"] != prev_phase:
            phase_color = PHASE_COLORS.get(event["phase"], C)
            print(f"\n  {phase_color}{B}── {event['phase']} ──────────────────────────{R}")
            prev_phase = event["phase"]

        icon = SEVERITY_ICONS.get(event["severity"], "")
        mitre_tag = f"{GR}[{event['mitre']}]{R}"
        print(f"  {GR}{event['time']}{R}  {icon}  {event['event']}")
        print(f"             {mitre_tag}")


def render_ueba_summary(data: dict) -> None:
    h("UEBA INSIGHTS — USER RISK PROFILE")

    ueba = data["ueba_summary"]
    score = ueba["overall_score"]
    score_color = RED if score >= 80 else (Y if score >= 50 else G)
    p(f"User: {ueba['user']}", B)
    p(f"Overall Risk Score: {score}/100", score_color + B)
    p(f"Peer Comparison: {ueba['peer_comparison']}", Y)

    print(f"\n  {B}Behavioral Anomalies:{R}")
    for anomaly in ueba["anomalies"]:
        color = RED if anomaly["score"] >= 9 else Y
        print(f"  {color}  [{anomaly['score']}/10] {anomaly['description']}{R}")


def render_response_actions(data: dict) -> None:
    h("RECOMMENDED RESPONSE ACTIONS")

    categories = {"IMMEDIATE": [], "URGENT": [], "FOLLOW-UP": []}
    for priority, action in data["recommended_actions"]:
        categories[priority].append(action)

    for cat, actions in categories.items():
        color = RED if cat == "IMMEDIATE" else (Y if cat == "URGENT" else C)
        print(f"  {color}{B}{cat}:{R}")
        for i, action in enumerate(actions, 1):
            print(f"  {color}  {i}. {action}{R}")
        print()


def render_mitre_coverage(data: dict) -> None:
    h("MITRE ATT&CK COVERAGE")
    for phase in data["mitre_phases"]:
        p(f"  ✓ {phase}", Y)
    print()
    techniques = sorted(set(e["mitre"] for e in data["timeline"]))
    p(f"Techniques: {', '.join(techniques)}", GR)


def render_html_report(data: dict, output_path: Path) -> None:
    """Generate a standalone HTML investigation report."""
    timeline_rows = "".join(
        f"<tr class='sev-{e['severity'].lower()}'>"
        f"<td>{e['time']}</td><td>{e['phase']}</td>"
        f"<td>{e['mitre']}</td><td>{e['event']}</td></tr>"
        for e in data["timeline"]
    )
    actions_html = "".join(
        f"<li class='priority-{p.lower()}'><strong>{p}:</strong> {a}</li>"
        for p, a in data["recommended_actions"]
    )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sentinel Investigation Report — {data['incident_id']}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 40px; }}
  h1 {{ color: #58a6ff; }}
  h2 {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
  th {{ background: #161b22; color: #8b949e; padding: 8px 12px; text-align: left; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; }}
  .sev-critical td {{ color: #ff7b72; }}
  .sev-high td {{ color: #f0883e; }}
  .sev-medium td {{ color: #e3b341; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
  .badge-high {{ background: #b91c1c; }}
  .badge-medium {{ background: #92400e; }}
  ul {{ padding-left: 20px; }}
  li {{ margin-bottom: 8px; }}
  .priority-immediate {{ color: #ff7b72; }}
  .priority-urgent {{ color: #e3b341; }}
  .priority-follow-up {{ color: #58a6ff; }}
</style>
</head>
<body>
<h1>🔍 Sentinel Investigation Report</h1>
<p><strong>Incident:</strong> {data['incident_id']} — {data['title']}<br>
   <strong>Severity:</strong> <span class="badge badge-high">{data['severity']}</span><br>
   <strong>Generated:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>

<h2>MITRE ATT&amp;CK Coverage</h2>
<p>{' | '.join(f'<span class="badge badge-medium">{p}</span>' for p in data['mitre_phases'])}</p>

<h2>Attack Timeline</h2>
<table>
<tr><th>Time (UTC)</th><th>Phase</th><th>Technique</th><th>Event</th></tr>
{timeline_rows}
</table>

<h2>UEBA Risk Summary</h2>
<p><strong>User:</strong> {data['ueba_summary']['user']}<br>
   <strong>Risk Score:</strong> {data['ueba_summary']['overall_score']}/100</p>
<ul>{''.join(f"<li>[{a['score']}/10] {a['description']}</li>" for a in data['ueba_summary']['anomalies'])}</ul>

<h2>Recommended Response Actions</h2>
<ul>{actions_html}</ul>
</body></html>"""
    output_path.write_text(html, encoding="utf-8")
    print(f"{G}  HTML report saved to: {output_path}{R}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Graph Investigation Demo")
    parser.add_argument("--replay", action="store_true", default=True)
    parser.add_argument("--incident-id", default="INC-2847")
    parser.add_argument("--export-html", action="store_true",
                        help="Export investigation to HTML report")
    args = parser.parse_args()

    data = ATTACK_CHAIN

    h(f"DEMO: Graph Investigation Walkthrough  |  {data['incident_id']}")
    p(data["title"], B)
    time.sleep(0.5)

    render_entity_graph(data)
    time.sleep(0.5)
    render_attack_timeline(data)
    time.sleep(0.5)
    render_ueba_summary(data)
    time.sleep(0.5)
    render_mitre_coverage(data)
    time.sleep(0.5)
    render_response_actions(data)

    if args.export_html:
        out = Path(__file__).parent / f"investigation_report_{data['incident_id']}.html"
        render_html_report(data, out)


if __name__ == "__main__":
    main()
