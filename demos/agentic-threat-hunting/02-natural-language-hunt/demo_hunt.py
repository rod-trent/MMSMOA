"""
demo_hunt.py
============
Natural Language Threat Hunt Demo
Simulates an AI agent using Sentinel MCP tools to investigate a suspicious
sign-in incident. Can run live (against real MCP server) or in replay mode.

Demo: "Natural Language Threat Hunt"
Session: Agentic Threat Hunting with Microsoft Sentinel
Conference: MMS MOA 2026

Usage:
    python demo_hunt.py --replay                    # No Azure needed
    python demo_hunt.py --incident-id INC-2847      # Live mode
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
# Pretty printing helpers
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BLUE   = "\033[94m"


def _print_header(text: str) -> None:
    width = 70
    print(f"\n{BOLD}{CYAN}{'═' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * width}{RESET}\n")


def _print_tool_call(tool_name: str, args: dict) -> None:
    print(f"{YELLOW}  ⚡ TOOL CALL: {BOLD}{tool_name}{RESET}")
    for k, v in args.items():
        print(f"{GRAY}     {k}: {v}{RESET}")
    print()


def _print_tool_result(result: dict, max_rows: int = 5) -> None:
    if "error" in result:
        print(f"  {RED}✗ Error: {result['error']}{RESET}\n")
        return
    if "rows" in result:
        rows = result["rows"][:max_rows]
        print(f"  {GREEN}✓ {result['row_count']} row(s) returned{RESET}")
        for row in rows:
            summary = "  |  ".join(f"{k}: {v}" for k, v in list(row.items())[:4])
            print(f"  {GRAY}  → {summary}{RESET}")
        if result["row_count"] > max_rows:
            print(f"  {GRAY}  ... and {result['row_count'] - max_rows} more rows{RESET}")
    else:
        # Incident/entity result
        for k, v in result.items():
            if k not in ("entities", "behavior_analytics", "peer_analytics"):
                print(f"  {GRAY}  {k}: {v}{RESET}")
    print()


def _typewrite(text: str, delay: float = 0.018) -> None:
    """Simulate AI typing effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def _pause(seconds: float = 1.0) -> None:
    time.sleep(seconds)


# ---------------------------------------------------------------------------
# Replay mode (offline demo using sample_incident.json)
# ---------------------------------------------------------------------------

def run_replay(data: dict) -> None:
    incident   = data["incident"]
    signins    = data["failed_signins"]
    timeline   = data["entity_timeline"]
    ueba       = data["ueba_insights"]

    _print_header("DEMO: Natural Language Threat Hunt (Replay Mode)")
    _pause(0.5)

    # ── Step 1: Analyst prompt ──────────────────────────────────────────────
    print(f"{BOLD}Analyst:{RESET}")
    _typewrite(
        f'  "Investigate incident {incident["incident_id"]} and tell me if it\'s real. '
        'Should I wake up the CISO?"'
    )
    _pause(1.5)

    # ── Step 2: Tool call — get_incident_details ───────────────────────────
    print(f"\n{BOLD}Copilot for Security (via MCP):{RESET}")
    _typewrite("  I'll start by pulling the full incident details...")
    _pause(0.5)
    _print_tool_call("get_incident_details", {"incident_id": incident["incident_id"]})
    _print_tool_result({
        **incident,
        "rows": [],
        "row_count": len(incident["entities"]),
    })
    _pause(0.5)

    print(f"  {BLUE}→ {incident['severity']} severity incident. "
          f"Entities: {', '.join(e['friendly_name'] for e in incident['entities'])}. "
          f"Tactics: {', '.join(incident['tactics'])}.{RESET}\n")
    _pause(1.0)

    # ── Step 3: Tool call — get_failed_signins ─────────────────────────────
    _typewrite("  Let me check the sign-in failure pattern around this incident...")
    _pause(0.5)
    _print_tool_call("get_failed_signins", {"lookback_hours": 1, "min_failures": 5})
    _print_tool_result(signins)

    top = signins["rows"][0]
    print(f"  {BLUE}→ {top['FailedAttempts']} failures for {top['UserPrincipalName']} "
          f"from {top['IPAddress']} ({top['Locations'][0]}) — "
          f"classic password spray. {len(signins['rows'])} accounts targeted.{RESET}\n")
    _pause(1.0)

    # ── Step 4: Tool call — search_entities ────────────────────────────────
    upn = top["UserPrincipalName"]
    _typewrite(f"  Now I'll build an entity timeline for {upn} to see what happened after...")
    _pause(0.5)
    _print_tool_call("search_entities", {"entity_value": upn, "entity_type": "account", "lookback_hours": 2})
    _print_tool_result(timeline)

    post_success = [r for r in timeline["rows"] if r["EventType"] in ("AuditEvent", "SecurityAlert")]
    print(f"  {RED}⚠ CRITICAL: {len(post_success)} post-authentication events detected:{RESET}")
    for event in post_success:
        icon = "🚨" if event["EventType"] == "SecurityAlert" else "📋"
        print(f"  {RED}  {icon} [{event['TimeGenerated']}] {event['Detail']}{RESET}")
    print()
    _pause(1.5)

    # ── Step 5: Tool call — get_ueba_insights ─────────────────────────────
    _typewrite(f"  Checking UEBA risk profile for {upn}...")
    _pause(0.5)
    _print_tool_call("get_ueba_insights", {"user_upn": upn, "lookback_days": 7})

    ba_rows = ueba["behavior_analytics"]["rows"]
    top_risk = max(ba_rows, key=lambda r: r["InvestigationPriority"])
    print(f"  {GREEN}✓ {len(ba_rows)} behavior anomalies found{RESET}")
    for row in ba_rows:
        priority_color = RED if row["InvestigationPriority"] >= 9 else YELLOW
        print(f"  {priority_color}  [{row['InvestigationPriority']}/10] {row['ActivityInsights']}{RESET}")
    print()
    _pause(1.5)

    # ── Step 6: Final investigation report ────────────────────────────────
    _print_header("INVESTIGATION REPORT")
    _typewrite("  Synthesizing findings...\n", delay=0.01)
    _pause(0.5)

    report = f"""
{BOLD}Incident:{RESET}  {incident['incident_id']} — {incident['title']}
{BOLD}Verdict:{RESET}   {RED}{BOLD}CONFIRMED COMPROMISE — TRUE POSITIVE{RESET}
{BOLD}Confidence:{RESET} HIGH (multiple corroborating signals)

{BOLD}Attack Chain Reconstructed:{RESET}
  01:47 UTC  Password spray begins — 47 attempts against jsmith@contoso.com
             from Tor exit node 185.220.101.45 (Netherlands)
  01:59 UTC  {RED}✗ ACCOUNT COMPROMISED — Successful sign-in{RESET}
  02:02 UTC  Attacker modifies jsmith profile (persistence)
  02:03 UTC  {RED}✗ OAuth app registered with admin consent{RESET}
  02:07 UTC  {RED}✗ Mass download — 14x peer average{RESET}
  02:11 UTC  {RED}✗ Anomalous OAuth app flags automated exfiltration{RESET}
  02:14 UTC  {RED}✗✗ PRIVILEGE ESCALATION: jsmith added to Global Admin role{RESET}

{BOLD}Recommended Immediate Actions:{RESET}
  1. {RED}URGENT:{RESET} Revoke all active sessions for jsmith@contoso.com
  2. {RED}URGENT:{RESET} Remove jsmith from Global Admin role
  3. {RED}URGENT:{RESET} Revoke consent for OAuth app registered at 02:03 UTC
  4. Block IP 185.220.101.45 at Conditional Access + firewall
  5. Force password reset for all 3 targeted accounts
  6. Audit any files downloaded by jsmith in the last 60 minutes
  7. Escalate to Incident Response — potential data exfiltration

{BOLD}CISO Escalation:{RESET} {RED}{BOLD}YES — privilege escalation to Global Admin detected{RESET}
"""
    print(report)
    print(f"{GRAY}  (Investigation completed in ~15 seconds vs. typical 45-90 minutes){RESET}\n")


# ---------------------------------------------------------------------------
# Live mode — connects to real MCP server via subprocess
# ---------------------------------------------------------------------------

def run_live(incident_id: str) -> None:
    """
    Live demo: calls the actual MCP server tools.
    Requires the MCP server running and .env configured.
    """
    import subprocess
    import asyncio
    from pathlib import Path

    server_script = Path(__file__).parent.parent / "01-mcp-server" / "sentinel_mcp_server.py"
    if not server_script.exists():
        print(f"{RED}MCP server not found at {server_script}{RESET}")
        sys.exit(1)

    print(f"{CYAN}Starting MCP server...{RESET}")
    # For a real demo, you'd use the MCP client SDK to connect.
    # This shows the tool-calling pattern — adapt to your client SDK version.
    print(f"{YELLOW}Live mode requires the mcp[client] package and a running server.")
    print(f"For now, run in --replay mode or connect via Claude Desktop.{RESET}")
    print(f"\nTo use with Claude Desktop, add to claude_desktop_config.json:")
    print(json.dumps({
        "mcpServers": {
            "sentinel": {
                "command": "python",
                "args": [str(server_script)],
            }
        }
    }, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Natural Language Threat Hunt Demo")
    parser.add_argument("--replay", action="store_true",
                        help="Run in offline replay mode using sample_incident.json")
    parser.add_argument("--incident-id", default="INC-2847",
                        help="Incident ID for live mode")
    args = parser.parse_args()

    if args.replay or True:  # default to replay for conference demo safety
        data_file = Path(__file__).parent / "sample_incident.json"
        with open(data_file) as f:
            data = json.load(f)
        run_replay(data)
    else:
        run_live(args.incident_id)


if __name__ == "__main__":
    main()
