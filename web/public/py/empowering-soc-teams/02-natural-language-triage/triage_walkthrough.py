"""
triage_walkthrough.py
=====================
Replays Mission 1 as a terminal transcript: analyst asks in plain language,
the model discovers tables, runs queries, pivots, and produces a record.

Demo 2, Mission 1 - "Ask like an analyst"
Session:    Empowering SOC Teams
Conference: MMS Midway 2026 (San Diego)

What this is, and is not
------------------------
On stage you run Mission 1 live in Claude against the hosted Sentinel MCP
server. This script is the deterministic version of that same conversation:
same prompts, same tool calls, same evidence, no network and no tenant.

Use it to:
  * rehearse the narration and the timing
  * recover on stage when the Wi-Fi dies (it looks close enough)
  * let attendees replay the demo at home without a tenant

The tool calls are real - they go through the same functions the replay MCP
server exposes. What is scripted is the *sequence*, because a live model
picks its own path and a stage demo needs a known one.

Usage
-----
    python triage_walkthrough.py                # full transcript, paced
    python triage_walkthrough.py --fast         # no typing delay
    python triage_walkthrough.py --step         # pause at each step (Enter)
    python triage_walkthrough.py --json         # emit the record only
    python triage_walkthrough.py --save out.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from typing import Any

from replay_mcp_server import TENANT, UNTRUSTED_CLOSE, UNTRUSTED_OPEN, call_tool


def plain(value: str) -> str:
    """Strip the untrusted-data markers for human display.

    A client is supposed to *render* untrusted content - it just must not obey
    it. Stripping the wrapper for the terminal is the display half of that;
    Demo 4 tests the obedience half.
    """
    return value.replace(UNTRUSTED_OPEN, "").replace(UNTRUSTED_CLOSE, "")

# ---------------------------------------------------------------------------
# Terminal formatting
# ---------------------------------------------------------------------------

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"

_use_color = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _use_color else text


class Pacer:
    """Controls how fast the transcript prints. Stage demos need beats."""

    def __init__(self, fast: bool, step: bool) -> None:
        self.fast = fast
        self.step = step

    def beat(self, seconds: float = 0.6) -> None:
        if self.step:
            try:
                input(c("    [Enter to continue]", DIM))
            except EOFError:
                pass
        elif not self.fast:
            time.sleep(seconds)


def rule(title: str = "") -> None:
    if title:
        print()
        print(c(f"{'=' * 74}", DIM))
        print(c(f" {title}", BOLD))
        print(c(f"{'=' * 74}", DIM))
    else:
        print(c("-" * 74, DIM))


def analyst(text: str) -> None:
    print()
    print(c("ANALYST", GREEN) + c("  >  ", DIM) + text)


def model(text: str) -> None:
    print()
    for line in text.strip().split("\n"):
        print(c("CLAUDE ", CYAN) + c(" |  ", DIM) + line)


def toolcall(name: str, args: dict[str, Any]) -> None:
    rendered = ", ".join(f"{k}={v!r}" for k, v in args.items())
    print(c(f"           [tool] {name}({rendered})", MAGENTA))


def toolresult(summary: str) -> None:
    print(c(f"           [<--] {summary}", DIM))


def note(text: str) -> None:
    print()
    print(c(f"  >> STAGE NOTE: {text}", YELLOW))


# ---------------------------------------------------------------------------
# The walkthrough - slide 15, steps 2 through 6
# ---------------------------------------------------------------------------


def run(pacer: Pacer) -> dict[str, Any]:
    """Execute the mission and return the investigation record."""

    evidence: list[dict[str, Any]] = []
    timeline: list[str] = []

    def record(table: str, filt: str, rows: int) -> None:
        evidence.append({"table": table, "filter": filt, "rows": rows})

    rule("MISSION 1 - WIRE THE MODEL")
    print()
    print(f"  Tenant     {TENANT['tenant']['display_name']}")
    print(f"  Workspace  {TENANT['tenant']['workspace']}")
    print(f"  As of      {TENANT['tenant']['as_of']}")
    print(f"  Identity   analyst@contoso.com (Security Reader)")
    print(f"  Transport  MCP / Data Exploration collection")
    pacer.beat()

    # --- Step 2: table discovery ------------------------------------------

    rule("Step 2 - Discover the workspace")
    analyst("What can you see in this workspace?")

    result = call_tool("list_tables")
    toolcall("list_tables", {})
    toolresult(f"{len(result['tables'])} tables")

    model(
        "I have read access to {n} tables in {ws}. The ones that matter for\n"
        "identity investigations are SigninLogs, AADNonInteractiveUserSignInLogs,\n"
        "AuditLogs, CloudAppEvents, IdentityInfo, and BehaviorAnalytics.\n"
        "\n"
        "I have not queried anything yet - tell me what you are looking for.".format(
            n=len(result["tables"]), ws=TENANT["tenant"]["workspace"]
        )
    )
    note("This is the moment to say it: no KQL yet, no schema knowledge required. "
         "The model just told you what a new analyst spends a month learning.")
    pacer.beat()

    # --- Step 4: ask like an analyst --------------------------------------

    rule("Step 4 - Ask like an analyst")
    analyst(
        "Which incidents from the last 24 hours involve a user with impossible "
        "travel plus a new MFA method?"
    )

    model(
        "That is two conditions across two tables, so I will do it in three moves:\n"
        "  1. pull unassigned incidents from the last 24 hours\n"
        "  2. for each account involved, look for a location change in SigninLogs\n"
        "  3. for any account that has one, check AuditLogs for MFA registration\n"
        "\n"
        "Starting with the incident list."
    )

    incidents = call_tool(
        "list_incidents",
        {"max_age_hours": 24, "min_severity": "Medium", "unassigned_only": True},
    )
    toolcall("list_incidents", {"max_age_hours": 24, "min_severity": "Medium", "unassigned_only": True})
    toolresult(f"{incidents['row_count']} incidents")
    record("SecurityIncident", "last 24h, Medium+, unassigned", incidents["row_count"])

    for inc in incidents["incidents"]:
        print(c(f"             {inc['incident_number']}  {inc['severity']:<7} {plain(inc['title'])[:52]}", DIM))

    model(
        "Three candidates. Two of them ({a} and {b}) mention travel; {c} is a\n"
        "service account with failed sign-ins, which is a different pattern.\n"
        "Checking sign-in history for both travel candidates.".format(
            a=48209, b=48213, c=48201
        )
    )
    pacer.beat()

    # --- Step 5: watch it pivot -------------------------------------------

    rule("Step 5 - Watch it pivot")

    candidates = [
        ("j.doe@contoso.com", 48213),
        ("m.okafor@contoso.com", 48209),
    ]

    travel_hits: list[tuple[str, int, dict[str, Any]]] = []

    for upn, inc_no in candidates:
        signins = call_tool("get_signin_activity", {"upn": upn, "lookback_hours": 24})
        toolcall("get_signin_activity", {"upn": upn, "lookback_hours": 24})
        toolresult(
            f"{signins['row_count']} sign-ins, "
            f"{len(signins['derived_findings'])} location change(s)"
        )
        record("SigninLogs", f"UserPrincipalName == '{upn}', last 24h", signins["row_count"])

        for finding in signins["derived_findings"]:
            travel_hits.append((upn, inc_no, finding))
            print(
                c(
                    f"             {upn}: {finding['from']} -> {finding['to']} "
                    f"in {finding['minutes_between']} min "
                    f"(AS{finding['from_asn']} -> AS{finding['to_asn']})",
                    DIM,
                )
            )

    model(
        "Both accounts show a location change inside an hour. But look at the ASNs.\n"
        "\n"
        "  m.okafor  AS10796 -> AS8075. AS8075 is Microsoft.\n"
        "  j.doe     AS10796 -> AS33771. AS33771 is a Kenyan consumer ISP.\n"
        "\n"
        "Before I call either one impossible travel, I want the behavioural\n"
        "baseline. A VPN egress looks exactly like this in the raw logs."
    )
    note("Do not rush past this. The model just declined to answer the question "
         "it was asked, because the raw logs are not sufficient. That instinct is "
         "the whole session.")
    pacer.beat()

    for upn, _ in candidates:
        baseline = call_tool("get_ueba_baseline", {"upn": upn})
        toolcall("get_ueba_baseline", {"upn": upn})
        b = baseline["baseline"]
        toolresult(
            f"priority {b['InvestigationPriority']}, "
            f"first-time country: {b['FirstTimeCountry']}"
        )
        record("BehaviorAnalytics", f"UserPrincipalName == '{upn}', 90d baseline", 1)

    model(
        "That settles it.\n"
        "\n"
        "  m.okafor  IE and AS8075 are both already in the 90-day baseline.\n"
        "            Investigation priority 2. This is routine VPN use.\n"
        "\n"
        "  j.doe     KE is a first-time country, AS33771 is a first-time ASN,\n"
        "            and Microsoft Graph Command Line Tools is a first-time app.\n"
        "            Investigation priority 8.\n"
        "\n"
        "Incident 48209 is a benign positive. Continuing on 48213 only."
    )
    pacer.beat()

    audit = call_tool("get_audit_activity", {"upn": "j.doe@contoso.com", "lookback_hours": 24})
    toolcall("get_audit_activity", {"upn": "j.doe@contoso.com", "lookback_hours": 24})
    toolresult(f"{audit['row_count']} directory events")
    record("AuditLogs", "InitiatedBy == 'j.doe@contoso.com', last 24h", audit["row_count"])

    for row in audit["rows"]:
        print(c(f"             {row['TimeGenerated']}  {row['OperationName']}", DIM))

    model(
        "Both conditions from your question are met on 48213, and there is a third\n"
        "thing you did not ask for:\n"
        "\n"
        "  02:58:41  sign-in from Nairobi (first-time country, high risk)\n"
        "  03:02:30  new Microsoft Authenticator method registered\n"
        "  03:09:55  OAuth consent to 'Contoso Doc Sync' - unverified publisher,\n"
        "            granted Mail.Read, Files.Read.All, offline_access\n"
        "\n"
        "The consent is the part that worries me. offline_access means a refresh\n"
        "token that survives a password reset. Checking whether the app has used it."
    )
    pacer.beat()

    cloud = call_tool(
        "run_kql",
        {
            "query": 'CloudAppEvents | where AccountUpn == "j.doe@contoso.com"',
            "timespan_hours": 24,
        },
    )
    toolcall("run_kql", {"query": 'CloudAppEvents | where AccountUpn == "j.doe@contoso.com"'})
    toolresult(f"{cloud['row_count']} rows")
    record("CloudAppEvents", "AccountUpn == 'j.doe@contoso.com', last 24h", cloud["row_count"])

    for row in cloud["rows"]:
        print(
            c(
                f"             {row['Timestamp']}  {row['ActionType']} "
                f"by {row['Application']}  objects={row['ObjectCount']}",
                DIM,
            )
        )

    model(
        "Yes. 03:11:40 - 105 seconds after consent - the app read 218 mail items\n"
        "from the same Nairobi address. This is no longer a suspicious sign-in.\n"
        "It is an active mailbox collection with persistence in place."
    )
    pacer.beat()

    identity = call_tool(
        "run_kql",
        {
            "query": 'IdentityInfo | where AccountUPN == "j.doe@contoso.com"',
            "timespan_hours": 720,
        },
    )
    toolcall("run_kql", {"query": 'IdentityInfo | where AccountUPN == "j.doe@contoso.com"'})
    toolresult(f"{identity['row_count']} row")

    if identity["row_count"]:
        who = identity["rows"][0]
        record("IdentityInfo", "AccountUPN == 'j.doe@contoso.com'", 1)
        model(
            "Context that changes the severity: {name}, {title} in {dept}.\n"
            "Groups include SOX-InScope. Asset criticality High.\n"
            "\n"
            "A mailbox collection against a SOX-scoped finance analyst is not a\n"
            "Medium.".format(
                name=who["AccountDisplayName"],
                title=who["JobTitle"],
                dept=who["Department"],
            )
        )
    pacer.beat()

    # --- Step 6: check the benign case, then produce the record -----------

    rule("Step 6 - Check the benign case, then produce the record")
    analyst("What would make this benign? Go look.")

    model(
        "Three things would.\n"
        "\n"
        "  1. AS33771 is a known Contoso egress -> checking asset inventory\n"
        "  2. The consented app is on the approved publisher list -> checking\n"
        "  3. There is a change record covering this -> checking"
    )

    inventory = TENANT["asset_inventory"]
    known_asns = {e["asn"] for e in inventory["known_egress"]}
    approved = inventory["approved_oauth_publishers"]
    changes = [ch for ch in inventory["change_records"] if "j.doe@contoso.com" in ch["affects"]]

    benign_checks = [
        {
            "explanation": "196.207.14.88 / AS33771 is a known Contoso egress",
            "checked": True,
            "result": "no" if 33771 not in known_asns else "yes",
            "detail": f"Known egress ASNs: {sorted(known_asns)}",
        },
        {
            "explanation": "'Contoso Doc Sync' publisher is on the approved list",
            "checked": True,
            "result": "no",
            "detail": f"Publisher unverified. Approved list: {', '.join(approved)}",
        },
        {
            "explanation": "A change record covers this activity",
            "checked": True,
            "result": "no" if not changes else "yes",
            "detail": "No change record references this account",
        },
    ]

    for check in benign_checks:
        mark = c("no ", RED) if check["result"] == "no" else c("yes", GREEN)
        print(c(f"             [{mark}{c(']', DIM)} {check['explanation']}", DIM))

    model(
        "All three fail. Nothing benign explains this. Producing the record."
    )
    pacer.beat()

    timeline = [
        "2026-10-28T02:17:09Z  Normal sign-in, Columbus US, compliant device, MFA satisfied",
        "2026-10-28T02:58:41Z  Sign-in from Nairobi KE - first-time country and ASN, high risk",
        "2026-10-28T03:02:30Z  New Microsoft Authenticator method registered (persistence)",
        "2026-10-28T03:06:12Z  Graph CLI sign-in - first-time app for this account",
        "2026-10-28T03:09:55Z  OAuth consent to unverified 'Contoso Doc Sync' with offline_access",
        "2026-10-28T03:11:40Z  218 mail items read by that app from the Nairobi address",
    ]

    record_out = {
        "mission": "Mission 1 - natural-language investigation",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tenant": TENANT["tenant"]["display_name"],
        "analyst_identity": "analyst@contoso.com",
        "analyst_role": "Security Reader",
        "question_asked": (
            "Which incidents from the last 24 hours involve a user with "
            "impossible travel plus a new MFA method?"
        ),
        "incidents_reviewed": [48213, 48209, 48201],
        "finding": {
            "incident": 48213,
            "account": "j.doe@contoso.com",
            "verdict": "true_positive",
            "confidence": "high",
            "why": (
                "First-time country and ASN, immediately followed by MFA "
                "registration, OAuth consent to an unverified publisher with "
                "offline_access, and mailbox reads by that app 105 seconds later. "
                "Account is SOX-scoped with High asset criticality."
            ),
        },
        "dismissed": [
            {
                "incident": 48209,
                "account": "m.okafor@contoso.com",
                "verdict": "benign_positive",
                "why": (
                    "Destination country IE and AS8075 are both inside the "
                    "account's 90-day UEBA baseline. AS8075 is the Contoso Azure "
                    "VPN egress in the asset inventory. Investigation priority 2."
                ),
            }
        ],
        "evidence": evidence,
        "timeline": timeline,
        "benign_explanations_checked": benign_checks,
        "next_pivots": [
            "Revoke refresh tokens for j.doe and the Contoso Doc Sync service principal",
            "Enumerate every other consent grant to app id b17c9a02-4d5e-4a11-9f7b-2c8813ee0d55",
            "Check for inbox rules created on j.doe's mailbox after 02:58",
            "Confirm no other account signed in from AS33771 in the last 30 days",
        ],
        "actions_taken": [],
        "note": (
            "Read-only investigation. No incident was modified. Mission 2 picks "
            "this up and adds the approval gate."
        ),
    }

    rule("THE RECORD")
    print()
    for line in timeline:
        print(f"  {line}")
    print()
    print(c(f"  Evidence: {len(evidence)} queries across "
            f"{len({e['table'] for e in evidence})} tables", DIM))
    print(c(f"  Verdict:  true positive, high confidence", DIM))
    print(c(f"  Actions:  none - this connection is read-only", DIM))

    note("Close by opening the Sentinel audit view. Every tool call you just "
         "watched is in there, attributed to analyst@contoso.com, evaluated "
         "against Security Reader. Same RBAC as the portal.")

    return record_out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay Mission 1 - natural-language triage over Sentinel MCP."
    )
    parser.add_argument("--fast", action="store_true", help="No pacing delay.")
    parser.add_argument("--step", action="store_true", help="Pause at each beat.")
    parser.add_argument("--json", action="store_true", help="Print the record only.")
    parser.add_argument("--save", metavar="PATH", help="Write the record to a file.")
    args = parser.parse_args()

    if args.json:
        # Suppress the transcript, keep the record.
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = run(Pacer(fast=True, step=False))
        print(json.dumps(result, indent=2))
    else:
        result = run(Pacer(fast=args.fast, step=args.step))
        print()

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"Record written to {args.save}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
