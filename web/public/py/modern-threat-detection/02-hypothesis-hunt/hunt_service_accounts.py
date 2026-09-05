"""
hunt_service_accounts.py
========================
Mission 1: hypothesis to evidence, without writing a line of KQL.

Demo 2 · Session: Using AI for Modern Threat Detection
Conference: MMS 2026 Midway Edition - San Diego, October 25-28 2026

The hypothesis (slide 15, step 1):

    "Service accounts should never sign in interactively. Show me any that
     did in the last 7 days and what they touched afterward."

The six steps from slide 15, replayed deterministically:

    1. State the hypothesis
    2. Watch table discovery
    3. Review the KQL          <- the first validation checkpoint
    4. Pivot on the hit
    5. Check the baseline
    6. Produce the record      <- Mission 2 consumes this

Why the decoy matters
---------------------
Two service accounts signed in interactively this week. One is a compromise.
The other is a documented break-glass procedure on a compliant jump host,
inside an approved change window.

A hunt that reports both is a hunt nobody runs twice. Step 5 is where the
difference shows up, and it is the part of the demo worth slowing down for.

Usage
-----
    python hunt_service_accounts.py            # paced transcript
    python hunt_service_accounts.py --fast
    python hunt_service_accounts.py --step     # pause at each beat
    python hunt_service_accounts.py --json
    python hunt_service_accounts.py --save mission1-record.json
    python hunt_service_accounts.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DATA = Path(__file__).parent / "sample_hunt_data.json"

RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
CYAN, GREEN, YELLOW, MAGENTA, RED = "\033[36m", "\033[32m", "\033[33m", "\033[35m", "\033[31m"
_color = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _color else text


# ---------------------------------------------------------------------------
# Data access - the tool layer a real MCP connection would provide
# ---------------------------------------------------------------------------


def load() -> dict[str, Any]:
    with DATA.open(encoding="utf-8") as fh:
        return json.load(fh)


TENANT = load()


def strip_meta(obj: Any) -> Any:
    """Remove authoring notes and ground truth before anything is 'seen'."""
    if isinstance(obj, dict):
        return {k: strip_meta(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [strip_meta(v) for v in obj]
    return obj


def now() -> datetime:
    return datetime.fromisoformat(TENANT["tenant"]["as_of"].replace("Z", "+00:00"))


def ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Transcript formatting
# ---------------------------------------------------------------------------


class Pacer:
    def __init__(self, fast: bool, step: bool) -> None:
        self.fast, self.step = fast, step

    def beat(self, seconds: float = 0.6) -> None:
        if self.step:
            try:
                input(c("    [Enter]", DIM))
            except EOFError:
                pass
        elif not self.fast:
            time.sleep(seconds)


def step_header(number: int, title: str) -> None:
    print()
    print(c("=" * 74, DIM))
    print(c(f" STEP {number}/6  {title}", BOLD))
    print(c("=" * 74, DIM))


def hunter(text: str) -> None:
    print()
    print(c("HUNTER", GREEN) + c("  >  ", DIM) + text)


def model(text: str) -> None:
    print()
    for line in text.strip().split("\n"):
        print(c("CLAUDE", CYAN) + c(" |  ", DIM) + line)


def kql(query: str) -> None:
    print()
    for line in query.strip().split("\n"):
        print(c("        " + line, MAGENTA))
    print()


def result(text: str) -> None:
    print(c(f"        -> {text}", DIM))


def note(text: str) -> None:
    print()
    print(c(f"  >> STAGE NOTE: {text}", YELLOW))


# ---------------------------------------------------------------------------
# The hunt
# ---------------------------------------------------------------------------


def run(pacer: Pacer) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    timeline: list[str] = []

    def cite(table: str, filt: str, rows: int) -> None:
        evidence.append({"table": table, "filter": filt, "rows": rows})

    window_days = 7
    cutoff = now() - timedelta(days=window_days)

    print()
    print(c("  MISSION 1 - SPEED THE INVESTIGATION", BOLD))
    print(c(f"  {TENANT['tenant']['display_name']} / {TENANT['tenant']['workspace']}", DIM))
    print(c(f"  Window: last {window_days} days, as of {TENANT['tenant']['as_of']}", DIM))
    print(c("  Identity: hunter@contoso.com (Security Reader, read-only)", DIM))

    # --- Step 1 -----------------------------------------------------------

    step_header(1, "State the hypothesis")
    hunter(
        "Service accounts should never sign in interactively. Show me any that "
        "did in the last 7 days and what they touched afterward."
    )
    note("That is a hypothesis, not a question. It can come back empty, and "
         "empty would be a real answer. Build-HuntPrompt.py in Demo 1 is the "
         "linter that enforces the difference.")
    pacer.beat()

    # --- Step 2 -----------------------------------------------------------

    step_header(2, "Watch table discovery")
    model(
        "Before I query anything, here is what I think is relevant and why:\n"
        "\n"
        "  SigninLogs                        interactive sign-ins, has IsInteractive\n"
        "  AADNonInteractiveUserSignInLogs   the baseline - what these accounts\n"
        "                                    normally do, so I can tell 'unusual'\n"
        "                                    from 'never'\n"
        "  MicrosoftGraphActivityLogs        what happened afterward\n"
        "  BehaviorAnalytics                 UEBA baseline per account\n"
        "  AuditLogs                         directory changes made after the fact\n"
        "\n"
        "I also need to know which accounts are service accounts. There is no\n"
        "flag for that in Entra - I will use the naming convention and confirm\n"
        "against IdentityInfo. Say so now, because it is the weakest assumption\n"
        "in this hunt."
    )
    result(f"{len(TENANT['tables'])} tables in the workspace")
    note("The model named its own weakest assumption before it ran anything. "
         "That is what you want, and it is the thing to point at.")
    pacer.beat()

    # --- Step 3 -----------------------------------------------------------

    step_header(3, "Review the KQL - the first validation checkpoint")
    hunter("Show me the query first. What would it miss?")

    query = """let window = 7d;
let service_accounts = IdentityInfo
    | where AccountUPN startswith "svc-"
    | distinct AccountUPN;
SigninLogs
| where TimeGenerated > ago(window)
| where UserPrincipalName in (service_accounts)
| where IsInteractive == true
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress,
          AutonomousSystemNumber, Location, AppDisplayName, UserAgent
| order by TimeGenerated desc"""
    kql(query)

    model(
        "What it matches: successful interactive sign-ins by any account whose\n"
        "UPN starts with 'svc-', in the last 7 days.\n"
        "\n"
        "What it would MISS, which is the more useful list:\n"
        "  - service accounts not named svc-* (the naming convention is a\n"
        "    convention, not a control)\n"
        "  - failed interactive attempts, which are a signal in their own right\n"
        "  - workload identities and service principals, which live in\n"
        "    AADServicePrincipalSignInLogs, a different table entirely\n"
        "  - anything outside the 7-day window\n"
        "\n"
        "I would not treat an empty result from this query as 'no compromise'."
    )
    note('Say the line: "I never run a query I have not read." It comes back '
         'in the guardrails section and it answers half the Q&A.')
    pacer.beat()

    hunter("Run it.")

    hits = [
        s for s in TENANT["signin_logs"]
        if s.get("IsInteractive") and s["ResultType"] == "0" and ts(s["TimeGenerated"]) >= cutoff
    ]
    cite("SigninLogs", 'svc-* AND IsInteractive == true AND ResultType == 0, 7d', len(hits))
    result(f"{len(hits)} rows")
    print()
    for h in hits:
        print(c(f"        {h['TimeGenerated']}  {h['UserPrincipalName']:<28} "
                f"AS{h['AutonomousSystemNumber']:<7} {h.get('City', h['Location']):<10} "
                f"{h['AppDisplayName']}", DIM))

    model(
        "Two hits. Both are service accounts signing in interactively, which is\n"
        "the thing you said should never happen.\n"
        "\n"
        "I am not going to tell you both are incidents. One of them looks like\n"
        "infrastructure I recognise. Checking the baseline before I say anything\n"
        "about either."
    )
    pacer.beat()

    # --- Step 5 (before 4 - baseline first, deliberately) ------------------

    step_header(5, "Check the baseline - is this new for THIS account?")

    known_asns = {a["asn"] for a in TENANT["known_infrastructure"]["egress_asns"]}
    jump_hosts = set(TENANT["known_infrastructure"]["jump_hosts"])

    assessments: list[dict[str, Any]] = []

    # Assess per account, not per row. svc-datasync signed in twice; that is one
    # account to judge, not two. Pick the sign-in UEBA scored highest - it is the
    # one carrying the first-time signals.
    def ueba_priority(row: dict[str, Any]) -> int:
        match = [
            a for a in TENANT["ueba_anomalies"]
            if a["UserPrincipalName"] == row["UserPrincipalName"]
            and a["TimeGenerated"] == row["TimeGenerated"]
        ]
        return match[0]["InvestigationPriority"] if match else 0

    by_account: dict[str, dict[str, Any]] = {}
    for row in hits:
        upn_key = row["UserPrincipalName"]
        if upn_key not in by_account or ueba_priority(row) > ueba_priority(by_account[upn_key]):
            by_account[upn_key] = row

    for hit in by_account.values():
        upn = hit["UserPrincipalName"]
        asn = hit["AutonomousSystemNumber"]

        anomalies = [
            a for a in TENANT["ueba_anomalies"]
            if a["UserPrincipalName"] == upn and a["TimeGenerated"] == hit["TimeGenerated"]
        ]
        priority = anomalies[0]["InvestigationPriority"] if anomalies else 0
        insights = anomalies[0]["ActivityInsights"] if anomalies else []
        cite("BehaviorAnalytics", f"UserPrincipalName == '{upn}', 90d baseline", len(anomalies))

        device = (hit.get("DeviceDetail") or {}).get("deviceId")
        changes = [
            ch for ch in TENANT["change_records"]
            if upn in ch["affects"] and ts(ch["opened"]) <= ts(hit["TimeGenerated"]) <= ts(ch["closed"])
        ]

        benign: list[dict[str, Any]] = [
            {
                "explanation": f"AS{asn} is a known Contoso egress",
                "result": "yes" if asn in known_asns else "no",
                "detail": f"Known egress: {sorted(known_asns)}",
            },
            {
                "explanation": "Sign-in came from an approved jump host",
                "result": "yes" if device in jump_hosts else "no",
                "detail": f"Device: {device or 'not recorded'}; approved: {sorted(jump_hosts)}",
            },
            {
                "explanation": "An open change record covers this sign-in",
                "result": "yes" if changes else "no",
                "detail": changes[0]["id"] + " - " + changes[0]["summary"] if changes
                          else "No change record covers this time window",
            },
        ]

        explained = sum(1 for b in benign if b["result"] == "yes")
        verdict = "benign" if explained >= 2 else "investigate"

        assessments.append({
            "upn": upn,
            "asn": asn,
            "priority": priority,
            "insights": insights,
            "benign_checks": benign,
            "verdict": verdict,
            "signin": hit,
        })

        print()
        print(c(f"        {upn}", BOLD))
        print(c(f"          UEBA investigation priority : {priority}", DIM))
        print(c(f"          First-time signals          : {', '.join(insights) or 'none'}", DIM))
        for b in benign:
            mark = c("yes", GREEN) if b["result"] == "yes" else c("no ", RED)
            print(c(f"          [{mark}{c(']', DIM)} {b['explanation']}", DIM))

    pacer.beat()

    target = next(a for a in assessments if a["verdict"] == "investigate")
    decoy = next(a for a in assessments if a["verdict"] == "benign")

    model(
        "They are not the same thing.\n"
        "\n"
        "  {decoy}\n"
        "    AS{d_asn} is our Columbus HQ range, the sign-in came from an\n"
        "    approved jump host, and {chg} covers the window. UEBA priority {d_pri}.\n"
        "    This is a documented break-glass procedure. Not reporting it.\n"
        "\n"
        "  {target}\n"
        "    AS{t_asn} is not ours. No jump host. No change record. UEBA\n"
        "    priority {t_pri}, and five first-time signals at once, including\n"
        "    'FirstTimeUserLoggedOnInteractively'.\n"
        "\n"
        "Following the second one.".format(
            decoy=decoy["upn"],
            d_asn=decoy["asn"],
            d_pri=decoy["priority"],
            chg=next(b["detail"].split(" - ")[0] for b in decoy["benign_checks"]
                     if b["explanation"].startswith("An open change record") and b["result"] == "yes"),
            target=target["upn"],
            t_asn=target["asn"],
            t_pri=target["priority"],
        )
    )
    note("This is the highest-value 30 seconds in the session. The model just "
         "declined to report a finding that matched the hypothesis, because the "
         "boring explanation held. A hunt that cannot do this generates work "
         "instead of removing it.")
    pacer.beat()

    # --- Step 4 -----------------------------------------------------------

    step_header(4, "Pivot on the hit - what did it touch afterward?")
    hunter(
        "Show me everything that identity did in the 60 minutes after that "
        "sign-in, across every table you can reach."
    )

    upn = target["upn"]
    start = ts(target["signin"]["TimeGenerated"])
    end = start + timedelta(minutes=60)

    graph = [
        g for g in TENANT["graph_activity"]
        if g["UserPrincipalName"] == upn and start <= ts(g["TimeGenerated"]) <= end
    ]
    cite("MicrosoftGraphActivityLogs", f"UserPrincipalName == '{upn}', +60min", len(graph))
    result(f"{len(graph)} Graph API calls")
    print()
    for g in graph:
        endpoint = g["RequestUri"].replace("https://graph.microsoft.com/v1.0/", "")
        print(c(f"        {g['TimeGenerated']}  {g['RequestMethod']:<5} /{endpoint:<18} "
                f"{g['ResponseSizeBytes']:>9,} bytes", DIM))

    more_signins = [
        s for s in TENANT["signin_logs"]
        if s["UserPrincipalName"] == upn and start < ts(s["TimeGenerated"]) <= end
    ]
    cite("SigninLogs", f"UserPrincipalName == '{upn}', +60min", len(more_signins))

    timeline = [f"{target['signin']['TimeGenerated']}  Interactive sign-in from "
                f"AS{target['asn']} ({target['signin'].get('City')}, "
                f"{target['signin']['Location']}) via {target['signin']['AppDisplayName']}"]
    for s in more_signins:
        timeline.append(f"{s['TimeGenerated']}  Second sign-in, {s['AppDisplayName']}")
    for g in graph:
        endpoint = g["RequestUri"].split("/")[-1]
        timeline.append(f"{g['TimeGenerated']}  Graph GET /{endpoint} "
                        f"({g['ResponseSizeBytes']:,} bytes)")
    timeline.sort()

    model(
        "Four Graph calls in seventeen minutes: /users, /groups, /directoryRoles,\n"
        "/applications. That sequence is directory enumeration - who exists, how\n"
        "they are grouped, who is privileged, and what apps are trusted.\n"
        "\n"
        "The /directoryRoles call is the one that matters. A data sync service\n"
        "has no reason to ask who the administrators are.\n"
        "\n"
        "1.8 MB from /users means the full directory came back."
    )
    pacer.beat()

    lateral = [
        e for e in TENANT["cloud_app_events"]
        if e.get("IPAddress") == target["signin"]["IPAddress"]
    ]
    if lateral:
        cite("CloudAppEvents", f"IPAddress == '{target['signin']['IPAddress']}', 7d", len(lateral))
        model(
            "One more pivot, on the IP rather than the account.\n"
            "\n"
            f"AS{target['asn']} / {target['signin']['IPAddress']} also appears in\n"
            f"{len(lateral)} CloudAppEvents rows for different users entirely -\n"
            + "\n".join(
                f"  {e['Timestamp']}  {e['AccountUpn']}  {e['ActionType']} "
                f"x{e['ObjectCount']} via '{e['Application']}'"
                for e in lateral
            )
            + "\n\n"
            "That is the same infrastructure touching mail and files through a\n"
            "third-party application. This is not one compromised service\n"
            "account. Recommend a second hunt on that application, in its own\n"
            "thread."
        )
        note("One hypothesis per thread. Park this and come back to it - that "
             "is exactly what Mission 2 does, and it is why the two demos are "
             "one story.")
        pacer.beat()

    # --- Step 6 -----------------------------------------------------------

    step_header(6, "Produce the record")
    hunter(
        "Give me the record: hypothesis, evidence with row counts, timeline, "
        "confidence, what you checked for benign, and next pivots."
    )

    record = {
        "mission": "Mission 1 - service accounts used interactively",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tenant": TENANT["tenant"]["display_name"],
        "hunter_identity": "hunter@contoso.com",
        "hunter_role": "Security Reader (read-only)",
        "window_days": window_days,
        "hypothesis": (
            "Service accounts are being used interactively from infrastructure "
            "we do not own."
        ),
        "result": "confirmed",
        "finding": {
            "account": target["upn"],
            "first_seen": target["signin"]["TimeGenerated"],
            "source_ip": target["signin"]["IPAddress"],
            "source_asn": target["asn"],
            "location": f"{target['signin'].get('City')}, {target['signin']['Location']}",
            "ueba_investigation_priority": target["priority"],
            "first_time_signals": target["insights"],
            "post_access_activity": "Directory enumeration via Graph API - "
                                    "/users, /groups, /directoryRoles, /applications",
        },
        "dismissed": [
            {
                "account": decoy["upn"],
                "why": (
                    "Matched the hypothesis but is explained: known egress ASN, "
                    "approved jump host, and an open change record covering the "
                    "window. UEBA priority 3."
                ),
            }
        ],
        "evidence": evidence,
        "timeline": timeline,
        "confidence": "high",
        "confidence_reasoning": (
            "Five independent first-time signals on one sign-in, a coherent "
            "enumeration sequence immediately afterward, and no benign "
            "explanation held. The source ASN also appears against unrelated "
            "users, which raises this from an account issue to a campaign."
        ),
        "benign_explanations_checked": target["benign_checks"],
        "what_this_hunt_would_miss": [
            "Service accounts not following the svc-* naming convention",
            "Failed interactive attempts (ResultType != 0)",
            "Service principals - they are in AADServicePrincipalSignInLogs, not SigninLogs",
            "Activity outside the 7-day window",
        ],
        "next_pivots": [
            f"Every account that authenticated from AS{target['asn']} in the last 30 days",
            "The third-party application appearing in CloudAppEvents from the same IP "
            "(this is Mission 2)",
            f"Whether {target['upn']} has an owner who can confirm it should never sign in interactively",
            "Whether the enumerated directory roles were subsequently targeted",
        ],
        "actions_taken": [],
    }

    print()
    print(c("  Hypothesis    ", BOLD) + record["hypothesis"])
    print(c("  Result        ", BOLD) + c("confirmed", RED))
    print(c("  Finding       ", BOLD) + f"{target['upn']} from AS{target['asn']}")
    print(c("  Dismissed     ", BOLD) + f"{decoy['upn']} (documented break-glass)")
    print(c("  Evidence      ", BOLD) + f"{len(evidence)} queries across "
          f"{len({e['table'] for e in evidence})} tables")
    print(c("  Confidence    ", BOLD) + "high")
    print(c("  Actions taken ", BOLD) + "none - this connection is read-only")

    print()
    print(c("  Timeline", BOLD))
    for line in timeline:
        print(f"    {line}")

    note("Save this record. Mission 2 starts from it - the application that "
         "shows up in the last pivot is what the analytics rules missed.")

    return record


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def self_test() -> int:
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        record = run(Pacer(fast=True, step=False))

    checks: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        checks.append((label, ok, detail))

    check(
        "hunt confirms the hypothesis",
        record["result"] == "confirmed",
    )
    check(
        "identifies svc-datasync as the finding",
        record["finding"]["account"] == "svc-datasync@contoso.com",
        record["finding"]["account"],
    )
    check(
        "dismisses the svc-reporting decoy",
        any(d["account"] == "svc-reporting@contoso.com" for d in record["dismissed"]),
        "the decoy is the whole point",
    )
    check(
        "every benign explanation was actually checked",
        len(record["benign_explanations_checked"]) == 3
        and all(b["result"] in ("yes", "no") for b in record["benign_explanations_checked"]),
    )
    check(
        "no benign explanation held for the finding",
        all(b["result"] == "no" for b in record["benign_explanations_checked"]),
    )
    check(
        "evidence cites tables and row counts",
        len(record["evidence"]) >= 5
        and all({"table", "filter", "rows"} <= set(e) for e in record["evidence"]),
        f"{len(record['evidence'])} items",
    )
    check(
        "record states what the hunt would miss",
        len(record["what_this_hunt_would_miss"]) >= 3,
    )
    check(
        "read-only - no actions taken",
        record["actions_taken"] == [],
    )
    check(
        "ground truth never leaks into the record",
        "_ground_truth" not in json.dumps(record) and "_is_target" not in json.dumps(record),
    )
    check(
        "next pivots hand off to Mission 2",
        any("Mission 2" in p for p in record["next_pivots"]),
    )

    print()
    print("hunt_service_accounts self-test")
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
    parser = argparse.ArgumentParser(description="Mission 1 - hypothesis to evidence.")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--step", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--save", metavar="PATH")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if args.json:
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            record = run(Pacer(fast=True, step=False))
        print(json.dumps(record, indent=2))
    else:
        record = run(Pacer(fast=args.fast, step=args.step))
        print()

    if args.save:
        Path(args.save).write_text(json.dumps(record, indent=2), encoding="utf-8")
        print(f"Record written to {args.save}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
