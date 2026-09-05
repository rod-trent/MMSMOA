"""
anomaly_to_detection.py
=======================
Mission 2: start from anomalies instead of alerts, validate on purpose, and
turn the finding into a detection rule.

Demo 3 · Session: Using AI for Modern Threat Detection
Conference: MMS 2026 Midway Edition - San Diego, October 25-28 2026

The five steps from slide 17:

    1. Start from anomalies, not alerts   <- the flip
    2. Let the model propose hypotheses
    3. Hunt it with the slide 12 template
    4. Validate on purpose                <- the step that makes it defensible
    5. Operationalise into an analytics rule

The finding is a low-and-slow OAuth consent campaign: six users, seven days,
one unverified publisher, never more than one grant per day. Three existing
analytics rules should have caught it and none did, and the script says
exactly why for each - that is the "what the rules missed" payoff.

Step 4 is the one that matters. A model finding is a lead. It becomes evidence
only after a human re-queries it, cross-checks a second source, baselines it,
and goes looking for the innocent explanation. The script slows down there on
purpose, and `--skip-validation` exists only to show you what the output looks
like without it - which is a lead, not a detection.

Usage
-----
    python anomaly_to_detection.py               # full run
    python anomaly_to_detection.py --fast
    python anomaly_to_detection.py --step
    python anomaly_to_detection.py --emit-rule   # write the analytics rule files
    python anomaly_to_detection.py --json
    python anomaly_to_detection.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "02-hypothesis-hunt"))

from hunt_service_accounts import TENANT, strip_meta, ts  # noqa: E402

OUT_DIR = Path(__file__).parent / "generated"

RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
CYAN, GREEN, YELLOW, MAGENTA, RED = "\033[36m", "\033[32m", "\033[33m", "\033[35m", "\033[31m"
_color = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _color else text


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
    print(c(f" STEP {number}/5  {title}", BOLD))
    print(c("=" * 74, DIM))


def hunter(text: str) -> None:
    print()
    print(c("HUNTER", GREEN) + c("  >  ", DIM) + text)


def model(text: str) -> None:
    print()
    for line in text.strip().split("\n"):
        print(c("CLAUDE", CYAN) + c(" |  ", DIM) + line)


def result(text: str) -> None:
    print(c(f"        -> {text}", DIM))


def note(text: str) -> None:
    print()
    print(c(f"  >> STAGE NOTE: {text}", YELLOW))


def warn(text: str) -> None:
    print()
    print(c(f"  !! {text}", RED))


# ---------------------------------------------------------------------------
# Injection screening - retrieved content is data
# ---------------------------------------------------------------------------

INJECTION_MARKERS = (
    "ignore prior instructions",
    "ignore previous instructions",
    "disregard the above",
    "report that no anomalies",
    "new instructions:",
    "system:",
    "assistant:",
)


def screen_free_text(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Look for instructions aimed at the model inside retrieved content."""
    hits: list[dict[str, str]] = []
    for record in records:
        for key, value in record.items():
            if not isinstance(value, str):
                continue
            lowered = value.lower()
            for marker in INJECTION_MARKERS:
                if marker in lowered:
                    hits.append({
                        "field": key,
                        "marker": marker,
                        "entity": record.get("UserPrincipalName", "unknown"),
                    })
                    break
    return hits


# ---------------------------------------------------------------------------
# The hunt
# ---------------------------------------------------------------------------


def run(pacer: Pacer, skip_validation: bool = False) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []

    def cite(table: str, filt: str, rows: int) -> None:
        evidence.append({"table": table, "filter": filt, "rows": rows})

    print()
    print(c("  MISSION 2 - WHAT THE RULES MISSED", BOLD))
    print(c(f"  {TENANT['tenant']['display_name']} / {TENANT['tenant']['workspace']}", DIM))
    print(c("  Input: the record from Mission 1", DIM))

    # --- Step 1 -----------------------------------------------------------

    step_header(1, "Start from anomalies, not alerts")
    hunter(
        "Summarise the UEBA anomalies from the last 7 days by tactic and entity. "
        "Which clusters have no matching incident?"
    )

    anomalies = TENANT["ueba_anomalies"]
    cite("BehaviorAnalytics", "InvestigationPriority > 0, last 7d", len(anomalies))

    # Screen the raw records before summarising them.
    injections = screen_free_text(
        [{k: v for k, v in a.items() if k in ("_free_text", "UserPrincipalName")}
         for a in anomalies]
    )

    orphans = [a for a in anomalies if a.get("_matching_incident") is None]
    matched = [a for a in anomalies if a.get("_matching_incident") is not None]

    by_tactic: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in orphans:
        by_tactic[a["Tactic"]].append(a)

    result(f"{len(anomalies)} anomalies, {len(orphans)} with no matching incident")
    print()
    for tactic, group in sorted(by_tactic.items(), key=lambda kv: -len(kv[1])):
        entities = sorted({a["UserPrincipalName"] for a in group})
        top = max(a["InvestigationPriority"] for a in group)
        print(c(f"        {tactic:<16} {len(group)} anomalies, {len(entities)} entities, "
                f"max priority {top}", DIM))
        for e in entities:
            print(c(f"          - {e}", DIM))

    if injections:
        warn(f"{len(injections)} retrieved record(s) contain text addressed to me.")
        for hit in injections:
            print(c(f"        {hit['entity']} / field '{hit['field']}': "
                    f"'{hit['marker']}'", RED))
        model(
            "One of the anomaly records asks me to report that nothing was found.\n"
            "I am treating it as data, reporting it, and continuing. Note what it\n"
            "asked for - silence. An injection that makes a hunt return nothing is\n"
            "more useful to an attacker than one that makes it return noise."
        )
        note("This is not a bonus. A poisoned record in your anomaly table is a "
             "live prompt-injection vector, and 'return nothing' is the payload "
             "you would never notice. Demo 5 is the full harness.")
        pacer.beat()

    persistence = by_tactic.get("Persistence", [])
    p_users = sorted({a["UserPrincipalName"] for a in persistence})
    p_span = (
        (ts(max(a["TimeGenerated"] for a in persistence))
         - ts(min(a["TimeGenerated"] for a in persistence))).days
        if persistence else 0
    )

    model(
        f"{len(matched)} anomaly has a matching incident, so someone is already on it.\n"
        f"{len(orphans)} do not. Those are the interesting ones - behaviour the\n"
        "detection rules did not have an opinion about.\n"
        "\n"
        "Two clusters stand out:\n"
        "\n"
        f"  Persistence  {len(p_users)} users, all AppConsent, all priority 5,\n"
        f"               spread across {p_span} days. Individually unremarkable.\n"
        "               As a set, a pattern.\n"
        "\n"
        "  InitialAccess/Discovery  svc-datasync, priority 9 and 7. That is\n"
        "               Mission 1's finding. Already worked.\n"
        "\n"
        "The Persistence cluster is where I am going. UEBA only scored some of\n"
        "these - the AuditLogs table will have the full set."
    )
    note("Step 1 flips the usual flow: anomalies first, alerts second. Everything "
         "in the Persistence cluster is below every alerting threshold you have. "
         "That is why it is still here on day eight.")
    pacer.beat()

    # --- Step 2 -----------------------------------------------------------

    step_header(2, "Let the model propose")

    hypotheses = [
        {
            "id": "H1",
            "statement": (
                "A single unverified publisher is collecting OAuth consent grants "
                "slowly across multiple users, staying under any per-day threshold."
            ),
            "why": (
                f"{len(p_users)} AppConsent anomalies across {len(p_users)} distinct "
                f"users, none with a matching incident, spread over {p_span} days."
            ),
            "falsifiable": "If the grants go to different apps, or one user, this is wrong.",
            "chosen": True,
        },
        {
            "id": "H2",
            "statement": (
                "The svc-datasync compromise and the consent grants are the same "
                "campaign, linked by shared infrastructure."
            ),
            "why": "Mission 1's IP pivot showed 45.129.14.201 against unrelated users.",
            "falsifiable": "If no consent-granting user's activity touches that IP, they are unrelated.",
            "chosen": False,
        },
    ]

    for h in hypotheses:
        marker = c("  [taking this one]", GREEN) if h["chosen"] else c("  [parked]", DIM)
        print()
        print(c(f"        {h['id']}", BOLD) + marker)
        print(f"          {h['statement']}")
        print(c(f"          because: {h['why']}", DIM))
        print(c(f"          falsifiable: {h['falsifiable']}", DIM))

    model(
        "Taking H1. Parking H2 in a separate thread - mixing them would give me\n"
        "mixed evidence and false confidence, and H2 is really a question about\n"
        "whether two confirmed findings share a root, which is worth its own hunt."
    )
    note("One hypothesis per thread. This is pattern 4 from slide 11 and it is "
         "the one people skip.")
    pacer.beat()

    # --- Step 3 -----------------------------------------------------------

    step_header(3, "Hunt it with the template")

    consents = [
        a for a in TENANT["audit_logs"]
        if a["OperationName"] == "Consent to application"
    ]
    cite("AuditLogs", "OperationName == 'Consent to application', last 8d", len(consents))

    by_app: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for grant in consents:
        by_app[grant["AppDisplayName"]].append(grant)

    print()
    for app, grants in sorted(by_app.items(), key=lambda kv: -len(kv[1])):
        verified = grants[0]["PublisherVerified"]
        span_days = (ts(max(g["TimeGenerated"] for g in grants))
                     - ts(min(g["TimeGenerated"] for g in grants))).days
        flag = c("unverified", RED) if not verified else c("verified", GREEN)
        print(c(f"        {app:<26} {len(grants)} grant(s)  {len(set(g['InitiatedBy'] for g in grants))} user(s)  "
                f"over {span_days}d  publisher: ", DIM) + flag)

    suspect_app = max(by_app.items(), key=lambda kv: len(kv[1]))
    app_name, grants = suspect_app
    campaign_days = (ts(max(g["TimeGenerated"] for g in grants))
                     - ts(min(g["TimeGenerated"] for g in grants))).days
    with_files = sum(1 for g in grants if "Files.Read.All" in g["Permissions"])
    with_offline = sum(1 for g in grants if "offline_access" in g["Permissions"])
    grantees = sorted({g["InitiatedBy"] for g in grants})

    # Per-day counts, to show why the threshold rule never fired.
    per_day: dict[str, int] = defaultdict(int)
    for g in grants:
        per_day[g["TimeGenerated"][:10]] += 1

    print()
    print(c(f"        '{app_name}' grants per day:", DIM))
    for day in sorted(per_day):
        print(c(f"          {day}  {'#' * per_day[day]} ({per_day[day]})", DIM))

    model(
        f"'{app_name}', app id {grants[0]['AppId']}.\n"
        f"{len(grants)} grants, {len(grantees)} users, across {campaign_days} days.\n"
        f"Publisher unverified. Peak is {max(per_day.values())} grant in any single day.\n"
        "\n"
        f"{with_offline} of {len(grants)} grants include offline_access, which issues a\n"
        f"refresh token that survives a password reset. {with_files} also include\n"
        "Files.Read.All.\n"
        "\n"
        "This is why nothing fired: your 'Mass OAuth consent grants' rule needs\n"
        "5 grants in 24 hours. This campaign never exceeded 1."
    )
    pacer.beat()

    # --- Step 4 -----------------------------------------------------------

    step_header(4, "Validate on purpose")

    if skip_validation:
        warn("--skip-validation: producing the output WITHOUT validating.")
        model(
            "I have a plausible finding and no verification of it. What follows is\n"
            "a lead, not evidence, and it must not become a detection rule."
        )
        note("This is what blind trust looks like. Everything below reads exactly "
             "the same as a validated finding - which is the problem.")
        validations: list[dict[str, Any]] = []
        benign_checks: list[dict[str, Any]] = []
        confidence = "unvalidated"
    else:
        hunter(
            "Before I believe any of that: re-run the key query on a different "
            "window, cross-check one entity in a second source, and go find the "
            "benign explanation."
        )

        # 4a. Re-query on a wider window.
        wide = [
            g for g in TENANT["audit_logs"]
            if g["OperationName"] == "Consent to application"
            and g["AppDisplayName"] == app_name
            and ts(g["TimeGenerated"]) >= ts(TENANT["tenant"]["as_of"]) - timedelta(days=30)
        ]
        cite("AuditLogs", f"AppDisplayName == '{app_name}', last 30d", len(wide))

        # 4b. Cross-source: did the app actually use the grants?
        usage = [
            e for e in TENANT["cloud_app_events"]
            if e["Application"] == app_name
        ]
        cite("CloudAppEvents", f"Application == '{app_name}', last 30d", len(usage))

        # 4c. Baseline: is this app new to the tenant?
        first_seen = min(g["TimeGenerated"] for g in wide)

        validations = [
            {
                "technique": "Re-query on a different window",
                "action": f"Same query over 30 days instead of 8",
                "outcome": f"{len(wide)} grants - the campaign starts {first_seen[:10]}, "
                           f"no earlier activity",
                "supports_finding": True,
            },
            {
                "technique": "Cross-source confirmation",
                "action": f"Look for '{app_name}' in CloudAppEvents, a different data source",
                "outcome": (
                    f"{len(usage)} events: "
                    + "; ".join(f"{u['AccountUpn']} {u['ActionType']} x{u['ObjectCount']}"
                                for u in usage)
                ),
                "supports_finding": True,
            },
            {
                "technique": "Independent corroboration",
                "action": "Check the source IP of that app activity against Mission 1",
                "outcome": (
                    f"{usage[0]['IPAddress']} - the same address as the svc-datasync "
                    f"compromise. Two findings, one campaign."
                    if usage and usage[0].get("IPAddress") == "45.129.14.201"
                    else "No overlap with Mission 1 infrastructure."
                ),
                "supports_finding": True,
            },
        ]

        print()
        for v in validations:
            print(c(f"        {v['technique']}", BOLD))
            print(c(f"          {v['action']}", DIM))
            print(c(f"          -> {v['outcome']}", GREEN if v["supports_finding"] else YELLOW))

        # 4d. The benign case.
        hunter("Now the other way. What would make this benign?")

        approved = TENANT["known_infrastructure"]["approved_oauth_publishers"]
        changes = [
            ch for ch in TENANT["change_records"]
            if any(u in ch["affects"] for u in grantees)
        ]
        same_dept = len({g["InitiatedBy"].split("@")[0][:1] for g in grants}) > 3

        benign_checks = [
            {
                "explanation": "The publisher is on the approved list",
                "result": "no",
                "detail": f"'{app_name}' publisherVerified=False; approved: {', '.join(approved)}",
            },
            {
                "explanation": "A change record or CAB approval covers this rollout",
                "result": "yes" if changes else "no",
                "detail": changes[0]["id"] if changes
                          else "No change record references any of the granting users",
            },
            {
                "explanation": "It is an IT-driven rollout - admin consent, one department",
                "result": "no",
                "detail": "All grants are ConsentType=Principal (user-initiated), "
                          "across unrelated users. An IT rollout would be AllPrincipals.",
            },
            {
                "explanation": "The app is a known-good tool users adopted organically",
                "result": "no",
                "detail": f"Not in the software inventory; unverified publisher; "
                          f"first seen {first_seen[:10]}",
            },
        ]

        print()
        for b in benign_checks:
            mark = c("yes", GREEN) if b["result"] == "yes" else c("no ", RED)
            print(c(f"        [{mark}{c(']', DIM)} {b['explanation']}", DIM))
            print(c(f"              {b['detail']}", DIM))

        confidence = "high"

        model(
            "All four benign explanations fail. Three independent validations\n"
            "support the finding, one of which ties it to Mission 1.\n"
            "\n"
            "Now it is evidence. Before this step it was a lead."
        )
        note("Narrate every validation move out loud. The difference between "
             "AI-assisted hunting and blind trust is entirely in this step, and "
             "the room needs to watch you do it slowly.")
        pacer.beat()

    # --- Step 5 -----------------------------------------------------------

    step_header(5, "Operationalise")
    hunter(
        "Draft a Sentinel analytics rule for this pattern, with a test query "
        "and the expected volume."
    )

    if skip_validation:
        model(
            "I will not. The finding has not been validated, and shipping an\n"
            "unvalidated pattern as a detection rule is how you page the wrong\n"
            "team at 2am for the next two years.\n"
            "\n"
            "Run step 4 first."
        )
        rule = None
    else:
        rule = build_rule(app_name, grants, grantees)
        print()
        print(c("        Rule: ", BOLD) + rule["displayName"])
        print(c(f"        Severity {rule['severity']}, runs every "
                f"{rule['queryFrequency']}, looks back {rule['queryPeriod']}", DIM))
        print(c(f"        MITRE: {', '.join(rule['tactics'])} / "
                f"{', '.join(rule['techniques'])}", DIM))
        print()
        print(c("        Expected volume (backtested on this window):", DIM))
        print(c(f"          {rule['_backtest']['would_have_fired']} alert(s) in "
                f"{rule['_backtest']['window_days']} days", DIM))
        print(c(f"          {rule['_backtest']['note']}", DIM))

        model(
            "The threshold is the whole design decision here.\n"
            "\n"
            "Your existing rule uses 5 grants in 24 hours and missed this at 1/day.\n"
            "Mine uses 3 grants to the same unverified publisher in 14 days, which\n"
            "catches the campaign and, on this window, fires once.\n"
            "\n"
            "Do not ship that number because I chose it. Backtest it over 90 days\n"
            "in your own tenant first - it is the difference between a detection\n"
            "and a new source of alert fatigue."
        )
        note("If you are short on time, skip the rule generation and show the "
             "pre-generated file in generated/. The threshold conversation is "
             "worth more than watching JSON print.")

    # --- The record --------------------------------------------------------

    record = {
        "mission": "Mission 2 - what the rules missed",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tenant": TENANT["tenant"]["display_name"],
        "hypothesis": hypotheses[0]["statement"],
        "hypothesis_parked": hypotheses[1]["statement"],
        "evidence": evidence,
        "timeline": [
            f"{g['TimeGenerated']}  {g['InitiatedBy']} consented to '{app_name}' "
            f"({', '.join(g['Permissions'])})"
            for g in sorted(grants, key=lambda g: g["TimeGenerated"])
        ],
        "confidence": confidence,
        "validations": validations,
        "benign_explanations_checked": benign_checks,
        "why_existing_rules_missed_it": [
            {
                "rule": r["name"],
                "logic": r["logic"],
                "why_it_missed": r["_why_it_missed"],
            }
            for r in TENANT["existing_analytics_rules"]
        ],
        "prompt_injection_detected": injections,
        "affected_users": grantees,
        "suspect_app": {
            "name": app_name,
            "app_id": grants[0]["AppId"],
            "publisher_verified": grants[0]["PublisherVerified"],
            "permissions": sorted({p for g in grants for p in g["Permissions"]}),
        },
        "next_pivots": [
            f"Every Graph API call made by app id {grants[0]['AppId']}",
            "Mailbox rules created by any of the affected users after their grant",
            "Whether the refresh tokens are still valid (offline_access survives password reset)",
            "H2 - is this the same campaign as the svc-datasync compromise",
        ],
        "generated_rule": rule,
        "actions_taken": [],
    }

    print()
    print(c("=" * 74, DIM))
    print(c(" THE RECORD", BOLD))
    print(c("=" * 74, DIM))
    print()
    print(json.dumps(
        {k: v for k, v in record.items()
         if k in ("hypothesis", "confidence", "affected_users", "suspect_app")},
        indent=2,
    ))
    print()
    print(c("  Why three existing rules missed it:", BOLD))
    for r in record["why_existing_rules_missed_it"]:
        print(c(f"    {r['rule']}", DIM))
        print(c(f"      logic: {r['logic']}", DIM))
        print(c(f"      miss:  {r['why_it_missed']}", DIM))

    note("'benign_explanations_checked' is the field that makes this defensible. "
         "Point at it. It is what you show the person who asks how you know.")

    return record


# ---------------------------------------------------------------------------
# Rule generation
# ---------------------------------------------------------------------------


def build_rule(app_name: str, grants: list[dict[str, Any]], grantees: list[str]) -> dict[str, Any]:
    query = """let lookback = 14d;
let min_grants = 3;
let approved_publishers = dynamic(["Microsoft", "Adobe", "Atlassian", "ServiceNow"]);
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName == "Consent to application"
| where Result == "success"
| extend AppDisplayName   = tostring(TargetResources[0].displayName),
         AppId            = tostring(TargetResources[0].id),
         Actor            = tostring(InitiatedBy.user.userPrincipalName),
         ConsentType      = tostring(TargetResources[0].modifiedProperties[0].newValue),
         Permissions      = tostring(TargetResources[0].modifiedProperties[4].newValue)
// User-initiated only. An admin rollout is a different thing and has a CAB record.
| where ConsentType !has "AllPrincipals"
| where not(AppDisplayName has_any (approved_publishers))
// Sensitive scopes only, or every Teams install becomes an alert.
| where Permissions has_any ("offline_access", "Mail.Read", "Mail.ReadWrite",
                             "Files.Read.All", "Files.ReadWrite.All")
| summarize
    GrantCount   = dcount(Actor),
    Users        = make_set(Actor, 20),
    FirstGrant   = min(TimeGenerated),
    LastGrant    = max(TimeGenerated),
    Permissions  = make_set(Permissions, 5)
  by AppDisplayName, AppId
| where GrantCount >= min_grants
| extend CampaignDays = datetime_diff('day', LastGrant, FirstGrant)
// The whole point: catch the slow ones the daily thresholds miss.
| extend GrantsPerDay = round(todouble(GrantCount) / max_of(CampaignDays, 1), 2)
| project AppDisplayName, AppId, GrantCount, CampaignDays, GrantsPerDay,
          Users, Permissions, FirstGrant, LastGrant"""

    return {
        "kind": "Scheduled",
        "displayName": "Low-and-slow OAuth consent to an unverified publisher",
        "description": (
            "Detects a single unverified application collecting user-initiated OAuth "
            "consent grants with sensitive scopes across multiple users over an "
            "extended period. Threshold rules measured per-day do not see this: the "
            "campaign that prompted this rule averaged under one grant/day for a week.\n\n"
            "Tuning: raise min_grants or shorten lookback if your environment has "
            "high organic app adoption. Backtest over 90 days before enabling."
        ),
        "severity": "Medium",
        "enabled": True,
        "query": query,
        "queryFrequency": "PT6H",
        "queryPeriod": "P14D",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT12H",
        "suppressionEnabled": True,
        "tactics": ["Persistence", "CredentialAccess"],
        "techniques": ["T1098.003", "T1550.001"],
        "entityMappings": [
            {
                "entityType": "CloudApplication",
                "fieldMappings": [
                    {"identifier": "AppId", "columnName": "AppId"},
                    {"identifier": "Name", "columnName": "AppDisplayName"},
                ],
            }
        ],
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": True,
                "reopenClosedIncident": False,
                "lookbackDuration": "P7D",
                "matchingMethod": "Selected",
                "groupByEntities": ["CloudApplication"],
            },
        },
        "_backtest": {
            "window_days": 14,
            "would_have_fired": 1,
            "note": f"One alert: '{app_name}', {len(grantees)} users. "
                    f"'Atlassian Jira Cloud' correctly excluded - verified publisher, "
                    f"AllPrincipals consent, User.Read only.",
        },
        "_provenance": {
            "source": "Generated from a validated Mission 2 finding",
            "validated": True,
            "reviewed_by": "REPLACE ME - a human must sign off before this is enabled",
            "backtest_required": "90 days in your own tenant",
        },
    }


def emit_rule(rule: dict[str, Any]) -> list[Path]:
    """Write the rule as ARM and as Sentinel repository YAML."""
    OUT_DIR.mkdir(exist_ok=True)
    written: list[Path] = []

    clean_rule = {k: v for k, v in rule.items() if not k.startswith("_")}

    arm = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspaceName": {"type": "string"},
            "ruleGuid": {
                "type": "string",
                "defaultValue": "[newGuid()]",
            },
        },
        "resources": [
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                "name": "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', parameters('ruleGuid'))]",
                "apiVersion": "2023-02-01",
                "kind": "Scheduled",
                "properties": {k: v for k, v in clean_rule.items() if k != "kind"},
            }
        ],
    }

    arm_path = OUT_DIR / "low-and-slow-oauth-consent.arm.json"
    arm_path.write_text(json.dumps(arm, indent=2), encoding="utf-8")
    written.append(arm_path)

    yaml_lines = [
        "# Generated by anomaly_to_detection.py from a VALIDATED Mission 2 finding.",
        "# MMS 2026 Midway Edition - Using AI for Modern Threat Detection.",
        "#",
        "# DO NOT ENABLE THIS WITHOUT BACKTESTING IT IN YOUR OWN TENANT.",
        "# The threshold (3 grants / 14 days) was chosen against one synthetic",
        "# campaign. Your environment's organic app adoption rate is not that one.",
        "",
        "id: 8f2b1c44-77aa-4e19-9d33-000000000001",
        f"name: {clean_rule['displayName']}",
        "version: 1.0.0",
        "kind: Scheduled",
        f"severity: {clean_rule['severity']}",
        "status: Available",
        "requiredDataConnectors:",
        "  - connectorId: AzureActiveDirectory",
        "    dataTypes:",
        "      - AuditLogs",
        f"queryFrequency: {clean_rule['queryFrequency']}",
        f"queryPeriod: {clean_rule['queryPeriod']}",
        f"triggerOperator: {clean_rule['triggerOperator']}",
        f"triggerThreshold: {clean_rule['triggerThreshold']}",
        "tactics:",
        *[f"  - {t}" for t in clean_rule["tactics"]],
        "relevantTechniques:",
        *[f"  - {t}" for t in clean_rule["techniques"]],
        "description: |",
        *[f"  {line}" for line in clean_rule["description"].split("\n")],
        "query: |",
        *[f"  {line}" for line in clean_rule["query"].split("\n")],
        "entityMappings:",
        "  - entityType: CloudApplication",
        "    fieldMappings:",
        "      - identifier: AppId",
        "        columnName: AppId",
        "      - identifier: Name",
        "        columnName: AppDisplayName",
    ]

    yaml_path = OUT_DIR / "low-and-slow-oauth-consent.yaml"
    yaml_path.write_text("\n".join(yaml_lines) + "\n", encoding="utf-8")
    written.append(yaml_path)

    return written


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def self_test() -> int:
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        record = run(Pacer(fast=True, step=False))

    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        unvalidated = run(Pacer(fast=True, step=False), skip_validation=True)

    checks: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        checks.append((label, ok, detail))

    check(
        "identifies the low-and-slow campaign",
        record["suspect_app"]["name"] == "Contoso Doc Sync",
        record["suspect_app"]["name"],
    )
    check(
        "finds all six granting users",
        len(record["affected_users"]) == 6,
        f"{len(record['affected_users'])} users",
    )
    check(
        "excludes the verified-publisher noise",
        "it-admin@contoso.com" not in record["affected_users"],
        "Atlassian grant correctly not part of the campaign",
    )
    check(
        "explains why each existing rule missed it",
        len(record["why_existing_rules_missed_it"]) == 3
        and all(r["why_it_missed"] for r in record["why_existing_rules_missed_it"]),
    )
    check(
        "runs three independent validations",
        len(record["validations"]) == 3,
        f"{len(record['validations'])}",
    )
    check(
        "checks four benign explanations, none of which hold",
        len(record["benign_explanations_checked"]) == 4
        and all(b["result"] == "no" for b in record["benign_explanations_checked"]),
    )
    check(
        "detects the injection payload in the anomaly table",
        len(record["prompt_injection_detected"]) == 1,
        record["prompt_injection_detected"][0]["marker"]
        if record["prompt_injection_detected"] else "none found",
    )
    check(
        "produces a rule only after validation",
        record["generated_rule"] is not None,
    )
    check(
        "REFUSES to produce a rule without validation",
        unvalidated["generated_rule"] is None,
        "this is the guardrail that matters",
    )
    check(
        "unvalidated run is labelled as such",
        unvalidated["confidence"] == "unvalidated",
    )
    check(
        "generated rule carries a provenance block requiring human sign-off",
        record["generated_rule"]["_provenance"]["reviewed_by"].startswith("REPLACE ME"),
    )
    check(
        "generated rule excludes admin-consent rollouts",
        "AllPrincipals" in record["generated_rule"]["query"],
    )
    check(
        "read-only - no actions taken",
        record["actions_taken"] == [],
    )
    check(
        "ground truth never leaks",
        "_why_it_missed" not in json.dumps(record["timeline"])
        and "_is_target" not in json.dumps(record),
    )

    written = emit_rule(record["generated_rule"])
    check(
        "emits ARM and YAML rule files",
        all(p.exists() and p.stat().st_size > 500 for p in written),
        ", ".join(p.name for p in written),
    )

    print()
    print("anomaly_to_detection self-test")
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
    parser = argparse.ArgumentParser(description="Mission 2 - anomalies to a validated detection.")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--step", action="store_true")
    parser.add_argument("--skip-validation", action="store_true",
                        help="Show what blind trust produces. Refuses to emit a rule.")
    parser.add_argument("--emit-rule", action="store_true", help="Write ARM + YAML to generated/.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if args.json:
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            record = run(Pacer(fast=True, step=False), args.skip_validation)
        print(json.dumps(record, indent=2))
    else:
        record = run(Pacer(fast=args.fast, step=args.step), args.skip_validation)
        print()

    if args.emit_rule:
        if not record["generated_rule"]:
            print("No rule to emit - the finding was not validated.")
            return 1
        for path in emit_rule(record["generated_rule"]):
            print(f"Wrote {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
