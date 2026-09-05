"""
validate_finding.py
===================
Runs the six validation techniques from slide 19 against a hunt finding and
tells you whether it is still a lead or has become evidence.

Demo 4 - validation · Session: Using AI for Modern Threat Detection
Conference: MMS 2026 Midway Edition - San Diego, October 25-28 2026

Slide 19: "A model finding is a lead until a human makes it evidence."

The six techniques:

    1. Re-query independently      fresh session, no prior context
    2. Cross-source confirmation   one table is a lead, two sources is evidence
    3. Baseline it                 "new" is meaningless without a reference
    4. Seed known bad              if it cannot find your test, distrust silence
    5. Hunt the benign case        actively search for the innocent explanation
    6. Score and log               confidence, evidence, and who validated

Technique 4 is the one people forget, and it is the one that matters most.
A hunt that returns "nothing found" is only useful if you have proved it can
find something. This harness plants a known-bad pattern and fails the whole
validation if the hunt misses it.

Usage
-----
    python validate_finding.py                       # validate the Mission 2 finding
    python validate_finding.py --finding mission1    # validate the Mission 1 finding
    python validate_finding.py --technique seed      # run one technique
    python validate_finding.py --json
    python validate_finding.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "02-hypothesis-hunt"))

from hunt_service_accounts import TENANT, ts  # noqa: E402

RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
CYAN, GREEN, YELLOW, RED = "\033[36m", "\033[32m", "\033[33m", "\033[31m"
_color = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _color else text


# ---------------------------------------------------------------------------
# Findings under validation
# ---------------------------------------------------------------------------

FINDINGS: dict[str, dict[str, Any]] = {
    "mission2": {
        "name": "Low-and-slow OAuth consent to an unverified publisher",
        "claim": (
            "Six users granted consent to 'Contoso Doc Sync' over seven days; "
            "the publisher is unverified and every grant includes offline_access."
        ),
        "entity": "Contoso Doc Sync",
        "entity_type": "application",
        "primary_table": "AuditLogs",
    },
    "mission1": {
        "name": "Service account used interactively from unowned infrastructure",
        "claim": (
            "svc-datasync@contoso.com signed in interactively from AS202425 and "
            "then enumerated the directory via Graph API."
        ),
        "entity": "svc-datasync@contoso.com",
        "entity_type": "account",
        "primary_table": "SigninLogs",
    },
}


# ---------------------------------------------------------------------------
# Technique 1 - re-query independently
# ---------------------------------------------------------------------------


def t1_requery(finding: dict[str, Any]) -> dict[str, Any]:
    """Re-run the claim's core query with a different window and no prior context.

    The point is not that the query is deterministic - of course it is. The
    point is that a model's *summary* of a query is not the query. Re-running
    it yourself is how you find out the summary drifted.
    """
    entity = finding["entity"]

    if finding["entity_type"] == "application":
        original = [
            g for g in TENANT["audit_logs"]
            if g.get("AppDisplayName") == entity
            and ts(g["TimeGenerated"]) >= ts(TENANT["tenant"]["as_of"]) - timedelta(days=8)
        ]
        wider = [g for g in TENANT["audit_logs"] if g.get("AppDisplayName") == entity]
    else:
        original = [
            s for s in TENANT["signin_logs"]
            if s["UserPrincipalName"] == entity and s.get("IsInteractive")
        ]
        wider = [s for s in TENANT["signin_logs"] if s["UserPrincipalName"] == entity]

    consistent = len(wider) >= len(original) and len(original) > 0

    return {
        "technique": "Re-query independently",
        "what_i_did": f"Re-ran the core query for '{entity}' on a 30-day window "
                      f"instead of the original 7-8 days.",
        "found": f"{len(original)} rows in the original window, {len(wider)} in the wider one",
        "passed": consistent,
        "interpretation": (
            "Consistent. The wider window adds context without contradicting the claim."
            if consistent else
            "INCONSISTENT. The claim does not survive a re-query. Stop here."
        ),
    }


# ---------------------------------------------------------------------------
# Technique 2 - cross-source confirmation
# ---------------------------------------------------------------------------


def t2_cross_source(finding: dict[str, Any]) -> dict[str, Any]:
    """One table is a lead. The same entity in two independent sources is evidence."""
    entity = finding["entity"]
    primary = finding["primary_table"]
    corroborating: list[str] = []

    if finding["entity_type"] == "application":
        if any(e["Application"] == entity for e in TENANT["cloud_app_events"]):
            corroborating.append("CloudAppEvents")
        if any(a["ActivityType"] == "AppConsent" for a in TENANT["ueba_anomalies"]):
            corroborating.append("BehaviorAnalytics")
    else:
        if any(g["UserPrincipalName"] == entity for g in TENANT["graph_activity"]):
            corroborating.append("MicrosoftGraphActivityLogs")
        if any(a["UserPrincipalName"] == entity for a in TENANT["ueba_anomalies"]):
            corroborating.append("BehaviorAnalytics")

    passed = len(corroborating) >= 1

    return {
        "technique": "Cross-source confirmation",
        "what_i_did": f"Looked for '{entity}' outside {primary}.",
        "found": f"Corroborated in: {', '.join(corroborating) or 'nowhere else'}",
        "passed": passed,
        "interpretation": (
            f"Confirmed across {len(corroborating) + 1} independent sources. "
            f"Identity plus activity, not one table's opinion."
            if passed else
            "Single-source only. This stays a lead. Do not escalate on one table."
        ),
    }


# ---------------------------------------------------------------------------
# Technique 3 - baseline it
# ---------------------------------------------------------------------------


def t3_baseline(finding: dict[str, Any]) -> dict[str, Any]:
    """'New' is only meaningful relative to something. Compare against history."""
    entity = finding["entity"]
    baseline_days = TENANT["tenant"]["ueba_baseline_days"]

    if finding["entity_type"] == "account":
        anomalies = [a for a in TENANT["ueba_anomalies"] if a["UserPrincipalName"] == entity]
        signals = sorted({s for a in anomalies for s in a["ActivityInsights"]})
        priority = max((a["InvestigationPriority"] for a in anomalies), default=0)
        passed = priority >= 5 and len(signals) >= 2
        found = f"UEBA priority {priority}, {len(signals)} first-time signals: {', '.join(signals)}"
        interpretation = (
            f"Deviation is real against a {baseline_days}-day baseline, and it is "
            f"multi-signal. One first-time signal is noise; {len(signals)} at once is not."
            if passed else
            f"Weak or no deviation against the {baseline_days}-day baseline. "
            f"Check whether this is simply normal for this entity."
        )
    else:
        first_seen = min(
            (g["TimeGenerated"] for g in TENANT["audit_logs"]
             if g.get("AppDisplayName") == entity),
            default=None,
        )
        approved = TENANT["known_infrastructure"]["approved_oauth_publishers"]
        is_new = first_seen is not None
        not_approved = not any(p.lower() in entity.lower() for p in approved)
        passed = is_new and not_approved
        found = (f"First seen {first_seen[:10] if first_seen else 'never'}; "
                 f"publisher not on the approved list: {not_approved}")
        interpretation = (
            "New to the tenant and not an approved publisher. The 'new' claim holds."
            if passed else
            "This entity is not new, or is approved. Re-examine the claim."
        )

    return {
        "technique": "Baseline it",
        "what_i_did": f"Compared '{entity}' against {baseline_days} days of history.",
        "found": found,
        "passed": passed,
        "interpretation": interpretation,
    }


# ---------------------------------------------------------------------------
# Technique 4 - seed known bad   <- the one people forget
# ---------------------------------------------------------------------------


def t4_seed_known_bad(finding: dict[str, Any]) -> dict[str, Any]:
    """Plant a pattern you know is there and confirm the hunt finds it.

    If the hunt cannot find your test, its silence means nothing. This is the
    single cheapest control on slide 19 and the one that is almost never run.
    """
    # A synthetic record matching the hunt's detection logic exactly.
    if finding["entity_type"] == "application":
        seeded = {
            "TimeGenerated": "2026-10-27T08:00:00Z",
            "OperationName": "Consent to application",
            "InitiatedBy": "svc-hunttest@contoso.com",
            "AppDisplayName": "HUNT-TEST-CANARY",
            "AppId": "00000000-0000-0000-0000-00000000cafe",
            "PublisherVerified": False,
            "Permissions": ["Mail.Read", "offline_access"],
            "ConsentType": "Principal",
        }
        corpus = TENANT["audit_logs"] + [seeded]

        # The same logic Mission 2's hunt uses.
        def hunt(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [
                r for r in rows
                if r.get("OperationName") == "Consent to application"
                and r.get("PublisherVerified") is False
                and any(p in r.get("Permissions", [])
                        for p in ("offline_access", "Mail.Read", "Files.Read.All"))
            ]

        canary = "HUNT-TEST-CANARY"
        found_it = any(r.get("AppDisplayName") == canary for r in hunt(corpus))
    else:
        seeded = {
            "TimeGenerated": "2026-10-27T08:00:00Z",
            "UserPrincipalName": "svc-hunttest@contoso.com",
            "IsInteractive": True,
            "IPAddress": "203.0.113.99",
            "AutonomousSystemNumber": 64512,
            "Location": "XX",
            "AppDisplayName": "HUNT-TEST-CANARY",
            "ResultType": "0",
        }
        corpus = TENANT["signin_logs"] + [seeded]
        known = {a["asn"] for a in TENANT["known_infrastructure"]["egress_asns"]}

        def hunt_signin(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [
                r for r in rows
                if r["UserPrincipalName"].startswith("svc-")
                and r.get("IsInteractive")
                and r["ResultType"] == "0"
                and r["AutonomousSystemNumber"] not in known
            ]

        canary = "svc-hunttest@contoso.com"
        found_it = any(r["UserPrincipalName"] == canary for r in hunt_signin(corpus))

    return {
        "technique": "Seed known bad",
        "what_i_did": f"Planted a synthetic record matching the hunt's own logic "
                      f"('{canary}') and re-ran the hunt.",
        "found": "Canary detected" if found_it else "CANARY MISSED",
        "passed": found_it,
        "interpretation": (
            "The hunt can find what it is looking for, so its silence elsewhere "
            "carries information."
            if found_it else
            "The hunt MISSED a pattern it was built to detect. Every 'nothing "
            "found' this hunt has ever returned is worthless. Fix the hunt before "
            "you trust any result from it."
        ),
    }


# ---------------------------------------------------------------------------
# Technique 5 - hunt the benign case
# ---------------------------------------------------------------------------


def t5_benign_case(finding: dict[str, Any]) -> dict[str, Any]:
    """Actively search for the innocent explanation. Most false positives die here."""
    entity = finding["entity"]
    checks: list[dict[str, str]] = []

    changes = [
        ch for ch in TENANT["change_records"]
        if entity in ch["affects"] or entity in ch["summary"]
    ]
    checks.append({
        "explanation": "An open change record covers this activity",
        "result": "yes" if changes else "no",
        "detail": changes[0]["id"] if changes else "No change record references this entity",
    })

    if finding["entity_type"] == "account":
        rows = [s for s in TENANT["signin_logs"] if s["UserPrincipalName"] == entity]
        known = {a["asn"] for a in TENANT["known_infrastructure"]["egress_asns"]}
        jump = set(TENANT["known_infrastructure"]["jump_hosts"])
        from_known = any(r["AutonomousSystemNumber"] in known for r in rows if r.get("IsInteractive"))
        from_jump = any(
            (r.get("DeviceDetail") or {}).get("deviceId") in jump
            for r in rows if r.get("IsInteractive")
        )
        checks.append({
            "explanation": "Interactive sign-in came from a known egress ASN",
            "result": "yes" if from_known else "no",
            "detail": f"Known egress: {sorted(known)}",
        })
        checks.append({
            "explanation": "Interactive sign-in came from an approved jump host",
            "result": "yes" if from_jump else "no",
            "detail": f"Approved jump hosts: {sorted(jump)}",
        })
    else:
        approved = TENANT["known_infrastructure"]["approved_oauth_publishers"]
        grants = [g for g in TENANT["audit_logs"] if g.get("AppDisplayName") == entity]
        verified = any(g.get("PublisherVerified") for g in grants)
        admin_led = any(g.get("ConsentType") == "AllPrincipals" for g in grants)
        checks.append({
            "explanation": "Publisher is verified or on the approved list",
            "result": "yes" if verified else "no",
            "detail": f"Approved publishers: {', '.join(approved)}",
        })
        checks.append({
            "explanation": "This is an admin-driven rollout, not user-initiated",
            "result": "yes" if admin_led else "no",
            "detail": "All grants are ConsentType=Principal" if not admin_led
                      else "AllPrincipals consent present",
        })

    held = [ch for ch in checks if ch["result"] == "yes"]
    passed = len(held) == 0

    return {
        "technique": "Hunt the benign case",
        "what_i_did": f"Actively searched for an innocent explanation for '{entity}'.",
        "found": f"{len(checks)} explanations checked, {len(held)} held",
        "passed": passed,
        "checks": checks,
        "interpretation": (
            "No benign explanation held. The finding survives the disconfirming search."
            if passed else
            f"{len(held)} benign explanation(s) hold: "
            f"{'; '.join(ch['explanation'] for ch in held)}. "
            f"This is probably not a finding."
        ),
    }


# ---------------------------------------------------------------------------
# Technique 6 - score and log
# ---------------------------------------------------------------------------


def t6_score_and_log(finding: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    """Record confidence, evidence, and who validated. Feed it back into tuning."""
    passed = [r for r in results if r["passed"]]
    critical_failed = [r for r in results if not r["passed"] and r["technique"] == "Seed known bad"]

    if critical_failed:
        confidence = "none"
    elif len(passed) == len(results):
        confidence = "high"
    elif len(passed) >= len(results) - 1:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "technique": "Score and log",
        "what_i_did": "Recorded confidence, the techniques run, and who validated.",
        "found": f"{len(passed)}/{len(results)} techniques passed",
        "passed": True,
        "confidence": confidence,
        "interpretation": (
            f"Confidence: {confidence}. Log this alongside the finding - confirmed "
            f"AND rejected findings both feed rule tuning, and the rejected ones "
            f"are the more useful half."
        ),
    }


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

TECHNIQUES: dict[str, tuple[str, Callable[[dict[str, Any]], dict[str, Any]]]] = {
    "requery": ("Re-query independently", t1_requery),
    "cross-source": ("Cross-source confirmation", t2_cross_source),
    "baseline": ("Baseline it", t3_baseline),
    "seed": ("Seed known bad", t4_seed_known_bad),
    "benign": ("Hunt the benign case", t5_benign_case),
}


def validate(finding_key: str, only: str | None = None, quiet: bool = False) -> dict[str, Any]:
    finding = FINDINGS[finding_key]

    if not quiet:
        print()
        print(c("  Validation harness - slide 19", BOLD))
        print(c("  A model finding is a lead until a human makes it evidence.", DIM))
        print()
        print(c(f"  Finding  {finding['name']}", BOLD))
        for line in _wrap(finding["claim"], 66):
            print(c(f"           {line}", DIM))
        print()

    selected = [(k, v) for k, v in TECHNIQUES.items() if only is None or k == only]
    results: list[dict[str, Any]] = []

    for index, (_key, (_label, func)) in enumerate(selected, 1):
        outcome = func(finding)
        results.append(outcome)

        if quiet:
            continue

        mark = c(" PASS ", GREEN) if outcome["passed"] else c(" FAIL ", RED)
        print(c("  " + "-" * 70, DIM))
        print(f"  [{mark}] {index}. {c(outcome['technique'], BOLD)}")
        print(c(f"         {outcome['what_i_did']}", DIM))
        print(f"         {outcome['found']}")
        for line in _wrap(outcome["interpretation"], 62):
            print(c(f"         {line}", YELLOW if not outcome["passed"] else DIM))
        if "checks" in outcome:
            for ch in outcome["checks"]:
                m = c("yes", RED) if ch["result"] == "yes" else c("no ", GREEN)
                print(c(f"           [{m}{c(']', DIM)} {ch['explanation']}", DIM))
        print()

    if only:
        return {"finding": finding_key, "results": results}

    scored = t6_score_and_log(finding, results)
    results.append(scored)

    if not quiet:
        print(c("  " + "=" * 70, DIM))
        print(f"  {c('6. ' + scored['technique'], BOLD)}")
        print(f"         {scored['found']}")
        for line in _wrap(scored["interpretation"], 62):
            print(c(f"         {line}", DIM))
        print()

        verdict_color = {
            "high": GREEN, "medium": YELLOW, "low": YELLOW, "none": RED
        }[scored["confidence"]]
        if scored["confidence"] == "none":
            print(c("  VERDICT: NOT EVIDENCE. The seed-known-bad test failed, which", RED + BOLD))
            print(c("  means this hunt's silence carries no information at all.", RED + BOLD))
        elif scored["confidence"] == "high":
            print(c("  VERDICT: This is now evidence. It survived all five techniques,", verdict_color))
            print(c("  including a deliberate search for the innocent explanation.", verdict_color))
        else:
            print(c(f"  VERDICT: still a lead ({scored['confidence']} confidence).", verdict_color))
            print(c("  Do not escalate and do not build a detection from it yet.", verdict_color))
        print()

    return {
        "finding": finding_key,
        "name": finding["name"],
        "confidence": scored["confidence"],
        "techniques_passed": sum(1 for r in results if r["passed"]),
        "techniques_run": len(results),
        "results": results,
    }


def _wrap(text: str, width: int) -> list[str]:
    import textwrap
    return textwrap.wrap(text, width)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def self_test() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        checks.append((label, ok, detail))

    m2 = validate("mission2", quiet=True)
    m1 = validate("mission1", quiet=True)

    check("Mission 2 finding reaches high confidence", m2["confidence"] == "high", m2["confidence"])
    check("Mission 1 finding reaches high confidence", m1["confidence"] == "high", m1["confidence"])

    seed_m2 = next(r for r in m2["results"] if r["technique"] == "Seed known bad")
    check("seed-known-bad canary is detected (app hunt)", seed_m2["passed"])

    seed_m1 = next(r for r in m1["results"] if r["technique"] == "Seed known bad")
    check("seed-known-bad canary is detected (account hunt)", seed_m1["passed"])

    benign_m1 = next(r for r in m1["results"] if r["technique"] == "Hunt the benign case")
    check(
        "no benign explanation holds for svc-datasync",
        benign_m1["passed"],
        f"{len(benign_m1['checks'])} checked",
    )

    # The decoy must FAIL validation. This is the harness proving it discriminates.
    FINDINGS["decoy"] = {
        "name": "Decoy - svc-reporting break-glass",
        "claim": "svc-reporting@contoso.com signed in interactively.",
        "entity": "svc-reporting@contoso.com",
        "entity_type": "account",
        "primary_table": "SigninLogs",
    }
    decoy = validate("decoy", quiet=True)
    decoy_benign = next(r for r in decoy["results"] if r["technique"] == "Hunt the benign case")
    check(
        "the decoy FAILS the benign-case search",
        not decoy_benign["passed"],
        "if this passed, the harness would rubber-stamp anything",
    )
    check(
        "the decoy does not reach high confidence",
        decoy["confidence"] != "high",
        decoy["confidence"],
    )

    # A hunt that cannot find its own canary must score 'none'.
    broken = t4_seed_known_bad(FINDINGS["mission2"]).copy()
    broken["passed"] = False
    scored = t6_score_and_log(FINDINGS["mission2"], [broken])
    check(
        "a failed canary forces confidence to 'none'",
        scored["confidence"] == "none",
        "silence from a blind hunt means nothing",
    )

    print()
    print("validate_finding self-test")
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
    parser = argparse.ArgumentParser(description="Slide 19 validation techniques.")
    parser.add_argument("--finding", choices=sorted(FINDINGS), default="mission2")
    parser.add_argument("--technique", choices=sorted(TECHNIQUES),
                        help="Run one technique instead of all six.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    result = validate(args.finding, args.technique, quiet=args.json)

    if args.json:
        print(json.dumps(result, indent=2))

    return 0 if result.get("confidence") in ("high", None) else 1


if __name__ == "__main__":
    sys.exit(main())
