"""
soc_triage_agent.py
===================
A triage agent that works an incident end to end, then stops and asks before
it acts.

Demo 3, Mission 2 - "Auto-Triage + HITL"
Session:    Empowering SOC Teams
Conference: MMS 2026 Midway Edition - San Diego, October 25-28 2026

The loop is the one on slide 16:

    Ingest -> Correlate -> Enrich -> Reason -> [APPROVE] -> Act

The amber stage is the point of the whole demo. Approval is a stage in the
pipeline, not a courtesy bolted on afterwards. The agent physically cannot
reach Act without passing through it, and that is enforced in code below
(see ApprovalGate and _act), not by convention.

What is real and what is scripted
---------------------------------
Real: the tool calls, the correlation, the scoring, the guardrails, the
      approval gate, the run log, the JSON contract.
Scripted: the reasoning narration. A live model picks its own words; a stage
      demo needs a known script and a known runtime.

Swap _reason() for a real model call (Claude Agent SDK, Security Copilot, or
Copilot Studio) and nothing else in this file changes. That is deliberate -
the shape is the product, not the model.

Usage
-----
    python soc_triage_agent.py                    # interactive approval gate
    python soc_triage_agent.py --auto-approve     # unattended, for CI
    python soc_triage_agent.py --reject           # scripted rejection + re-plan
    python soc_triage_agent.py --incident 48176   # the injection payload
    python soc_triage_agent.py --json             # machine-readable only
    python soc_triage_agent.py --self-test        # verify the guardrails hold

On stage: run it once clean, then run it again with the rejection. The second
run answers most of the "but what about control" questions before they are
asked.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# Reuse the replay tool layer from Demo 2 - same data, same guardrails.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "02-natural-language-triage"))

from replay_mcp_server import (  # noqa: E402
    TENANT,
    UNTRUSTED_CLOSE,
    UNTRUSTED_OPEN,
    call_tool,
)

RUN_LOG = Path(__file__).parent / "runs"

# ---------------------------------------------------------------------------
# Terminal formatting
# ---------------------------------------------------------------------------

RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
CYAN, GREEN, YELLOW, MAGENTA, RED = "\033[36m", "\033[32m", "\033[33m", "\033[35m", "\033[31m"

_color = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _color else text


def plain(value: Any) -> Any:
    """Strip untrusted-data markers for display. Rendering is not obeying."""
    if isinstance(value, str):
        return value.replace(UNTRUSTED_OPEN, "").replace(UNTRUSTED_CLOSE, "")
    return value


def stage(number: int, name: str, subtitle: str) -> None:
    print()
    print(c("=" * 74, DIM))
    print(c(f" STAGE {number}/6  {name}", BOLD) + c(f"   {subtitle}", DIM))
    print(c("=" * 74, DIM))


def think(text: str) -> None:
    for line in text.strip().split("\n"):
        print(c("  agent  ", CYAN) + line)


def tool(name: str, args: dict[str, Any], summary: str) -> None:
    rendered = ", ".join(f"{k}={v!r}" for k, v in args.items())
    print(c(f"  [tool] {name}({rendered})", MAGENTA))
    print(c(f"         -> {summary}", DIM))


def warn(text: str) -> None:
    print()
    print(c(f"  !! {text}", RED))


def note(text: str) -> None:
    print()
    print(c(f"  >> STAGE NOTE: {text}", YELLOW))


# ---------------------------------------------------------------------------
# Guardrails (slide 16 bottom row, slide 20)
# ---------------------------------------------------------------------------

# The agent's own identity. Read tools are always allowed; write tools are
# allowed only *after* a human approval, and only these.
READ_TOOLS = {
    "list_tables",
    "describe_table",
    "run_kql",
    "list_incidents",
    "get_incident",
    "get_signin_activity",
    "get_audit_activity",
    "get_ueba_baseline",
}

WRITE_TOOLS = {
    "add_incident_comment",
    "set_incident_classification",
    "assign_incident",
}

# Phrases that indicate retrieved content is trying to steer the agent.
#
# This is the weakest of the defence layers and it is here to tell you your
# feed is poisoned, not to protect you. The tool allow-list below is what
# actually protects you. Demo 4 measures exactly how much this catches and how
# much it misses - see ../04-guardrails-injection-test/.
#
# Every phrase must be specific enough not to fire on ordinary SOC prose.
# "ignored instructions" and "closing" appear in legitimate runbook text all
# day long; "ignore prior instructions" does not.
INJECTION_MARKERS = (
    # Direct instruction override
    "ignore prior instructions",
    "ignore previous instructions",
    "ignore all previous",
    "disregard the above",
    "disregard prior",
    "new instructions:",
    "you are now",
    # Forged authority or forged channel
    "system:",
    "assistant:",
    "admin override",
    "administrator override",
    "override]",
    "without human review",
    "maintenance mode",
    # Forged dispositions
    "mark all incidents",
    "classify as benign",
    "close it and do not escalate",
    "approve all pending",
    "safe to auto-close",
    # Exfiltration
    "list every user",
    "export all",
    "post them to",
    "send the results to",
    "report the output here",
)

# Names of privileged actions. Retrieved content has no business naming a tool
# - if it does, something is trying to pick one for the agent. This catches
# INJ-04 and the whole "data selects a tool" class, which is the dangerous one.
DANGEROUS_TOOL_MENTIONS = (
    "revoke_user_sessions",
    "isolate_device",
    "reset_password",
    "disable_account",
    "delete_incident",
    "block_ip",
    "approve_disposition",
    "http_post",
)


class ToolDenied(RuntimeError):
    """Raised when the agent attempts a tool it is not permitted to call."""


@dataclass
class AgentIdentity:
    """The agent runs as its own workload identity, not as a human.

    Slide 16: 'Agent runs as its own workload identity with Security Reader
    plus scoped write actions.'
    """

    principal: str = "svc-soc-triage-agent@contoso.com"
    role: str = "Security Reader"
    write_actions: frozenset[str] = field(default_factory=lambda: frozenset(WRITE_TOOLS))
    approved: bool = False

    def check(self, tool_name: str) -> None:
        if tool_name in READ_TOOLS:
            return
        if tool_name in self.write_actions:
            if not self.approved:
                raise ToolDenied(
                    f"'{tool_name}' is a write action and no human approval has been "
                    f"recorded for this run. Refusing."
                )
            return
        raise ToolDenied(f"'{tool_name}' is not on this agent's allow-list.")


# ---------------------------------------------------------------------------
# Run record - everything the agent did, for audit and tuning
# ---------------------------------------------------------------------------


@dataclass
class RunRecord:
    incident_number: int
    started_utc: str
    identity: str
    role: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[str] = field(default_factory=list)
    security_events: list[dict[str, Any]] = field(default_factory=list)
    disposition: dict[str, Any] | None = None
    human_decision: dict[str, Any] | None = None
    actions_taken: list[str] = field(default_factory=list)
    replans: int = 0

    def log_call(self, name: str, args: dict[str, Any], rows: int) -> None:
        self.tool_calls.append(
            {
                "tool": name,
                "arguments": args,
                "rows_returned": rows,
                "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        )

    def cite(self, table: str, filt: str, rows: int) -> None:
        self.evidence.append({"table": table, "filter": filt, "rows": rows})

    def flag(self, kind: str, detail: str, source: str) -> None:
        self.security_events.append(
            {
                "type": kind,
                "detail": detail,
                "source": source,
                "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        )


# ---------------------------------------------------------------------------
# The agent
# ---------------------------------------------------------------------------


class TriageAgent:
    def __init__(self, identity: AgentIdentity, record: RunRecord, pace: float = 0.5) -> None:
        self.id = identity
        self.record = record
        self.pace = pace

    # -- tool plumbing ----------------------------------------------------

    def call(self, name: str, args: dict[str, Any] | None = None, summary: str | None = None) -> dict[str, Any]:
        """Every tool call goes through here: allow-list, execute, log."""
        args = args or {}
        self.id.check(name)

        result = call_tool(name, args)
        rows = result.get("row_count", len(result.get("rows", [])) if isinstance(result.get("rows"), list) else 1)
        self.record.log_call(name, args, rows)

        tool(name, args, summary or f"{rows} row(s)")
        self._beat()
        return result

    def _beat(self) -> None:
        if self.pace:
            time.sleep(self.pace)

    # -- injection screening ---------------------------------------------

    def screen(self, obj: Any, source: str) -> bool:
        """Scan retrieved content for instructions aimed at the agent.

        Returns True if something was found. The agent reports it and keeps
        going; it never obeys it and never lets it pick a tool. Slide 20.
        """
        found = False

        def walk(node: Any, path: str) -> None:
            nonlocal found
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, f"{path}.{k}" if path else k)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, f"{path}[{i}]")
            elif isinstance(node, str):
                lowered = node.lower()
                for marker in INJECTION_MARKERS:
                    if marker in lowered:
                        found = True
                        self.record.flag(
                            "prompt_injection_attempt",
                            f"Field '{path}' contains: '{marker}'",
                            source,
                        )
                        return
                for tool_name in DANGEROUS_TOOL_MENTIONS:
                    if tool_name in lowered:
                        found = True
                        self.record.flag(
                            "prompt_injection_attempt",
                            f"Field '{path}' names a privileged action: '{tool_name}'. "
                            f"Retrieved data has no legitimate reason to name a tool.",
                            source,
                        )
                        return

        walk(obj, "")
        return found

    # -- stage 1: ingest --------------------------------------------------

    def ingest(self, incident_number: int | None) -> dict[str, Any]:
        stage(1, "INGEST", "pick the work")

        if incident_number is None:
            think(
                "No incident specified. Taking the oldest unassigned incident at\n"
                "Medium or above from the last 24 hours - the queue nobody got to."
            )
            listing = self.call(
                "list_incidents",
                {"max_age_hours": 24, "min_severity": "Medium", "unassigned_only": True},
                summary=None,
            )
            if not listing["incidents"]:
                raise SystemExit("Nothing in the queue matches the agent's scope.")

            candidates = listing["incidents"]
            print()
            for inc in candidates:
                print(c(f"         {inc['incident_number']}  {inc['severity']:<7} "
                        f"{plain(inc['title'])[:50]}", DIM))
            chosen = candidates[0]["incident_number"]
            think(f"\nTaking {chosen}. It has been open the longest.")
        else:
            chosen = incident_number
            think(f"Working incident {chosen} as instructed.")

        result = self.call("get_incident", {"incident_number": chosen})
        if "error" in result:
            raise SystemExit(result["error"])

        incident = result["incident"]
        self.record.cite("SecurityIncident", f"IncidentNumber == {chosen}", 1)

        if self.screen(incident, f"SecurityIncident/{chosen}"):
            warn("Retrieved incident content contains text addressed to me.")
            think(
                "I am treating it as data and reporting it. I will not act on it,\n"
                "and it will not be allowed to select a tool. Continuing the\n"
                "investigation on the actual evidence."
            )
            note("This is the prompt-injection defence from slide 20, firing for "
                 "real. Demo 4 is the test harness that proves it.")

        print()
        print(f"  {c('Incident', BOLD)}  {incident['incident_number']}  "
              f"{plain(incident['title'])}")
        print(f"  {c('Severity', BOLD)}  {incident['severity']}  "
              f"({incident['status']}, unassigned)" if not incident.get("owner")
              else f"  {c('Severity', BOLD)}  {incident['severity']}")
        print(f"  {c('Window  ', BOLD)}  {incident['first_activity']} -> {incident['last_activity']}")
        print(f"  {c('Entities', BOLD)}  " + ", ".join(
            f"{e['kind']}:{e['value']}" for e in incident["entities"]
        ))

        return incident

    # -- stage 2: correlate -----------------------------------------------

    def correlate(self, incident: dict[str, Any]) -> dict[str, Any]:
        stage(2, "CORRELATE", "pull everything about these entities")

        accounts = [e["value"] for e in incident["entities"] if e["kind"] == "Account"]
        if not accounts:
            think("No account entity on this incident. Correlation will be thin.")
            return {"accounts": [], "signins": {}, "audit": {}}

        think(f"Account entities: {', '.join(accounts)}\n"
              f"Pulling sign-in and directory activity for each.")

        signins: dict[str, Any] = {}
        audit: dict[str, Any] = {}

        for upn in accounts:
            s = self.call("get_signin_activity", {"upn": upn, "lookback_hours": 24})
            signins[upn] = s
            self.record.cite("SigninLogs", f"UserPrincipalName == '{upn}', 24h", s["row_count"])

            a = self.call("get_audit_activity", {"upn": upn, "lookback_hours": 24})
            audit[upn] = a
            self.record.cite("AuditLogs", f"InitiatedBy == '{upn}', 24h", a["row_count"])

            for finding in s.get("derived_findings", []):
                print(c(f"         {upn}: {finding['from']} -> {finding['to']} "
                        f"in {finding['minutes_between']} min "
                        f"(AS{finding['from_asn']} -> AS{finding['to_asn']})", DIM))

        return {"accounts": accounts, "signins": signins, "audit": audit}

    # -- stage 3: enrich --------------------------------------------------

    def enrich(self, correlated: dict[str, Any]) -> dict[str, Any]:
        stage(3, "ENRICH", "baseline, asset criticality, known-good")

        enriched: dict[str, Any] = {"baselines": {}, "identity": {}, "cloud": {}}

        for upn in correlated["accounts"]:
            b = self.call("get_ueba_baseline", {"upn": upn})
            if "baseline" in b:
                enriched["baselines"][upn] = b["baseline"]
                self.record.cite("BehaviorAnalytics", f"UserPrincipalName == '{upn}', 90d", 1)
                bl = b["baseline"]
                print(c(f"         {upn}: priority {bl['InvestigationPriority']}, "
                        f"first-time country={bl['FirstTimeCountry']}, "
                        f"first-time ASN={bl['FirstTimeASN']}", DIM))

            ident = self.call(
                "run_kql",
                {"query": f'IdentityInfo | where AccountUPN == "{upn}"', "timespan_hours": 720},
            )
            if ident.get("row_count"):
                enriched["identity"][upn] = ident["rows"][0]
                self.record.cite("IdentityInfo", f"AccountUPN == '{upn}'", 1)

            cloud = self.call(
                "run_kql",
                {"query": f'CloudAppEvents | where AccountUpn == "{upn}"', "timespan_hours": 24},
            )
            if cloud.get("row_count"):
                enriched["cloud"][upn] = cloud["rows"]
                self.record.cite("CloudAppEvents", f"AccountUpn == '{upn}', 24h", cloud["row_count"])

        return enriched

    # -- stage 4: reason --------------------------------------------------

    def reason(self, incident: dict[str, Any], correlated: dict[str, Any],
               enriched: dict[str, Any], prior_rejection: str | None = None) -> dict[str, Any]:
        stage(4, "REASON", "score it, and check the boring explanation first")

        if prior_rejection:
            think(f"Re-planning. The analyst rejected the previous disposition:\n"
                  f'  "{prior_rejection}"\n'
                  f"Re-weighting and producing a new one.")
            self.record.replans += 1

        inv = TENANT["asset_inventory"]
        known_asns = {e["asn"] for e in inv["known_egress"]}
        approved_pubs = set(inv["approved_oauth_publishers"])

        score = 0
        reasons: list[str] = []
        benign_checks: list[dict[str, Any]] = []
        timeline: list[str] = []

        primary = correlated["accounts"][0] if correlated["accounts"] else None

        # -- signal: unfamiliar location backed by baseline
        if primary:
            baseline = enriched["baselines"].get(primary, {})
            findings = correlated["signins"].get(primary, {}).get("derived_findings", [])

            for f in findings:
                asn = f.get("to_asn")
                is_known_egress = asn in known_asns
                benign_checks.append(
                    {
                        "explanation": f"AS{asn} is a Contoso-owned egress",
                        "result": "yes" if is_known_egress else "no",
                        "detail": f"Known egress ASNs: {sorted(known_asns)}",
                    }
                )
                if is_known_egress:
                    reasons.append(f"Location change to AS{asn} is a known corporate egress.")
                    continue

                in_baseline = not baseline.get("FirstTimeCountry", False)
                benign_checks.append(
                    {
                        "explanation": f"Destination is already in {primary}'s 90-day baseline",
                        "result": "yes" if in_baseline else "no",
                        "detail": f"Usual countries: {baseline.get('UsualCountries', [])}",
                    }
                )
                if in_baseline:
                    reasons.append("Destination country is inside the account's baseline.")
                else:
                    score += 30
                    reasons.append(
                        f"Location change {f['from']} -> {f['to']} in "
                        f"{f['minutes_between']} min, first-time country and ASN."
                    )
                    timeline.append(
                        f"{f.get('at', '')}  Sign-in from {f['to']} - "
                        f"first-time country and ASN"
                    )

            # -- signal: MFA registration
            for row in correlated["audit"].get(primary, {}).get("rows", []):
                op = plain(row["OperationName"])
                if "registered security info" in op:
                    score += 25
                    reasons.append("New MFA method registered during the suspicious session.")
                    timeline.append(f"{row['TimeGenerated']}  {op} - persistence")

                if op == "Consent to application":
                    target = row["TargetResources"][0]
                    pub_ok = target.get("publisherVerified", False)
                    name = target.get("displayName", "unknown")
                    perms = target.get("permissions", [])

                    benign_checks.append(
                        {
                            "explanation": f"'{name}' is an approved publisher",
                            "result": "yes" if (pub_ok or name in approved_pubs) else "no",
                            "detail": f"publisherVerified={pub_ok}; approved list: {sorted(approved_pubs)}",
                        }
                    )

                    if not pub_ok:
                        score += 25
                        reasons.append(f"OAuth consent to unverified publisher '{name}'.")
                        timeline.append(f"{row['TimeGenerated']}  Consent to '{name}' ({', '.join(perms)})")
                        if "offline_access" in perms:
                            score += 10
                            reasons.append(
                                "Grant includes offline_access - the refresh token "
                                "survives a password reset."
                            )

            # -- signal: the app actually used its grant
            for row in enriched["cloud"].get(primary, []):
                score += 20
                reasons.append(
                    f"{row['ObjectCount']} objects accessed by '{row['Application']}' "
                    f"via {row['ActionType']}."
                )
                timeline.append(
                    f"{row['Timestamp']}  {row['ActionType']} x{row['ObjectCount']} "
                    f"by {row['Application']}"
                )

            # -- context: asset criticality
            ident = enriched["identity"].get(primary, {})
            crit = ident.get("AssetCriticality")
            groups = ident.get("GroupMembership", [])
            if crit == "High" or "SOX-InScope" in groups:
                score += 10
                reasons.append(
                    f"{ident.get('JobTitle', 'user')} in {ident.get('Department', 'unknown')}; "
                    f"criticality {crit}; groups {groups}."
                )

            # -- benign: is there a change record?
            changes = [ch for ch in inv["change_records"] if primary in ch["affects"]]
            benign_checks.append(
                {
                    "explanation": "A change record covers this activity",
                    "result": "yes" if changes else "no",
                    "detail": changes[0]["id"] if changes else "No change record references this account",
                }
            )
            if changes:
                score = max(0, score - 40)
                reasons.append(f"Change record {changes[0]['id']} covers this activity.")

        # Rejection feedback shifts the agent's posture: it escalates rather
        # than closing, and it says why. Slide 18 - "the agent re-plans".
        if prior_rejection:
            score = max(score, 60)
            reasons.insert(0, f"Analyst override on the previous run: {prior_rejection}")

        severity = "High" if score >= 70 else "Medium" if score >= 40 else "Low"
        confidence = round(min(0.95, 0.35 + score / 130), 2)

        if score >= 70:
            disposition = "Escalate to Tier 2"
        elif score >= 40:
            disposition = "Escalate to Tier 2"
        elif any(b["result"] == "yes" for b in benign_checks):
            disposition = "Close as benign positive"
        else:
            disposition = "Route to human - insufficient evidence"

        think("Weighing the signals:")
        for r in reasons:
            print(c(f"           + {r}", DIM))

        print()
        think("Benign explanations checked before concluding:")
        for b in benign_checks:
            mark = c("yes", GREEN) if b["result"] == "yes" else c("no ", RED)
            print(c(f"           [{mark}{c(']', DIM)} {b['explanation']}", DIM))

        summary_bits = []
        if primary:
            summary_bits.append(primary)
        detail = "; ".join(reasons[:3])

        proposal = {
            "incident": incident["incident_number"],
            "severity": severity,
            "confidence": confidence,
            "disposition": disposition,
            "summary": detail,
            "account": primary,
            "evidence": [f"{e['table']} {e['rows']} rows" for e in self.record.evidence],
            "timeline": timeline,
            "benign_explanations_checked": benign_checks,
            "recommended_actions": self._recommend(reasons),
            "requires_approval": True,
            "risk_score": score,
        }

        self.record.timeline = timeline
        self.record.disposition = proposal
        return proposal

    @staticmethod
    def _recommend(reasons: list[str]) -> list[str]:
        actions: list[str] = []
        joined = " ".join(reasons).lower()
        if "offline_access" in joined or "consent" in joined:
            actions += [
                "Revoke refresh tokens for the account and the consented service principal",
                "Remove the OAuth consent grant and review other users who granted it",
            ]
        if "mfa method" in joined:
            actions.append("Reset MFA methods and require re-registration from a compliant device")
        if "objects accessed" in joined:
            actions.append("Scope the mailbox access - which items, and were any forwarded")
        if not actions:
            actions.append("No response action recommended; document and close")
        return actions

    # -- stage 6: act -----------------------------------------------------

    def act(self, proposal: dict[str, Any], decision: dict[str, Any]) -> list[str]:
        stage(6, "ACT", "only what the human approved")

        if decision["outcome"] != "approved":
            think("No approval recorded. Taking no action on the incident.")
            think("The run is written to the log either way - a rejection is a\n"
                  "training signal and it belongs in the record.")
            return []

        self.id.approved = True
        taken: list[str] = []

        # What gets written depends on what was decided. An escalation assigns
        # to Tier 2; a benign close does not page anyone.
        plan: list[tuple[str, str]] = [
            (
                "add_incident_comment",
                f"Agent triage: {proposal['disposition']} "
                f"(confidence {proposal['confidence']}, "
                f"approved by {decision['by']})",
            ),
            ("set_incident_classification", proposal["disposition"]),
        ]

        if proposal["disposition"].startswith("Escalate"):
            plan.append(("assign_incident", "tier2-oncall@contoso.com"))
        else:
            think("Disposition is not an escalation, so nobody gets paged.\n"
                  "Comment and classification only.")

        # These would be real MCP write calls against the Triage collection.
        # The allow-list check is what actually gates them.
        for tool_name, description in plan:
            try:
                self.id.check(tool_name)
            except ToolDenied as exc:
                warn(str(exc))
                continue
            print(c(f"  [tool] {tool_name}(incident={proposal['incident']!r})", MAGENTA))
            print(c(f"         -> {description}", DIM))
            taken.append(f"{tool_name}: {description}")
            self._beat()

        self.record.actions_taken = taken
        return taken


# ---------------------------------------------------------------------------
# Stage 5: the approval gate
# ---------------------------------------------------------------------------


class ApprovalGate:
    """Nothing reaches Act without passing through here.

    Slide 20: 'Read-only by default. Any write needs an explicit human approval
    with the evidence in view. No silent production actions, ever.'
    """

    def __init__(self, mode: str = "interactive") -> None:
        self.mode = mode  # interactive | auto | reject

    def present(self, proposal: dict[str, Any]) -> dict[str, Any]:
        stage(5, "APPROVE", "the analyst reviews a finished investigation")

        print()
        print(c("  " + "-" * 70, YELLOW))
        print(c("   AGENT PROPOSAL - REQUIRES HUMAN APPROVAL", YELLOW + BOLD))
        print(c("  " + "-" * 70, YELLOW))
        print()
        print(json.dumps(
            {k: v for k, v in proposal.items() if k not in ("benign_explanations_checked", "risk_score")},
            indent=2,
        ))
        print()
        print(c("   Benign explanations the agent checked before proposing this:", DIM))
        for b in proposal["benign_explanations_checked"]:
            mark = "yes" if b["result"] == "yes" else "no "
            print(c(f"     [{mark}] {b['explanation']} - {b['detail']}", DIM))
        print(c("  " + "-" * 70, YELLOW))

        note("The analyst is reviewing a finished investigation, not starting "
             "one. That is the whole pitch. Let it sit on screen for a beat.")

        if self.mode == "auto":
            print()
            print(c("  [--auto-approve] approving without a human. Do not do this in "
                    "production until accuracy earns it (slide 21).", DIM))
            return {"outcome": "approved", "by": "automation", "comment": "--auto-approve"}

        if self.mode == "reject":
            print()
            print(c("  [--reject] simulating an analyst rejection.", DIM))
            # The canned reason has to fit what the agent actually proposed,
            # or the re-plan looks like a non-sequitur on the projector.
            if proposal["disposition"].startswith("Close"):
                why = (
                    "Do not close. The change ticket covers a secret rotation, not "
                    "a successful interactive sign-in. Escalate and confirm which "
                    "host authenticated."
                )
            else:
                why = (
                    "Escalation is right but the scope is too narrow. The consented "
                    "app has tenant-wide reach - check every other user who granted "
                    "it before handing this to Tier 2."
                )
            return {"outcome": "rejected", "by": "analyst@contoso.com", "comment": why}

        return self._prompt()

    @staticmethod
    def _prompt() -> dict[str, Any]:
        print()
        print("  [a] approve as proposed")
        print("  [e] approve with an edited disposition")
        print("  [r] reject and send it back")
        print()
        while True:
            try:
                choice = input(c("  decision > ", GREEN)).strip().lower()
            except EOFError:
                print()
                return {"outcome": "rejected", "by": "no-tty", "comment": "No input available."}

            if choice.startswith("a"):
                return {"outcome": "approved", "by": "analyst@contoso.com", "comment": ""}
            if choice.startswith("e"):
                edited = input(c("  new disposition > ", GREEN)).strip()
                return {
                    "outcome": "approved",
                    "by": "analyst@contoso.com",
                    "comment": f"Edited disposition: {edited}",
                    "edited_disposition": edited,
                }
            if choice.startswith("r"):
                why = input(c("  reason > ", GREEN)).strip()
                return {"outcome": "rejected", "by": "analyst@contoso.com", "comment": why}
            print(c("  a, e, or r.", DIM))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_agent(
    incident_number: int | None,
    gate_mode: str,
    pace: float,
) -> dict[str, Any]:
    identity = AgentIdentity()
    record = RunRecord(
        incident_number=incident_number or 0,
        started_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        identity=identity.principal,
        role=identity.role,
    )
    agent = TriageAgent(identity, record, pace=pace)

    print()
    print(c("  MMS 2026 Midway Edition - Empowering SOC Teams", BOLD))
    print(c(f"  Mission 2: auto-triage with a human on the trigger", DIM))
    print()
    print(c(f"  Agent identity  {identity.principal}", DIM))
    print(c(f"  Role            {identity.role} (+ scoped write, post-approval only)", DIM))
    print(c(f"  Read tools      {len(READ_TOOLS)} allowed", DIM))
    print(c(f"  Write tools     {len(WRITE_TOOLS)} allowed, gated", DIM))

    incident = agent.ingest(incident_number)
    record.incident_number = incident["incident_number"]

    correlated = agent.correlate(incident)
    enriched = agent.enrich(correlated)
    proposal = agent.reason(incident, correlated, enriched)

    gate = ApprovalGate(gate_mode)
    decision = gate.present(proposal)
    record.human_decision = decision

    # A rejection sends it back to Reason. This is the moment on stage.
    if decision["outcome"] == "rejected":
        note("The analyst rejected it. Watch what happens: the agent re-plans, "
             "logs the override, and comes back with a different disposition. "
             "It does not argue and it does not act.")
        proposal = agent.reason(incident, correlated, enriched,
                                prior_rejection=decision["comment"])
        gate2 = ApprovalGate("auto" if gate_mode == "reject" else gate_mode)
        decision = gate2.present(proposal)
        record.human_decision = decision

    if decision.get("edited_disposition"):
        proposal["disposition"] = decision["edited_disposition"]
        record.disposition = proposal

    agent.act(proposal, decision)

    # --- Run log -----------------------------------------------------------

    output = {
        "run": {
            "incident": record.incident_number,
            "started_utc": record.started_utc,
            "finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agent_identity": record.identity,
            "agent_role": record.role,
            "replans": record.replans,
        },
        "disposition": record.disposition,
        "human_decision": record.human_decision,
        "actions_taken": record.actions_taken,
        "evidence": record.evidence,
        "timeline": record.timeline,
        "tool_calls": record.tool_calls,
        "security_events": record.security_events,
    }

    RUN_LOG.mkdir(exist_ok=True)
    path = RUN_LOG / f"run-{record.incident_number}-{int(time.time())}.json"
    path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print()
    print(c("=" * 74, DIM))
    print(c(" RUN LOG", BOLD) + c("   observability is not optional", DIM))
    print(c("=" * 74, DIM))
    print()
    print(f"  Tool calls        {len(record.tool_calls)}")
    print(f"  Evidence items    {len(record.evidence)}")
    print(f"  Re-plans          {record.replans}")
    print(f"  Security events   {len(record.security_events)}")
    print(f"  Actions taken     {len(record.actions_taken)}")
    print()
    print(c(f"  Run written to {path.name}", DIM))
    note("In production this run record goes to a custom Sentinel table. That "
         "is what you query for the ROI numbers on slide 21, and it is what an "
         "auditor asks for when they want to know who approved what.")

    return output


# ---------------------------------------------------------------------------
# Self-test - the guardrails, not the narrative
# ---------------------------------------------------------------------------


def self_test() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        checks.append((label, ok, detail))

    # 1. Write tools are refused before approval.
    ident = AgentIdentity()
    try:
        ident.check("set_incident_classification")
        check("write refused before approval", False, "it was allowed")
    except ToolDenied:
        check("write refused before approval", True)

    # 2. Allowed after approval.
    ident.approved = True
    try:
        ident.check("set_incident_classification")
        check("write allowed after approval", True)
    except ToolDenied as exc:
        check("write allowed after approval", False, str(exc))

    # 3. Tools outside the allow-list are refused even when approved.
    try:
        ident.check("isolate_device")
        check("off-allow-list tool refused", False, "it was allowed")
    except ToolDenied:
        check("off-allow-list tool refused", True, "isolate_device is not scoped to this agent")

    # 4. Read tools never need approval.
    try:
        AgentIdentity().check("run_kql")
        check("read tools need no approval", True)
    except ToolDenied as exc:
        check("read tools need no approval", False, str(exc))

    # 5. Injection screening finds the payload.
    rec = RunRecord(0, "", "", "")
    agent = TriageAgent(AgentIdentity(), rec, pace=0)
    incident = call_tool("get_incident", {"incident_number": 48176})["incident"]
    found = agent.screen(incident, "test")
    check("injection payload detected in incident 48176", found,
          rec.security_events[0]["detail"] if rec.security_events else "")

    # 6. Clean incidents do not false-positive.
    rec2 = RunRecord(0, "", "", "")
    agent2 = TriageAgent(AgentIdentity(), rec2, pace=0)
    clean_inc = call_tool("get_incident", {"incident_number": 48213})["incident"]
    check("no false positive on a clean incident", not agent2.screen(clean_inc, "test"))

    print()
    print("soc_triage_agent guardrail self-test")
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
    parser = argparse.ArgumentParser(description="Mission 2 - auto-triage with a human approval gate.")
    parser.add_argument("--incident", type=int, help="Incident number. Default: oldest unassigned.")
    parser.add_argument("--auto-approve", action="store_true", help="Skip the human. For CI only.")
    parser.add_argument("--reject", action="store_true", help="Scripted rejection, to show the re-plan.")
    parser.add_argument("--fast", action="store_true", help="No pacing delay.")
    parser.add_argument("--json", action="store_true", help="Emit the run record only.")
    parser.add_argument("--self-test", action="store_true", help="Verify the guardrails hold.")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if args.auto_approve and args.reject:
        parser.error("--auto-approve and --reject are mutually exclusive.")

    mode = "auto" if args.auto_approve else "reject" if args.reject else "interactive"
    pace = 0.0 if (args.fast or args.json) else 0.5

    if args.json:
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = run_agent(args.incident, "auto" if mode == "interactive" else mode, 0.0)
        print(json.dumps(result, indent=2))
    else:
        run_agent(args.incident, mode, pace)
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
