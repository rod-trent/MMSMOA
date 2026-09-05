#!/usr/bin/env python3
"""
run-all-tests.py
================
Runs every self-test in the MMS 2026 Midway Edition demos and reports.

    python run-all-tests.py           # run everything
    python run-all-tests.py --quick   # self-tests only, skip the transcripts
    python run-all-tests.py --list    # show what would run

Exit code is non-zero if anything fails, so this works in CI.

Why this exists: these demos are stage material. A demo that broke three weeks
ago and nobody noticed is worse than no demo. Run this before the conference,
and let CI run it on every push.

Nothing here touches a tenant, a network, or Azure.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
DEMOS = ROOT / "demos"

GREEN, RED, YELLOW, DIM, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
)
_color = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _color else text


# (label, path relative to demos/, args, is_self_test)
SUITES: list[tuple[str, str, list[str], bool]] = [
    # --- Empowering SOC Teams ------------------------------------------------
    ("SOC  01  MCP replay server",
     "empowering-soc-teams/02-natural-language-triage/replay_mcp_server.py",
     ["--self-test"], True),
    ("SOC  02  Mission 1 walkthrough",
     "empowering-soc-teams/02-natural-language-triage/triage_walkthrough.py",
     ["--fast"], False),
    ("SOC  03  Triage agent guardrails",
     "empowering-soc-teams/03-triage-agent-hitl/soc_triage_agent.py",
     ["--self-test"], True),
    ("SOC  03  Triage agent, clean run",
     "empowering-soc-teams/03-triage-agent-hitl/soc_triage_agent.py",
     ["--incident", "48213", "--auto-approve", "--fast"], False),
    ("SOC  03  Triage agent, rejection re-plan",
     "empowering-soc-teams/03-triage-agent-hitl/soc_triage_agent.py",
     ["--incident", "48201", "--reject", "--fast"], False),
    ("SOC  04  Injection scorecard",
     "empowering-soc-teams/04-guardrails-injection-test/test_injection_defense.py",
     [], True),
    ("SOC  04  Tool allow-list enforcement",
     "empowering-soc-teams/04-guardrails-injection-test/test_injection_defense.py",
     ["--tool-test"], True),

    # --- Modern Threat Detection --------------------------------------------
    ("HUNT 01  Prompt builder presets",
     "modern-threat-detection/01-prompt-patterns/Build-HuntPrompt.py",
     ["--list"], False),
    ("HUNT 02  Mission 1 hunt",
     "modern-threat-detection/02-hypothesis-hunt/hunt_service_accounts.py",
     ["--self-test"], True),
    ("HUNT 03  Mission 2 anomaly-to-detection",
     "modern-threat-detection/03-anomaly-to-detection/anomaly_to_detection.py",
     ["--self-test"], True),
    ("HUNT 03  Refuses rule without validation",
     "modern-threat-detection/03-anomaly-to-detection/anomaly_to_detection.py",
     ["--skip-validation", "--fast"], False),
    ("HUNT 04  Validation harness",
     "modern-threat-detection/04-validation-harness/validate_finding.py",
     ["--self-test"], True),
    ("HUNT 05  Hunt red-team",
     "modern-threat-detection/05-injection-redteam/Invoke-HuntRedTeam.py",
     [], True),
]


def run_one(label: str, script: str, args: list[str]) -> tuple[bool, str, float]:
    path = DEMOS / script
    if not path.exists():
        return False, f"missing: {script}", 0.0

    started = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(path), *args],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=path.parent,
            env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"},
        )
    except subprocess.TimeoutExpired:
        return False, "timed out after 120s", time.time() - started

    elapsed = time.time() - started
    ok = proc.returncode == 0

    # Pull the score line out of self-test output if there is one.
    summary = ""
    for line in reversed((proc.stdout or "").splitlines()):
        lowered = line.lower()
        if ("/" in line and "passed" in lowered) or "behaved as expected" in lowered:
            summary = " ".join(line.split())
            break

    if not ok and not summary:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        summary = tail[-1] if tail else f"exit {proc.returncode}"

    return ok, summary, elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Run every MMS Midway demo self-test.")
    parser.add_argument("--quick", action="store_true", help="Self-tests only.")
    parser.add_argument("--list", action="store_true", help="Show what would run.")
    args = parser.parse_args()

    suites = [s for s in SUITES if s[3]] if args.quick else SUITES

    if args.list:
        for label, script, extra, is_test in suites:
            kind = "self-test" if is_test else "smoke"
            print(f"  [{kind:>9}] {label:<40} {script} {' '.join(extra)}")
        return 0

    print()
    print(c("  MMS 2026 Midway Edition - demo test suite", BOLD))
    print(c("  Offline. No tenant, no network, no Azure.", DIM))
    print()

    results: list[tuple[str, bool, str, float]] = []
    for label, script, extra, _ in suites:
        print(f"  {label:<40} ", end="", flush=True)
        ok, summary, elapsed = run_one(label, script, extra)
        results.append((label, ok, summary, elapsed))
        mark = c("ok", GREEN) if ok else c("FAIL", RED)
        print(f"{mark}  {c(summary, DIM)}  {c(f'{elapsed:.1f}s', DIM)}")

    failed = [r for r in results if not r[1]]
    total_time = sum(r[3] for r in results)

    print()
    print(c("  " + "-" * 70, DIM))
    if failed:
        print(c(f"  {len(failed)} of {len(results)} suites FAILED "
                f"in {total_time:.1f}s", RED + BOLD))
        for label, _, summary, _ in failed:
            print(c(f"    {label}: {summary}", RED))
        print()
        print(c("  Do not demo this until it is green.", RED))
    else:
        print(c(f"  All {len(results)} suites passed in {total_time:.1f}s", GREEN + BOLD))
    print()

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
