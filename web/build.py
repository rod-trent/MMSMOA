#!/usr/bin/env python3
"""
build.py
========
Builds the static demo site in web/public/.

    python web/build.py            # build
    python web/build.py --check    # build to a temp dir and diff (CI drift guard)

What it does
------------
1. Copies the runnable demo sources into public/py/, preserving the directory
   layout so the scripts' relative imports and data-file paths work unchanged
   inside Pyodide's virtual filesystem.

2. Runs every demo variant locally with colour forced on, and bakes the output
   into public/transcripts/. That is the offline fallback: if Pyodide cannot
   load - dead conference Wi-Fi on first visit - the page plays the baked
   transcript instead, and it looks identical.

3. Writes public/data/manifest.json describing every card the site renders.

The demos are the single source of truth. Nothing here edits them, and CI runs
--check so the site can never drift from the code it claims to run.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import runpy
import shutil
import sys
import tempfile
from pathlib import Path

WEB = Path(__file__).resolve().parent
ROOT = WEB.parent
DEMOS = ROOT / "demos"

SOC = "empowering-soc-teams"
HUNT = "modern-threat-detection"

# Files copied into the browser filesystem. Everything a script imports or
# reads at runtime has to be listed here.
PY_ASSETS = [
    f"{SOC}/02-natural-language-triage/replay_mcp_server.py",
    f"{SOC}/02-natural-language-triage/triage_walkthrough.py",
    f"{SOC}/02-natural-language-triage/sample_tenant.json",
    f"{SOC}/03-triage-agent-hitl/soc_triage_agent.py",
    f"{SOC}/04-guardrails-injection-test/test_injection_defense.py",
    f"{SOC}/04-guardrails-injection-test/injection_corpus.json",
    f"{HUNT}/01-prompt-patterns/Build-HuntPrompt.py",
    f"{HUNT}/02-hypothesis-hunt/hunt_service_accounts.py",
    f"{HUNT}/02-hypothesis-hunt/sample_hunt_data.json",
    f"{HUNT}/03-anomaly-to-detection/anomaly_to_detection.py",
    f"{HUNT}/04-validation-harness/validate_finding.py",
    f"{HUNT}/05-injection-redteam/Invoke-HuntRedTeam.py",
]

# id, session, order, title, blurb, script, and the variants exposed as buttons.
DEMOS_MANIFEST: list[dict] = [
    # ---------------- Empowering SOC Teams --------------------------------
    {
        "id": "soc-mcp-connection",
        "session": "soc",
        "title": "Wire the Model",
        "subtitle": "Mission 1 · slides 14–15",
        "blurb": "Register the Entra app, point Claude at the Sentinel MCP server, "
                 "and confirm the connection before you go on stage.",
        "kind": "reference",
        "note": "PowerShell — runs against a real tenant, not in the browser.",
        "links": [
            {"label": "Register-SentinelMcpApp.ps1",
             "href": f"https://github.com/rod-trent/MMSMOA/blob/main/demos/{SOC}/01-mcp-connection/Register-SentinelMcpApp.ps1"},
            {"label": "Test-SentinelMcpConnection.ps1",
             "href": f"https://github.com/rod-trent/MMSMOA/blob/main/demos/{SOC}/01-mcp-connection/Test-SentinelMcpConnection.ps1"},
        ],
    },
    {
        "id": "soc-tool-layer",
        "session": "soc",
        "title": "The Tool Layer",
        "subtitle": "Mission 1 · slide 15",
        "blurb": "Thirteen assertions against the MCP tool layer: read-only enforcement, "
                 "the table allow-list, the row cap, and the untrusted-data wrapper.",
        "kind": "run",
        "script": f"{SOC}/02-natural-language-triage/replay_mcp_server.py",
        "variants": [
            {"label": "Run self-test", "args": ["--self-test"], "primary": True},
        ],
    },
    {
        "id": "soc-triage-walkthrough",
        "session": "soc",
        "title": "Ask Like an Analyst",
        "subtitle": "Mission 1 · slide 15",
        "blurb": "An analyst asks in plain language. The model discovers tables, writes "
                 "the KQL, and refuses to answer until it has the UEBA baseline — which "
                 "is what separates the real compromise from the VPN false positive.",
        "kind": "run",
        "script": f"{SOC}/02-natural-language-triage/triage_walkthrough.py",
        "video": "video/demo-08-mission1-triage.mp4",
        "videoLength": "0:50",
        "variants": [
            {"label": "Run the mission", "args": ["--fast"], "primary": True},
            {"label": "Record only (JSON)", "args": ["--json"]},
        ],
    },
    {
        "id": "soc-triage-agent",
        "session": "soc",
        "title": "Auto-Triage + Human on the Trigger",
        "subtitle": "Mission 2 · slides 16–18",
        "blurb": "The six-stage loop, with an approval gate the agent cannot get past. "
                 "Run it clean, then reject it on purpose and watch it re-plan.",
        "kind": "run",
        "script": f"{SOC}/03-triage-agent-hitl/soc_triage_agent.py",
        "video": "video/demo-09-triage-agent-hitl.mp4",
        "videoLength": "2:02",
        "variants": [
            {"label": "The easy one (auto-close)", "args": ["--auto-approve", "--fast"]},
            {"label": "The real one (48213)",
             "args": ["--incident", "48213", "--auto-approve", "--fast"], "primary": True},
            {"label": "Reject it on purpose",
             "args": ["--incident", "48201", "--reject", "--fast"],
             "highlight": True},
            {"label": "Injection payload (48176)",
             "args": ["--incident", "48176", "--auto-approve", "--fast"]},
            {"label": "Guardrail self-test", "args": ["--self-test"]},
        ],
    },
    {
        "id": "soc-injection",
        "session": "soc",
        "title": "Prove the Guardrails Hold",
        "subtitle": "Slide 20",
        "blurb": "Ten prompt-injection payloads and two benign controls, scored. "
                 "Reports one payload it does not detect, on purpose.",
        "kind": "run",
        "script": f"{SOC}/04-guardrails-injection-test/test_injection_defense.py",
        "variants": [
            {"label": "Scorecard", "args": [], "primary": True},
            {"label": "With commentary", "args": ["--verbose"]},
            {"label": "Tool allow-list", "args": ["--tool-test"], "highlight": True},
        ],
    },
    {
        "id": "soc-roi",
        "session": "soc",
        "title": "Instrument, Then Automate",
        "subtitle": "Slides 21–22",
        "blurb": "The four baseline metrics, which alert class to automate first, and an "
                 "ROI model that includes human review time — the largest cost line.",
        "kind": "playback",
        "note": "PowerShell — this is its recorded output.",
        "transcript": "soc-roi",
    },

    # ---------------- Modern Threat Detection ------------------------------
    {
        "id": "hunt-prompt-builder",
        "session": "hunt",
        "title": "Prompts That Produce Evidence",
        "subtitle": "Slides 11–12",
        "blurb": "The template the room photographs, plus a linter that tells you when "
                 "your hypothesis cannot fail.",
        "kind": "run",
        "script": f"{HUNT}/01-prompt-patterns/Build-HuntPrompt.py",
        "variants": [
            {"label": "Lint a bad hypothesis",
             "args": ["--lint", "Find anything suspicious"],
             "primary": True, "highlight": True},
            {"label": "Six good hypotheses", "args": ["--list"]},
            {"label": "Render the template", "args": ["--preset", "service-accounts"]},
            {"label": "OAuth consent hunt", "args": ["--preset", "oauth-consent"]},
        ],
    },
    {
        "id": "hunt-mission1",
        "session": "hunt",
        "title": "Speed the Investigation",
        "subtitle": "Mission 1 · slides 14–15",
        "blurb": "Hypothesis to evidence with no hand-written KQL. Two service accounts "
                 "match the hypothesis; only one is a finding.",
        "kind": "run",
        "script": f"{HUNT}/02-hypothesis-hunt/hunt_service_accounts.py",
        "video": "video/demo-10-hypothesis-hunt.mp4",
        "videoLength": "1:06",
        "variants": [
            {"label": "Run the hunt", "args": ["--fast"], "primary": True},
            {"label": "Self-test (10 checks)", "args": ["--self-test"]},
            {"label": "Record only (JSON)", "args": ["--json"]},
        ],
    },
    {
        "id": "hunt-mission2",
        "session": "hunt",
        "title": "What the Rules Missed",
        "subtitle": "Mission 2 · slides 16–17",
        "blurb": "UEBA anomalies to a validated finding to a generated analytics rule — "
                 "and a flat refusal to generate that rule if you skip validation.",
        "kind": "run",
        "script": f"{HUNT}/03-anomaly-to-detection/anomaly_to_detection.py",
        "video": "video/demo-11-anomaly-to-detection.mp4",
        "videoLength": "1:03",
        "variants": [
            {"label": "Run the mission", "args": ["--fast"], "primary": True},
            {"label": "Skip validation (watch it refuse)",
             "args": ["--skip-validation", "--fast"], "highlight": True},
            {"label": "Self-test (15 checks)", "args": ["--self-test"]},
        ],
    },
    {
        "id": "hunt-validation",
        "session": "hunt",
        "title": "Validate Before You Believe",
        "subtitle": "Slide 19",
        "blurb": "Six techniques, ending in a verdict: still a lead, or now evidence. "
                 "Includes seed-known-bad, the one everyone forgets.",
        "kind": "run",
        "script": f"{HUNT}/04-validation-harness/validate_finding.py",
        "variants": [
            {"label": "Validate the finding", "args": ["--finding", "mission2"], "primary": True},
            {"label": "Seed known bad only",
             "args": ["--technique", "seed"], "highlight": True},
            {"label": "Mission 1 finding", "args": ["--finding", "mission1"]},
            {"label": "Self-test (8 checks)", "args": ["--self-test"]},
        ],
    },
    {
        "id": "hunt-redteam",
        "session": "hunt",
        "title": "Red-Team Your Own Hunt",
        "subtitle": "Slide 20",
        "blurb": "Leakage and injection testing for a hunting workflow. The highest-value "
                 "injection against a hunt is not 'do something' — it is 'find nothing'.",
        "kind": "run",
        "script": f"{HUNT}/05-injection-redteam/Invoke-HuntRedTeam.py",
        "variants": [
            {"label": "Full red-team", "args": [], "primary": True},
            {"label": "Why each payload matters", "args": ["--verbose"]},
            {"label": "Leakage posture only", "args": ["--leakage"]},
        ],
    },
]

SESSIONS = {
    "soc": {
        "id": "soc",
        "title": "Empowering SOC Teams",
        "subtitle": "How Claude, Copilot, ChatGPT, MCP Servers, and Agents Drive Efficiency",
        "slot": "Monday 26 October · 3:00pm PDT · Seaport H",
        "presenters": "Rod Trent · Ken Goossens",
        "accent": "#297FD5",
    },
    "hunt": {
        "id": "hunt",
        "title": "Using AI for Modern Threat Detection",
        "subtitle": "Hunt what SIEM rules miss",
        "slot": "Tuesday 27 October · 10:00am PDT · Seaport G",
        "presenters": "Rod Trent · Chris Sires",
        "accent": "#F2B134",
    },
}


# ---------------------------------------------------------------------------
# Baking transcripts
# ---------------------------------------------------------------------------


# Some demos stamp the moment they ran into their output - generated_utc,
# started_utc, and the run-log filename. Those change every build and are not
# drift. --check masks them so it compares what the demo actually produced.
VOLATILE = [
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"),
    re.compile(r"run-\d+-\d+\.json"),
]


def normalise(raw: bytes) -> bytes:
    """Mask timestamps and line endings so --check compares content.

    Line endings vary with the developer's git checkout; timestamps vary with
    the clock. Neither is drift.
    """
    raw = raw.replace(b"\r\n", b"\n")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    for pattern in VOLATILE:
        text = pattern.sub("<TIMESTAMP>", text)
    return text.encode("utf-8")


def write_lf(path: Path, text: str) -> None:
    """Write text with LF endings on every platform.

    Without this, a Windows build emits CRLF, a Linux CI rebuild emits LF, and
    --check reports drift that is not there.
    """
    path.write_text(text, encoding="utf-8", newline="\n")


class TTYCapture(io.StringIO):
    """Captures stdout while claiming to be a terminal.

    The demos decide whether to emit ANSI colour with sys.stdout.isatty().
    Baked transcripts need the colour codes so the fallback looks identical to
    a live Pyodide run.
    """

    def isatty(self) -> bool:  # noqa: D102
        return True


def bake(script_rel: str, args: list[str]) -> str:
    """Run one demo variant and capture its coloured output."""
    script = DEMOS / script_rel
    cwd = os.getcwd()
    old_argv, old_stdout, old_path = sys.argv, sys.stdout, list(sys.path)
    buf = TTYCapture()

    try:
        os.chdir(script.parent)
        sys.argv = [str(script), *args]
        sys.stdout = buf
        # `python script.py` puts the script's directory on sys.path; runpy does
        # not. The demos rely on it for their sibling imports, and Pyodide needs
        # the same treatment - see assets/app.js.
        sys.path.insert(0, str(script.parent))
        try:
            runpy.run_path(str(script), run_name="__main__")
        except SystemExit:
            pass
    finally:
        os.chdir(cwd)
        sys.argv, sys.stdout, sys.path = old_argv, old_stdout, old_path
        # Demo modules cache module-level state; drop them so the next bake is clean.
        for name in ("replay_mcp_server", "soc_triage_agent",
                     "hunt_service_accounts", "anomaly_to_detection"):
            sys.modules.pop(name, None)

    return buf.getvalue()


PS_ROI_TRANSCRIPT = """\033[2m
==========================================================================\033[0m
\033[1m SOC baseline - 30 days\033[0m
\033[2m==========================================================================\033[0m
\033[33m  SAMPLE MODE. No -WorkspaceId supplied, so these are illustrative
  numbers, not your tenant. Pass -WorkspaceId to measure for real.\033[0m

\033[1m The four metrics (slide 21)\033[0m
\033[2m--------------------------------------------------------------------------\033[0m
  Mean time to triage        \033[31m68.4 min\033[0m        \033[2mindustry ~56 min to first action\033[0m
    p50 / p90                41 / 187 min    \033[2mp90 is where the pain actually is\033[0m
  Uninvestigated rate        \033[33m39.2%\033[0m           \033[2mindustry 42%\033[0m
  Auto-disposition accuracy  no data         \033[2mno rows in SOCAgentRuns_CL yet - expected pre-agent\033[0m
  Analyst hours reclaimed    0 (baseline)    \033[2mtarget: 10 hrs/week into hunting\033[0m

\033[1m Where to start (slide 22: one high-volume, low-risk class)\033[0m
\033[2m--------------------------------------------------------------------------\033[0m
\033[2m  Alert class                                  Volume  High sev  Opportunity\033[0m
  Atypical travel                                1842      4.1%        38863
  Multiple failed sign-ins then success           688     11.3%        18918
  Suspicious sign-in from unfamiliar ISP         1106      6.8%        18554
  Anomalous file download volume                  402     14.9%        15052
  Malware detected and remediated                 974        2%        11454
\033[2m  Suspicious inbox forwarding rule                 97     62.9%         1979\033[0m

\033[32m  Recommended first class: Atypical travel\033[0m
\033[2m  1842 alerts in 30 days, 4.1% high severity.
  Greyed rows are high-severity classes. Do not start there.\033[0m

\033[1m ROI model (the version your CFO will accept)\033[0m
\033[2m--------------------------------------------------------------------------\033[0m

  Class            Atypical travel
  Volume           1842 alerts/month
  Minutes saved    17.6 of 22 per alert (agent owns ~80% of the loop)
  Analyst rate     $65/hr fully loaded

\033[32m  BENEFIT
    540.3 analyst-hours/month               $35,120\033[0m

\033[33m  COST\033[0m
    Model tokens                               $111
    Platform / licensing                     $1,200
    Engineering (amortised)                    $139
    Human review (2.5 min/alert)             $4,989
\033[33m    Total                                    $6,439\033[0m

\033[32m  NET                                       $28,681/month\033[0m
\033[2m                                            $344,172/year

  Sanity check before you show this to anyone: does the benefit
  line represent hours your team actually gets back, or hours
  nobody was spending in the first place? Alerts in the 42%
  uninvestigated bucket cost you risk, not payroll. Automating
  those is worth doing and it is not a payroll saving - say so
  before your CFO says it for you.

  Human review is a real, recurring cost. Any ROI model that
  omits it is selling something.\033[0m

\033[1m Scaling gate (slide 21)\033[0m
\033[2m--------------------------------------------------------------------------\033[0m

  No agent runs yet. That is correct for a baseline.
\033[2m  Capture these four metrics for 30 days, THEN deploy the agent
  read-only on one class, THEN compare. In that order.\033[0m
"""


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out: Path) -> dict:
    py_dir = out / "py"
    tx_dir = out / "transcripts"
    data_dir = out / "data"

    for d in (py_dir, tx_dir, data_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)

    # 1. Copy the demo sources, normalising line endings to LF.
    #
    # Not cosmetic: git checks demos/ out as CRLF on Windows and LF on Linux, so
    # a byte-for-byte copy would make the build output depend on the developer's
    # checkout settings and --check would report drift that is not there.
    for rel in PY_ASSETS:
        src = DEMOS / rel
        if not src.exists():
            raise SystemExit(f"missing demo asset: {rel}")
        dst = py_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes().replace(b"\r\n", b"\n"))

    # 2. Bake every variant.
    baked = 0
    for demo in DEMOS_MANIFEST:
        if demo["kind"] == "playback":
            write_lf(tx_dir / f"{demo['transcript']}.txt", PS_ROI_TRANSCRIPT)
            baked += 1
            continue
        if demo["kind"] != "run":
            continue
        for i, variant in enumerate(demo["variants"]):
            text = bake(demo["script"], variant["args"])
            key = f"{demo['id']}-{i}"
            write_lf(tx_dir / f"{key}.txt", text)
            variant["transcript"] = key
            baked += 1
            print(f"  baked {key:<34} {len(text):>7,} chars  "
                  f"({' '.join(variant['args']) or 'no args'})")

    # 3. Manifest.
    manifest = {
        "generated_note": "Built by web/build.py. Do not edit by hand.",
        "repo": "https://github.com/rod-trent/MMSMOA",
        "event": {
            "name": "MMS 2026 Midway Edition",
            "location": "Manchester Grand Hyatt, San Diego",
            "dates": "25–28 October 2026",
            "url": "https://mmsmoa.com/mms2026midway",
        },
        "sessions": list(SESSIONS.values()),
        "pyAssets": PY_ASSETS,
        "demos": DEMOS_MANIFEST,
    }
    write_lf(data_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n")

    print(f"\n  {len(PY_ASSETS)} sources copied, {baked} transcripts baked")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the demo site.")
    parser.add_argument("--check", action="store_true",
                        help="Build to a temp dir and fail if it differs from public/.")
    args = parser.parse_args()

    public = WEB / "public"

    if not args.check:
        print("\nBuilding web/public ...")
        build(public)
        print(f"  -> {public}\n")
        return 0

    print("\nChecking web/public is up to date ...")
    with tempfile.TemporaryDirectory() as tmp:
        candidate = Path(tmp) / "public"
        candidate.mkdir()
        build(candidate)

        drift: list[str] = []
        for sub in ("py", "transcripts", "data"):
            a, b = public / sub, candidate / sub
            if not a.exists():
                drift.append(f"{sub}/ missing from public/")
                continue
            a_files = {p.relative_to(a) for p in a.rglob("*") if p.is_file()}
            b_files = {p.relative_to(b) for p in b.rglob("*") if p.is_file()}
            for missing in sorted(b_files - a_files):
                drift.append(f"{sub}/{missing.as_posix()} missing")
            for extra in sorted(a_files - b_files):
                drift.append(f"{sub}/{extra.as_posix()} is stale")
            for common in sorted(a_files & b_files):
                if normalise((a / common).read_bytes()) != normalise((b / common).read_bytes()):
                    drift.append(f"{sub}/{common.as_posix()} differs")

    if drift:
        print("\n  web/public is out of date. The site would not match the demos:\n")
        for d in drift[:40]:
            print(f"    {d}")
        if len(drift) > 40:
            print(f"    ... and {len(drift) - 40} more")
        print("\n  Fix: python web/build.py\n")
        return 1

    print("\n  Up to date. The site runs exactly the committed demo code.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
