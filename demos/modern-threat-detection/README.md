# Using AI for Modern Threat Detection

**Hunt what SIEM rules miss**

MMS 2026 Midway Edition · Tuesday 27 October, 10:00am PDT · Seaport G
Rod Trent · Chris Sires

---

Traditional threat hunting relies on queries, dashboards, and time-consuming log
review. These demos show where AI compresses the time from hypothesis to
evidence — and, just as importantly, where it does not and must not.

Everything here runs **offline**. No tenant, no Azure, no network.

## The demos

| # | Demo | Maps to | Runs offline |
|---|------|---------|:---:|
| 1 | [Prompts That Produce Evidence](01-prompt-patterns/) | Slides 11–12 | ✅ |
| 2 | [Speed the Investigation](02-hypothesis-hunt/) | Mission 1, slides 14–15 | ✅ |
| 3 | [What the Rules Missed](03-anomaly-to-detection/) | Mission 2, slides 16–17 | ✅ |
| 4 | [Validate Before You Believe](04-validation-harness/) | Slide 19 | ✅ |
| 5 | [Red-Team Your Own Hunt](05-injection-redteam/) | Slide 20 | ✅ |

Demos 2–3 are the stage content. Demo 1 is the thing the room photographs.
Demos 4–5 are the take-home proof for the two guardrail slides.

## Quick start

```bash
# Nothing to install - these run on the standard library
python 01-prompt-patterns/Build-HuntPrompt.py --list
python 02-hypothesis-hunt/hunt_service_accounts.py
python 03-anomaly-to-detection/anomaly_to_detection.py
python 04-validation-harness/validate_finding.py
python 05-injection-redteam/Invoke-HuntRedTeam.py
```

Every script has a `--self-test`. All of them pass:

```bash
python 02-hypothesis-hunt/hunt_service_accounts.py --self-test      # 10/10
python 03-anomaly-to-detection/anomaly_to_detection.py --self-test  # 15/15
python 04-validation-harness/validate_finding.py --self-test        #  8/8
```

## The scenario, and why it is built this way

All demos share `02-hypothesis-hunt/sample_hunt_data.json`. Two seeded findings
that turn out to be one campaign:

**Mission 1** — `svc-datasync` signs in interactively from AS202425 (Moldova,
bulletproof hosting), then enumerates the directory via Graph:
`/users` → `/groups` → `/directoryRoles` → `/applications`.

**Mission 2** — six users grant OAuth consent to one unverified publisher over
seven days, never more than one per day. Three existing analytics rules should
have caught it. None did, and the demo says exactly why for each.

**The link** — both touch `45.129.14.201`. A hunter who pivots on infrastructure
rather than identity finds one campaign instead of two findings.

### The two decoys, which are the point

A hunting demo where everything anomalous is malicious teaches the wrong lesson.

| Decoy | Looks like | Actually |
|-------|-----------|----------|
| `svc-reporting` | Service account signing in interactively — matches the Mission 1 hypothesis exactly | Documented break-glass on a compliant jump host, inside change window CHG-88901 |
| Atlassian Jira Cloud | OAuth consent grant | Verified publisher, admin-initiated, `User.Read` only, CAB record CHG-88755 |

Both must be *correctly dismissed*, and the self-tests assert that they are. A
hunt that reports them generates work instead of removing it.

## Stage running order

| Block | Slides | Demo | Minutes |
|-------|--------|------|---------|
| Problem | 5–7 | — | 12 |
| Toolkit | 8–12 | 1 (show the template) | 6 |
| **Mission 1** | 14–15 | 2 | 8 |
| **Mission 2** | 16–17 | 3 | 10 |
| Guardrails | 18–22 | (4, 5 as reference) | rest |

## The three lines that carry the session

> **"I never run a query I have not read."** (Demo 2, step 3)

> **"A model finding is a lead until a human makes it evidence."** (Demo 4)

> **"If it cannot find your test, distrust its silence."** (Demo 4, seed known bad)

## Recordings

Silent screen recordings of both missions, for when the live version cannot run.
They pause at every step the live runner does — each stage, tool call,
check and result, so you can talk over them with
the rhythm you had planned.

| Recording | Mission | Length |
|-----------|---------|--------|
| [▶ demo-10-hypothesis-hunt.mp4](../../web/public/video/demo-10-hypothesis-hunt.mp4) | Mission 1 — including the decoy being dismissed | 1:06 |
| [▶ demo-11-anomaly-to-detection.mp4](../../web/public/video/demo-11-anomaly-to-detection.mp4) | Mission 2 — anomalies to a validated detection rule | 1:03 |

Both also play from their cards on the [demo site](https://mms-midway-demos.vercel.app/?s=hunt). Re-render with
`python record-demos.py` from the repo root.

## Pre-flight for the live version

From slides 14 and 16:

- Entra app with `SentinelPlatform.DelegatedAccess`, admin-consented
- Sentinel data lake enabled
- Demo account is **Security Reader only**
- **UEBA enabled with at least 14 days of baseline** — without it, Mission 1
  step 5 has nothing to say and the decoy does not resolve. This is the
  prerequisite most likely to be missing.
- Both seeded scenarios present in the last 7 days
- Recorded backups queued (see **Recordings** above)

Reuse `../empowering-soc-teams/01-mcp-connection/Test-SentinelMcpConnection.ps1`
for the connection checks.

## Honest notes

- The model narration is **scripted** so the stage runtime is predictable. The
  data, the correlation, the validation logic, the guardrails, and the rule
  generation are real, and every self-test asserts behaviour rather than output.
- Demo 5 reports **one attack it does not detect** (base64), on purpose. Keyword
  screening caught 5 of 6; tool design caught 6 of 6. Say which one is protecting
  you.
- The generated analytics rule's threshold (3 grants / 14 days) was chosen against
  one synthetic campaign. The rule says so, the YAML header says so in capitals,
  and you should say so on stage. Backtest 90 days before enabling anything.
- Statistics quoted in the deck (Prophet Security 2026, CrowdStrike 2026) are the
  deck's, not the demos'. Re-verify before presenting.
