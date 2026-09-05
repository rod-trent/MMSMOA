# Demo 2 — Speed the Investigation

**Mission 1** · Session: *Using AI for Modern Threat Detection* · Slides 14–15

From a hypothesis to defensible evidence without writing a line of KQL.

---

## The hypothesis

> *"Service accounts should never sign in interactively. Show me any that did
> in the last 7 days and what they touched afterward."*

That is a hypothesis, not a question. It can come back empty, and empty would be
a real answer. `../01-prompt-patterns/Build-HuntPrompt.py` is the linter that
enforces the difference.

## What makes this demo work: the decoy

**Two** service accounts signed in interactively this week.

| Account | ASN | Device | Change record | UEBA priority | Verdict |
|---------|-----|--------|---------------|:---:|---------|
| `svc-datasync` | AS202425 (Moldova, bulletproof hosting) | none | none | **9** | Compromise |
| `svc-reporting` | AS10796 (Columbus HQ) | JUMP-CONTOSO-02, compliant | CHG-88901 | 3 | Documented break-glass |

Both match the hypothesis. One is a finding. The other is a Tuesday.

A hunt that reports both generates work instead of removing it, and nobody runs
it twice. **Step 5 is where that difference shows up**, and it is the part of
the demo worth slowing down for.

Note that UEBA priority alone does not separate them — 3 is not zero. It is the
change record and the known ASN that do it.

## Files

| File | What it does |
|------|--------------|
| `hunt_service_accounts.py` | The six steps from slide 15, replayed deterministically with stage notes inline. |
| `sample_hunt_data.json` | Synthetic CONTOSO-PROD hunting data. Both seeded scenarios, the decoy, and one injection payload. Shared with Demos 3–5. |
| `kql/mission1-hunt.kql` | The queries the model produces, plus the benign checks and the seed-known-bad test. |

## Run it

```bash
python hunt_service_accounts.py --self-test    # 10 assertions
python hunt_service_accounts.py                # the transcript
python hunt_service_accounts.py --step         # pause at each beat
python hunt_service_accounts.py --save mission1-record.json
```

Save the record. Mission 2 starts from it.

## The three moments to narrate

**Step 2 — the model names its own weakest assumption.** Before running
anything, it says there is no "service account" flag in Entra, that it is using
the naming convention, and that this is the weakest part of the hunt. Point at
that. A model that volunteers its own gaps is one you can work with.

**Step 3 — "what would this query miss?"** Rule 1 of the template done properly
is about the gaps, not the syntax. The answer includes service principals living
in a different table entirely, which is exactly the kind of thing a junior
hunter does not know.

> Say the line: **"I never run a query I have not read."** It comes back in the
> guardrails section and it answers half the Q&A.

**Step 5 — the model declines to report a match.** It found two accounts that
satisfy the hypothesis and reports one, because the boring explanation held for
the other. This is the highest-value thirty seconds in the session.

## The pivot that makes it a campaign

Step 4 pivots on the account and finds directory enumeration —
`/users` → `/groups` → `/directoryRoles` → `/applications` in seventeen minutes.
1.8 MB from `/users` means the whole directory came back.

Then it pivots **on the IP instead of the account**, and finds the same
infrastructure touching mail and files for two unrelated users through a
third-party app. That is not one compromised service account.

That third-party app is what Mission 2 hunts. The two demos are one story — say
so, and park the thread rather than chasing it (one hypothesis per thread).

## Pre-flight for the live version

From slide 14's speaker notes:

- Entra app with redirect `https://claude.ai/api/mcp/auth_callback` and
  `SentinelPlatform.DelegatedAccess` consented
- Sentinel data lake enabled
- Demo account is **Security Reader only**
- UEBA enabled with **at least 14 days** of baseline — without it, step 5 has
  nothing to say and the decoy does not resolve
- The seeded scenario present in the last 7 days
- Recorded backup queued

Reuse `../../empowering-soc-teams/01-mcp-connection/Test-SentinelMcpConnection.ps1`
for the connection checks.

## If it breaks

| Failure | Fallback |
|---------|----------|
| MCP auth fails | Run `hunt_service_accounts.py` and narrate over it |
| Only auth fails, portal works | Paste `kql/mission1-hunt.kql` into Advanced Hunting and narrate what Claude would have done — this is the documented fallback on slide 15 |
| Everything fails | Recorded backup |

## Timing

Slide 14 budgets 8 minutes. The transcript runs about 7 with narration, leaving
room for one clarifying question. If you are long, compress step 4's Graph
enumeration — never step 5.
