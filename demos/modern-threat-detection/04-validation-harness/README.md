# Demo 4 — Validate Before You Believe

**Take-home / bonus** · Session: *Using AI for Modern Threat Detection* · Slide 19

The six validation techniques, run against a real finding, ending in a verdict:
still a lead, or now evidence.

---

## The claim being tested

> **"A model finding is a lead until a human makes it evidence."**

This harness is what turns that sentence into a procedure.

## Run it

```bash
python validate_finding.py --self-test              # 8 assertions
python validate_finding.py                          # validate the Mission 2 finding
python validate_finding.py --finding mission1       # validate the Mission 1 finding
python validate_finding.py --technique seed         # just the one people forget
python validate_finding.py --json
```

Exit code is non-zero unless the finding reaches high confidence.

## The six techniques

| # | Technique | What it actually does |
|---|-----------|----------------------|
| 1 | Re-query independently | Re-runs the core query on a different window. A model's *summary* of a query is not the query — this is how you catch drift. |
| 2 | Cross-source confirmation | One table is a lead. The same entity in a second, independent source is evidence. |
| 3 | Baseline it | "New" is meaningless without a reference. Compares against 90 days of UEBA history and counts *how many* first-time signals fired — one is noise, seven is not. |
| 4 | **Seed known bad** | Plants a canary matching the hunt's own logic and re-runs it. |
| 5 | Hunt the benign case | Actively searches for the innocent explanation. Change records, known egress, approved publishers, admin rollouts. |
| 6 | Score and log | Records confidence and what was run. Confirmed *and* rejected findings feed rule tuning. |

## Technique 4 is the one that matters

Everyone runs 1, 2, and 5 eventually. Almost nobody runs 4.

A hunt that returns *"nothing found"* is only useful **if you have proved it can
find something.** The harness plants a synthetic record that matches the hunt's
own detection logic, re-runs the hunt, and checks the canary comes back.

If it does not:

```
  VERDICT: NOT EVIDENCE. The seed-known-bad test failed, which
  means this hunt's silence carries no information at all.
```

Confidence is forced to `none` — not low, none. Every "nothing found" that hunt
has ever returned is worthless, and `--self-test` asserts that this override
holds.

> **The line:** *"If it cannot find your test, distrust its silence."*

## The harness discriminates — and proves it

A validation harness that passes everything is decoration. The self-test runs
the **`svc-reporting` decoy** from Mission 1 through the same six techniques:

```
  [ok] the decoy FAILS the benign-case search
  [ok] the decoy does not reach high confidence   (low)
```

Three benign explanations hold for the decoy — known egress ASN, approved jump
host, open change record CHG-88901 — so it never reaches evidence. That is the
harness earning the right to be believed when it says "high".

## What good looks like

```
  [ PASS ] 3. Baseline it
         Compared 'svc-datasync@contoso.com' against 90 days of history.
         UEBA priority 9, 7 first-time signals
         Deviation is real against a 90-day baseline, and it is multi-signal.
         One first-time signal is noise; 7 at once is not.

  [ PASS ] 5. Hunt the benign case
         3 explanations checked, 0 held
           [no ] An open change record covers this activity
           [no ] Interactive sign-in came from a known egress ASN
           [no ] Interactive sign-in came from an approved jump host

  VERDICT: This is now evidence. It survived all five techniques,
  including a deliberate search for the innocent explanation.
```

## Using it on your own hunts

Add a finding to `FINDINGS` with its entity, entity type, and primary table.
The techniques are written against the shared dataset, but the *shape* is
portable — the questions do not change:

1. Does it survive a re-query on a different window?
2. Does a second source agree?
3. Is it actually new relative to a baseline?
4. **Can the hunt find a pattern you planted?**
5. Did you go looking for the innocent explanation?
6. Did you write down what you did and who did it?

Wire it into CI alongside your scheduled hunts. When a hunt changes, the canary
test tells you whether it still works before it silently stops finding things.

## Stage note

If time is short, run only `--technique seed`. It is six lines of output and it
makes the point better than the whole harness does. The OWASP LLM Top 10
"Misinformation" entry is the reference — models are confidently wrong by
design, so validation is a control, not a courtesy.
