# Demo 5 — Instrument, Then Automate

**Take-home / bonus** · Session: *Empowering SOC Teams* · Slides 21–22

The four metrics from slide 21, the query that picks which alert class to
automate first, and an ROI model that survives contact with a CFO.

---

## The one rule

**You cannot claim ROI without a baseline.** Capture these four numbers for
30 days *before* the first agent goes live. A number produced after the fact is
a number nobody believes, and you will be asked to produce it in front of people
whose job is to not believe you.

## Run it

```powershell
# Sample mode - see the report shape, no tenant needed
.\Measure-SocRoi.ps1

# Against your workspace
Connect-AzAccount
.\Measure-SocRoi.ps1 -WorkspaceId <guid> -Days 30 -LoadedAnalystRate 72

# Model a specific class, export for a deck
.\Measure-SocRoi.ps1 -WorkspaceId <guid> -AlertClass "Atypical travel" -ExportPath roi.json
```

`kql/baseline-metrics.kql` has the same queries plus reopen tracking, the
governance query, and the injection-attempt query. Pin them to a workbook and
let them run.

## The four metrics

| Metric | Definition | Industry baseline (slide 21) |
|--------|-----------|------------------------------|
| Mean time to triage | Alert created → first disposition | ~56 min to first action |
| Uninvestigated rate | % of alerts no analyst ever touched | 42% |
| Auto-disposition accuracy | Verdicts confirmed on review, no reopen | **Gate: >95% before widening scope** |
| Analyst hours reclaimed | Time moved from triage into hunting | Target: 10 hrs/week |

Two things worth saying about how these are computed:

- **Watch p90, not the mean.** The mean is dragged down by the alerts someone
  happened to be looking at. p90 is what the queue actually feels like.
- **An approval the analyst had to edit is not a correct verdict.** The accuracy
  query counts `ApprovedClean` only, and `METRIC 3b` subtracts incidents the
  agent closed that a human reopened within 7 days. Counting every approval as a
  win is how teams end up with a 99% accuracy number and a breach.

## Picking the first class

Slide 22: one high-volume, **low-risk** class. The opportunity score is volume
discounted by how often the class is genuinely High severity.

```
  Alert class                                  Volume  High sev  Opportunity
  Atypical travel                                1842      4.1%        38863
  Multiple failed sign-ins then success           688     11.3%        18918
  Suspicious sign-in from unfamiliar ISP         1106      6.8%        18554
  Suspicious inbox forwarding rule                 97     62.9%         1979   <- not this one
```

You want the boring, noisy, well-understood class. Starting with the scary one
is how you end up with an agent nobody trusts and a project nobody funds.

## The ROI model

```
Benefit = alerts auto-triaged/month  x  minutes saved/alert  x  loaded analyst rate
Cost    = model tokens + platform licensing + engineering (amortised) + human review
```

Sample output at 1,842 alerts/month and $65/hr:

```
  BENEFIT
    540.3 analyst-hours/month               $35,120
  COST
    Model tokens                               $111
    Platform / licensing                     $1,200
    Engineering (amortised)                    $139
    Human review (2.5 min/alert)             $4,989
    Total                                    $6,439
  NET                                       $28,681/month
```

**Two honesty checks the script prints, and you should say out loud:**

1. **Human review is a real, recurring cost.** It is the largest cost line here
   by a factor of four. Any ROI model that omits it is selling something.
2. **Not all reclaimed hours are payroll savings.** Alerts in the 42%
   uninvestigated bucket cost you *risk*, not payroll — nobody was working them.
   Automating those is absolutely worth doing, and it is not a headcount saving.
   Say that before your CFO says it for you.

The token cost line usually surprises people by how small it is relative to
analyst time. That is a legitimate and useful surprise.

## Not modelled, and real

- Reduced dwell time
- Fewer missed true positives
- Lower attrition — slide 6 puts junior analyst turnover at 70% within three
  years. One avoided backfill is worth more than everything in the table above.

## The scaling gate

The script ends by checking accuracy against the 95% gate:

- **No agent runs yet** → correct for a baseline. Measure 30 days, deploy
  read-only on one class, then compare. In that order.
- **Accuracy ≥ 95%** → you may widen scope, one class at a time, re-measuring
  each time.
- **Accuracy < 95%** → do not widen and do not enable auto-close. Every rejected
  run in the log is a tuning signal. Read them.

Demo 3 writes those run records. `SOCAgentRuns_CL` is where they land.

## Stage note

Slide 21 is a talk slide, not a demo slide. If you have 90 seconds, run
`.\Measure-SocRoi.ps1` in sample mode and let the room read the cost table —
particularly the human review line. It reframes the conversation from "will AI
replace analysts" to "what is review time worth", which is the conversation you
want to be having.
