# Demo 2 — Ask Like an Analyst

**Mission 1, part B** · Session: *Empowering SOC Teams* · Slide 15, steps 2–6

An analyst asks a question in plain language. The model discovers tables,
writes the KQL, pivots across sign-in, audit, and cloud app data, checks the
behavioural baseline, and hands back a record with cited evidence.

---

## What this demonstrates

Slide 12's **Level 2 — Connected**. The two moments that matter on stage:

1. **Table discovery** (step 2) — the model names tables nobody told it about.
2. **The model refusing to answer** (step 5) — it has two impossible-travel
   hits and declines to call either one until it has the UEBA baseline,
   because a corporate VPN and a compromised session look identical in the
   raw logs. That instinct is the session.

## Files

| File | What it does |
|------|--------------|
| `sample_tenant.json` | Synthetic CONTOSO-PROD data. One true positive, one VPN false positive, four pieces of noise, one prompt-injection payload. Shared by Demos 3 and 4. |
| `replay_mcp_server.py` | A real MCP server over stdio serving that data with the same tool shapes as the hosted Sentinel MCP server. Offline fallback and rehearsal rig. |
| `triage_walkthrough.py` | Deterministic replay of the Mission 1 conversation as a terminal transcript, with stage notes inline. |
| `prompts.md` | The exact prompts, in order, with what to watch for and timing. |
| `kql/mission1-queries.kql` | The queries the model produces. Read them before the session; paste them into the portal if auth dies. |

## Run it

No tenant, no network, no Azure:

```bash
pip install -r ../requirements.txt

# Prove the tool layer works
python replay_mcp_server.py --self-test

# Watch the whole mission
python triage_walkthrough.py

# Rehearsal modes
python triage_walkthrough.py --step      # pause at every beat
python triage_walkthrough.py --fast      # no pacing delay
python triage_walkthrough.py --json      # just the record
```

Wire the replay server into Claude Code and drive it yourself:

```bash
claude mcp add sentinel-replay -- python "$(pwd)/replay_mcp_server.py"
```

Then ask it the prompts from `prompts.md`. The model picks its own path, which
is a better rehearsal than the scripted transcript — and a good way to find out
which of your prompts are fragile.

## Recording

A silent screen recording of this demo, for when the live version cannot run:

**[▶ demo-08-mission1-triage.mp4](../../../web/public/video/demo-08-mission1-triage.mp4)** · 0:31

It includes the moment the model declines to answer until it has the UEBA baseline.

It pauses on the same beats the live demo does — every stage note, and before
each stage — so you can talk over it with the rhythm you had planned. There is
no narration, so do not introduce it as a narrated walkthrough.

It also plays from this demo's card on the
[demo site](https://mms-midway-demos.vercel.app/?demo=soc-triage-walkthrough). Re-render it with
`python record-demos.py` from the repo root after changing this demo.

## The scenario

| Incident | Account | Looks like | Actually is |
|---------|---------|-----------|-------------|
| 48213 | j.doe@contoso.com | Atypical travel | **True positive.** Nairobi sign-in (first-time country + ASN) → new MFA method at +4 min → OAuth consent to an unverified publisher with `offline_access` at +11 min → 218 mail items read at +13 min. SOX-scoped finance analyst. |
| 48209 | m.okafor@contoso.com | Atypical travel | **Benign.** Dublin via AS8075 — the Contoso Azure VPN egress. Both IE and AS8075 are already in the account's 90-day baseline. Compliant device, same browser. |
| 48201 | svc-backup@contoso.com | Credential attack | **Benign.** Expired secret, change ticket CHG-88214. |
| 48198 | a.reyes@contoso.com | Forwarding rule | True positive, but already assigned — the Demo 3 agent skips it. |
| 48187 | LT-CONTOSO-4471 | Malware | Benign. Awareness training payload, quarantined. |
| 48176 | p.nakamura@contoso.com | Bulk download | Carries a **prompt-injection payload** in its description. See Demo 4. |

48209 exists so the model has to do real work. If 48213 were the only travel
hit, the demo would prove nothing.

## Guardrails baked into the replay server

These mirror what you would enforce against the real hosted server, and the
self-test proves each one:

- **Read-only** — no tool writes anything, and `run_kql` rejects `set`, `drop`,
  `delete`, `purge`, `export`, `ingest`, `alter`, `rename`, `append`
- **Table allow-list** — queries outside the nine security tables are refused
- **Row cap** — 200 rows per call
- **Data is not instructions** — free-text fields come back wrapped in
  `<untrusted-data source="tenant-record">…</untrusted-data>`, so a client can
  render content without obeying it (slide 20)
- **No answer leakage** — `_ground_truth` and authoring notes are stripped
  before anything reaches the model

## Stage notes

- **Zoom It.** Tool call lines are the smallest text on screen and the back
  rows will not see them. Slide 2 tells the room to yell; mean it.
- The `--step` flag exists so you can rehearse with the same beats you will use
  live. The stage notes printed in yellow are the things worth saying out loud.
- Close on the audit view (query 10 in the KQL file). The compliance people in
  the room came for that, not for the investigation.
- Budget 8 minutes (slide 14). The transcript runs ~9 with narration. Cut the
  "can it write?" detour first, never the benign check.

## If it breaks

| Failure | Fallback |
|---------|----------|
| OAuth / consent fails | Point Claude at `replay_mcp_server.py` — same tool names, same transcript shape |
| Conference Wi-Fi blocked | Same, it is fully offline |
| Model wanders off script | Run `triage_walkthrough.py --step` and narrate over it |
| Everything is on fire | Recorded backup video, queued before you go on stage |
