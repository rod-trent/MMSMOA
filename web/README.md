# Live demo site

A static site that runs the Midway demos **in a browser**, so you can put it
beside the deck and click through the demos instead of alt-tabbing to a terminal.

Deployed on Vercel. No backend, no serverless functions, no database.

---

## How it works

The demos are pure Python standard library with no network or tenant calls, so
they run **unmodified** in the browser via [Pyodide](https://pyodide.org)
(CPython compiled to WebAssembly). The page mounts the demo sources into
Pyodide's virtual filesystem at the same relative paths they use on disk, so
sibling imports and data-file loads work with no changes.

If Pyodide cannot load — dead venue Wi-Fi on a first visit — the page falls back
to a transcript baked from the same code at build time. Output is identical; the
status pill in the header is the only difference:

| Pill | Meaning |
|------|---------|
| `Python ready` (green) | Running the real code in your tab |
| `recorded output` (amber) | Playing a transcript baked from that same code |

A service worker caches the page, the demo sources, every transcript, and the
Pyodide runtime, so once you have loaded the site in the venue it keeps working
if the network dies mid-session.

## Stage controls

Playback pauses at the beats the demos already mark in their own output, so you
can talk over them:

- at every `>> STAGE NOTE:` — the thing that just happened
- before each `STAGE n/6` or `STEP n/5` — the thing about to happen
- before the agent's approval-gate JSON, and before a verdict

| Key | Action |
|-----|--------|
| `space` | continue, or pause where you are |
| `→` | skip to the end |
| `r` | re-run the current variant |
| `1`–`9` | jump to that variant |
| `esc` | close |

Untick **animate** to render instantly while still honouring the pause points.

The triage agent stops at 9 points, Mission 2 at 11.

## Deep links

Hyperlink a specific demo straight from a slide:

```
https://<your-site>/?demo=soc-triage-agent&v=2      → the rejection run
https://<your-site>/?demo=hunt-mission2&v=1         → "skip validation"
https://<your-site>/?demo=soc-injection&v=2         → the tool allow-list
```

The URL updates as you switch variants, so you can copy the link to whatever is
on screen. Demo ids are in `public/data/manifest.json`.

## Rehearsing the failure case

```
https://<your-site>/?mode=fallback
```

Forces the baked-transcript path. Use it to check the fallback looks right
*before* the session rather than discovering it on stage.

## Building

```bash
python web/build.py            # rebuild public/py, public/transcripts, manifest
python web/build.py --check    # fail if public/ is stale (what CI runs)
```

The build:

1. copies the runnable demo sources into `public/py/`
2. runs all 29 demo variants with colour forced on and bakes the output
3. writes `public/data/manifest.json`

Everything under `public/py`, `public/transcripts` and `public/data` is
**generated**. Edit the demos, then rebuild — never edit those by hand.

`--check` masks timestamps before comparing, since some demos stamp the moment
they ran into their output. That is not drift.

## Deploying to Vercel

The site is committed pre-built, so Vercel needs no build step.

1. **New Project** → import `rod-trent/MMSMOA`
2. **Root Directory**: `web`
3. Framework preset: **Other**. Build command: none. Output directory: `public`.
4. Deploy.

`vercel.json` sets the output directory and the headers, so those settings
should be picked up automatically. Every push to `main` redeploys.

To run it locally:

```bash
cd web/public && python -m http.server 8899
# http://localhost:8899
```

## Adding or changing a demo

1. Edit the demo under `demos/`.
2. If it needs a new file at runtime, add it to `PY_ASSETS` in `build.py`.
3. Add or edit its entry in `DEMOS_MANIFEST` — `variants` become the buttons.
4. `python web/build.py`
5. Commit the regenerated `public/` alongside the demo change.

CI runs `--check` on every push, so the site cannot silently drift from the code
it claims to be running.

## What is honest about this

- The **run** cards execute the real code. The status pill says so.
- The **playback** card (ROI) is PowerShell, so it is a recording, and the card
  says "PowerShell — this is its recorded output."
- The **reference** card (MCP connection) is PowerShell against a live tenant and
  is not runnable here at all; it links to the scripts.

Do not describe the fallback as a live run. The pill tells you which you are in.
