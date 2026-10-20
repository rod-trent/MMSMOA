#!/usr/bin/env python3
"""
build-companion.py
==================
Builds the presenter companion as an EPUB, for reading on a Kindle or phone
while you run the demos.

    python build-companion.py                      # -> presenter-companion.epub
    python build-companion.py -o ~/companion.epub
    python build-companion.py --list               # chapters only, no build

Why this exists
---------------
The presenter-side material already lives in this repo, but scattered: speaker
notes inside two .pptx files, and "Stage notes", "Run it" and "If it breaks"
sections across nine demo folders. None of it is readable while you are
standing up. This pulls the parts you actually need mid-demo into one
reflowable file, ordered the way the sessions run.

It is also where the stage direction went. The demo runners used to print it
on screen in yellow - "Do not rush past this", "Say the line", "Point at it" -
which meant the room read your cues off the projector. Those lines were
rewritten as audience-facing commentary (`>> WHY THIS MATTERS:`) and the
direction moved here.

Nothing here edits the decks or the demos; it only reads them. Re-run it after
changing a deck's notes or a demo README.

Requires: python-pptx, markdown (both already used elsewhere in this repo).
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import zipfile
from pathlib import Path

import markdown
from pptx import Presentation

ROOT = Path(__file__).resolve().parent
DEMOS = ROOT / "demos"

SOC_DECK = ROOT / "SlideDecks/Empowering SOC Teams - MMS Midway 2026.pptx"
MTD_DECK = ROOT / "SlideDecks/Using AI for Modern Threat Detection - MMS Midway 2026.pptx"

parser = argparse.ArgumentParser(description="Build the presenter companion EPUB.")
parser.add_argument("-o", "--out", default="presenter-companion.epub",
                    help="output path (default: presenter-companion.epub)")
parser.add_argument("--list", action="store_true",
                    help="print the chapter list and exit")
args = parser.parse_args()
OUT = Path(args.out)

for p in (SOC_DECK, MTD_DECK, DEMOS):
    if not p.exists():
        sys.exit("not found: " + str(p) + " - run this from the repository root.")

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:                      # pragma: no cover - older interpreters
    pass


# ---------------------------------------------------------------- extraction
def deck_notes(deck_path):
    """{slide number: (title, notes text)}"""
    prs = Presentation(str(deck_path))
    out = {}
    for i, s in enumerate(prs.slides, 1):
        title = ""
        try:
            if s.shapes.title is not None:
                title = " ".join((s.shapes.title.text or "").split())
        except Exception:
            pass
        notes = ""
        if s.has_notes_slide:
            notes = s.notes_slide.notes_text_frame.text.strip()
        out[i] = (title, notes)
    return out


def section(md_path, heading):
    """The body of '## heading' up to the next '## '."""
    text = (DEMOS / md_path).read_text(encoding="utf-8")
    pat = re.compile(r"^##\s+" + re.escape(heading) + r"\s*$(.*?)(?=^##\s|\Z)",
                     re.M | re.S)
    m = pat.search(text)
    if not m:
        sys.exit("%s: no section %r" % (md_path, heading))
    return m.group(1).strip()


def whole(md_path):
    text = (DEMOS / md_path).read_text(encoding="utf-8")
    return re.sub(r"^#\s+.*$", "", text, count=1, flags=re.M).strip()


SOC, MTD = deck_notes(SOC_DECK), deck_notes(MTD_DECK)


def from_deck(notes, slides):
    out = []
    for n in slides:
        title, body = notes[n]
        if not body:
            continue
        out.append("### Slide %d — %s\n\n%s" % (n, title or "(no title)", body))
    return "\n\n".join(out)


# ------------------------------------------------------------------ chapters
chapters = []


def ch(title, body):
    chapters.append((title, body.strip()))


ch("How to use this", """
This is the presenter-side material for the two MMS 2026 Midway demo
sessions, pulled from the slide decks' speaker notes and the demo folders
in `rod-trent/MMSMOA`. It is ordered the way the sessions run.

Each demo chapter has the same four parts:

**From the deck** — the speaker notes for the slides that demo sits behind.

**Run this** — the exact commands, in order.

**Beats to narrate** — the moments worth slowing down for. These used to be
printed in the demo output itself in yellow; they were moved out so the room
would stop reading your stage directions off the projector. They live here now.

**If it breaks** — the fallback, decided in advance.

A note on the demo output: the yellow lines that still appear on screen are
marked `>> WHY THIS MATTERS:` and are written *for the room to read*. They are
commentary on what just happened, not cues for you. Expand on them; do not read
them aloud verbatim.

Playback pauses at every one of those lines, and before each stage header.
Space continues, right-arrow skips to the end, and `+` / `-` change the text
size for the back of the room.
""")

# --- fallbacks first: the thing you need when something is already wrong ----
ch("Fallbacks at a glance", """
If a live demo dies, every mission has a silent recorded run baked from the
same code, playable from its card on the demo site. Reach for it rather than
debugging in front of the room.

### Empowering SOC Teams

%s

### Ask Like an Analyst

%s

### Modern Threat Detection — Mission 1

%s

### The universal fallback

Every mission has a recorded MP4 in `web/public/video/`, and the demo site
falls back to a baked transcript automatically if Pyodide cannot load. The
status pill tells you which engine is running. The audience cannot tell the
difference.
""" % (section("empowering-soc-teams/01-mcp-connection/README.md", "If it breaks"),
       section("empowering-soc-teams/02-natural-language-triage/README.md", "If it breaks"),
       section("modern-threat-detection/02-hypothesis-hunt/README.md", "If it breaks")))

# ============================ SESSION 1 ====================================
ch("Session 1 — Empowering SOC Teams", """
Monday 26 October, 3:00pm PDT, Seaport H. With Rod Trent and Ken Goossens.

%s

## Pre-flight

%s

## From the deck — the Live Missions handoff

%s
""" % (section("empowering-soc-teams/README.md", "Stage running order"),
       section("empowering-soc-teams/README.md", "Pre-flight"),
       from_deck(SOC, [13])))

ch("SOC Demo 1 — Wire the Model", """
Slide 14. Register the app, point the assistant at the Sentinel MCP server.

## From the deck

%s

## Run this

%s

## Beats to narrate

%s

## If it breaks

%s
""" % (from_deck(SOC, [14]),
       section("empowering-soc-teams/01-mcp-connection/README.md", "Run it"),
       section("empowering-soc-teams/01-mcp-connection/README.md", "Stage notes"),
       section("empowering-soc-teams/01-mcp-connection/README.md", "If it breaks")))

ch("SOC Demo 2 — Ask Like an Analyst", """
Slide 15. The Mission 1 walkthrough: natural language to evidence, no KQL.

## From the deck

%s

## The scenario

%s

## Run this

%s

## Beats to narrate

%s

## If it breaks

%s
""" % (from_deck(SOC, [15]),
       section("empowering-soc-teams/02-natural-language-triage/README.md", "The scenario"),
       section("empowering-soc-teams/02-natural-language-triage/README.md", "Run it"),
       section("empowering-soc-teams/02-natural-language-triage/README.md", "Stage notes"),
       section("empowering-soc-teams/02-natural-language-triage/README.md", "If it breaks")))

ch("SOC Demo 2 — the prompts, verbatim",
   "These are the prompts to type, in order.\n\n" +
   whole("empowering-soc-teams/02-natural-language-triage/prompts.md"))

ch("SOC Demo 3 — Auto-Triage and the Human Trigger", """
Slides 16 to 18. The agent runs the loop; the analyst keeps the trigger.

## From the deck

%s

## Run this

%s

## The stage sequence

%s
""" % (from_deck(SOC, [16, 17, 18]),
       section("empowering-soc-teams/03-triage-agent-hitl/README.md", "Run it"),
       section("empowering-soc-teams/03-triage-agent-hitl/README.md", "The stage sequence")))

ch("SOC Demo 4 — Guardrails and Injection", """
Slide 20. The prompt-injection defence, tested rather than asserted.

## From the deck

%s

## Run this

%s

## Beats to narrate

%s
""" % (from_deck(SOC, [20]),
       section("empowering-soc-teams/04-guardrails-injection-test/README.md", "Run it"),
       section("empowering-soc-teams/04-guardrails-injection-test/README.md", "Stage note")))

ch("SOC Demo 5 — Measuring ROI", """
Slides 21 and 22. Instrument first, automate second.

## From the deck

%s

## Run this

%s

## Beats to narrate

%s
""" % (from_deck(SOC, [21, 22]),
       section("empowering-soc-teams/05-roi-baseline/README.md", "Run it"),
       section("empowering-soc-teams/05-roi-baseline/README.md", "Stage note")))

# ============================ SESSION 2 ====================================
ch("Session 2 — Using AI for Modern Threat Detection", """
Tuesday 27 October, 10:00am PDT, Seaport G. With Rod Trent and Chris Sires.

%s

## The three lines that carry the session

%s

## Pre-flight

%s

## From the deck — the Live Missions handoff

%s
""" % (section("modern-threat-detection/README.md", "Stage running order"),
       section("modern-threat-detection/README.md", "The three lines that carry the session"),
       section("modern-threat-detection/README.md", "Pre-flight for the live version"),
       from_deck(MTD, [14])))

ch("Hunt Demo 1 — Prompt Patterns", """
Slides 11 and 12. The hypothesis linter, and the anatomy of a hunting prompt.

## From the deck

%s

## Run this

%s

## Beats to narrate

%s
""" % (from_deck(MTD, [11, 12, 13]),
       section("modern-threat-detection/01-prompt-patterns/README.md", "Run it"),
       section("modern-threat-detection/01-prompt-patterns/README.md", "Stage note")))

ch("Hunt Demo 2 — Speed the Investigation", """
Slides 15 and 16. Hypothesis to evidence with no hand-written KQL.

## From the deck

%s

## The hypothesis

%s

## What makes this demo work: the decoy

%s

## Run this

%s

## The three moments to narrate

%s

## Timing

%s

## If it breaks

%s
""" % (from_deck(MTD, [15, 16]),
       section("modern-threat-detection/02-hypothesis-hunt/README.md", "The hypothesis"),
       section("modern-threat-detection/02-hypothesis-hunt/README.md",
               "What makes this demo work: the decoy"),
       section("modern-threat-detection/02-hypothesis-hunt/README.md", "Run it"),
       section("modern-threat-detection/02-hypothesis-hunt/README.md",
               "The three moments to narrate"),
       section("modern-threat-detection/02-hypothesis-hunt/README.md", "Timing"),
       section("modern-threat-detection/02-hypothesis-hunt/README.md", "If it breaks")))

ch("Hunt Demo 3 — What the Rules Missed", """
Slides 17 and 18. Anomalies first, alerts second, ending in a detection rule.

## From the deck

%s

## The finding

%s

## Run this

%s

## The five steps

%s

## The guardrail worth demoing

%s

## About that threshold

%s
""" % (from_deck(MTD, [17, 18]),
       section("modern-threat-detection/03-anomaly-to-detection/README.md", "The finding"),
       section("modern-threat-detection/03-anomaly-to-detection/README.md", "Run it"),
       section("modern-threat-detection/03-anomaly-to-detection/README.md", "The five steps"),
       section("modern-threat-detection/03-anomaly-to-detection/README.md",
               "The guardrail worth demoing"),
       section("modern-threat-detection/03-anomaly-to-detection/README.md",
               "About that threshold")))

ch("Hunt Demo 4 — Validate Before You Believe", """
Slides 19 and 20. A model finding is a lead until a human makes it evidence.

## From the deck

%s

## The claim being tested

%s

## Run this

%s

## Technique 4 is the one that matters

%s

## Beats to narrate

%s
""" % (from_deck(MTD, [19, 20]),
       section("modern-threat-detection/04-validation-harness/README.md", "The claim being tested"),
       section("modern-threat-detection/04-validation-harness/README.md", "Run it"),
       section("modern-threat-detection/04-validation-harness/README.md",
               "Technique 4 is the one that matters"),
       section("modern-threat-detection/04-validation-harness/README.md", "Stage note")))

ch("Hunt Demo 5 — Leakage and Prompt Injection", """
Slide 21. Why a hunt needs its own threat model.

## From the deck

%s

## Why a hunt needs its own threat model

%s

## Run this

%s

## The honest conclusion

%s
""" % (from_deck(MTD, [21]),
       section("modern-threat-detection/05-injection-redteam/README.md",
               "Why a hunt needs its own threat model"),
       section("modern-threat-detection/05-injection-redteam/README.md", "Run it"),
       section("modern-threat-detection/05-injection-redteam/README.md",
               "The honest conclusion")))

ch("The URLs", """
Nothing printed on the slides shows a real address any more - every URL on
them is a tracked short link. If anyone asks, these are the destinations.

| Short link | Goes to |
|---|---|
| `go.rodtrent.com/go/8sxe66m` | `mms-midway-demos.vercel.app/?s=soc` — the SOC session tab |
| `go.rodtrent.com/go/c638n85` | `mms-midway-demos.vercel.app/?s=hunt` — the hunt session tab |
| `go.rodtrent.com/go/eje7vdj` | `github.com/rod-trent/MMSMOA` — the repo |

The plain site address, for anyone who wants to type it:
**mms-midway-demos.vercel.app**

Before you present, open the site once on each machine and hard-reload
(Ctrl+Shift+R). An older service worker may otherwise serve a stale copy of
the page the first time it loads.
""")

# ------------------------------------------------------------------ to EPUB
CSS = """
html, body { margin: 0; padding: 0; }
body { font-family: serif; line-height: 1.5; margin: 0 0.6em; widows: 2; orphans: 2; }
h1 { font-size: 1.5em; line-height: 1.25; margin: 1em 0 0.6em; page-break-before: always; }
h2 { font-size: 1.2em; margin: 1.4em 0 0.4em; }
h3 { font-size: 1.05em; margin: 1.2em 0 0.3em; }
p, li { font-size: 1em; }
ul, ol { margin: 0.5em 0 0.5em 1.1em; padding-left: 0.4em; }
li { margin: 0.25em 0; }
/* Kindle will not scroll sideways: force long commands to wrap. */
pre, code, kbd {
  font-family: monospace;
  white-space: pre-wrap;
  word-wrap: break-word;
  overflow-wrap: break-word;
  word-break: break-all;
}
pre {
  font-size: 0.8em; line-height: 1.35;
  margin: 0.7em 0; padding: 0.5em 0.6em;
  background: #f2f2f2; border-left: 3px solid #999;
}
code { font-size: 0.88em; }
pre code { font-size: 1em; background: none; }
blockquote { margin: 0.7em 0.8em; font-style: italic; }
table { border-collapse: collapse; width: 100%; margin: 0.7em 0; font-size: 0.9em; }
th, td { border: 1px solid #999; padding: 0.3em 0.4em; text-align: left; }
th { background: #eee; }
hr { border: none; border-top: 1px solid #ccc; margin: 1.2em 0; }
/* Wide tables, re-cast as blocks so they reflow on a small screen. */
.wrow { margin: 0.8em 0; padding-left: 0.6em; border-left: 2px solid #bbb; }
.wkey { font-weight: bold; margin: 0 0 0.2em; }
.wrow ul { margin: 0.2em 0 0 1em; padding-left: 0.3em; }
.wrow li { margin: 0.15em 0; }
"""

MD = markdown.Markdown(extensions=["tables", "fenced_code", "sane_lists"])

TH = re.compile(r"<th[^>]*>(.*?)</th>", re.S)
TD = re.compile(r"<td[^>]*>(.*?)</td>", re.S)
TR = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S)
TABLE = re.compile(r"<table>(.*?)</table>", re.S)


def unwide(doc, limit=3):
    """Re-cast tables wider than `limit` columns as per-row blocks.

    A six-column table is unreadable on a Kindle at any font size - the
    columns either squeeze to nothing or run off the page. One block per
    row, keyed on the first cell, reflows properly.
    """
    def one(m):
        inner = m.group(1)
        heads = [h.strip() for h in TH.findall(inner)]
        if len(heads) <= limit:
            return m.group(0)
        body = inner.split("</thead>", 1)[-1]
        out = ['<div class="wtable">']
        for row in TR.findall(body):
            cells = [c.strip() for c in TD.findall(row)]
            if not cells:
                continue
            out.append('<div class="wrow">')
            out.append('<p class="wkey">%s</p>' % cells[0])
            out.append("<ul>")
            for h, c in zip(heads[1:], cells[1:]):
                if not c or c == "&nbsp;":
                    continue
                out.append("<li><strong>%s:</strong> %s</li>" % (h, c))
            out.append("</ul></div>")
        out.append("</div>")
        return "\n".join(out)
    return TABLE.sub(one, doc)


PAGE = ('<?xml version="1.0" encoding="utf-8"?>\n'
        '<!DOCTYPE html>\n'
        '<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">\n'
        '<head><meta charset="utf-8"/><title>%s</title>'
        '<link rel="stylesheet" type="text/css" href="style.css"/></head>\n'
        '<body>\n<h1>%s</h1>\n%s\n</body>\n</html>\n')

if args.list:
    for i, (title, _) in enumerate(chapters, 1):
        print("%2d  %s" % (i, title))
    raise SystemExit(0)

files = []
for i, (title, body) in enumerate(chapters, 1):
    MD.reset()
    files.append(("ch%02d.xhtml" % i, title,
                  PAGE % (html.escape(title), html.escape(title),
                          unwide(MD.convert(body)))))

TITLE = "MMS 2026 Midway — Presenter Companion"
UID = "urn:uuid:mms-midway-2026-presenter-companion"

manifest = "\n".join(
    '    <item id="c%02d" href="%s" media-type="application/xhtml+xml"/>' % (i, f)
    for i, (f, _, _) in enumerate(files, 1))
spine = "\n".join('    <itemref idref="c%02d"/>' % i for i in range(1, len(files) + 1))

opf = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="bookid">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:identifier id="bookid">%s</dc:identifier>
    <dc:title>%s</dc:title>
    <dc:creator>Rod Trent</dc:creator>
    <dc:language>en</dc:language>
    <meta property="dcterms:modified">2026-10-20T00:00:00Z</meta>
  </metadata>
  <manifest>
    <item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>
    <item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
    <item id="css" href="style.css" media-type="text/css"/>
%s
  </manifest>
  <spine toc="ncx">
    <itemref idref="nav"/>
%s
  </spine>
</package>
""" % (UID, html.escape(TITLE), manifest, spine)

nav_items = "\n".join('      <li><a href="%s">%s</a></li>' % (f, html.escape(t))
                      for f, t, _ in files)
nav = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops"
      xml:lang="en" lang="en">
<head><meta charset="utf-8"/><title>Contents</title>
<link rel="stylesheet" type="text/css" href="style.css"/></head>
<body>
  <nav epub:type="toc" id="toc"><h1>Contents</h1>
    <ol>
%s
    </ol>
  </nav>
</body>
</html>
""" % nav_items

ncx_points = "\n".join(
    '    <navPoint id="n%02d" playOrder="%d"><navLabel><text>%s</text></navLabel>'
    '<content src="%s"/></navPoint>' % (i, i, html.escape(t), f)
    for i, (f, t, _) in enumerate(files, 1))
ncx = """<?xml version="1.0" encoding="utf-8"?>
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
  <head><meta name="dtb:uid" content="%s"/></head>
  <docTitle><text>%s</text></docTitle>
  <navMap>
%s
  </navMap>
</ncx>
""" % (UID, html.escape(TITLE), ncx_points)

OUT.parent.mkdir(parents=True, exist_ok=True)
if OUT.exists():
    OUT.unlink()
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    # mimetype must be first and stored, per the EPUB spec
    z.writestr(zipfile.ZipInfo("mimetype"), "application/epub+zip",
               compress_type=zipfile.ZIP_STORED)
    z.writestr("META-INF/container.xml",
               '<?xml version="1.0" encoding="utf-8"?>\n'
               '<container version="1.0" '
               'xmlns="urn:oasis:names:tc:opendocument:xmlns:container">\n'
               '  <rootfiles><rootfile full-path="OEBPS/content.opf" '
               'media-type="application/oebps-package+xml"/></rootfiles>\n'
               '</container>\n')
    z.writestr("OEBPS/content.opf", opf)
    z.writestr("OEBPS/nav.xhtml", nav)
    z.writestr("OEBPS/toc.ncx", ncx)
    z.writestr("OEBPS/style.css", CSS)
    for name, _, data in files:
        z.writestr("OEBPS/" + name, data)

print("wrote %s  (%d chapters, %.0f KB)" % (OUT, len(files), OUT.stat().st_size / 1024))
for i, (f, t, _) in enumerate(files, 1):
    print("  %2d  %s" % (i, t))
