#!/usr/bin/env python3
"""
record-demos.py
===============
Renders the four MMS Midway mission demos to MP4.

    python record-demos.py                 # all four
    python record-demos.py --only soc-m2   # one
    python record-demos.py --list
    python record-demos.py --preview soc-m2   # single PNG, no encoding

These are the recorded backups both decks call for on every mission slide
(14 and 17 in Empowering SOC Teams; 14 and 16 in Modern Threat Detection).

They are SILENT screen recordings, not narrated walkthroughs. The MOA videos in
this repo are named "-voiced" because someone talked over them; these are not,
and are named accordingly. Do not present one as the other.

How it works
------------
Frames are drawn from the transcripts under web/public/transcripts/, which
web/build.py bakes by running the real demo scripts with colour forced on, and
which CI re-checks on every push. So the video shows the same output the code
produces - not a re-enactment.

Playback pauses on the same beats the live runner does: every ">> STAGE NOTE:",
and before each STAGE/STEP header. That is what makes it usable as a stand-in
if the live demo dies - it has the same rhythm you would have talked over.

Requires: pillow, imageio-ffmpeg (both already used elsewhere in this repo).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
TRANSCRIPTS = ROOT / "web" / "public" / "transcripts"

# ---------------------------------------------------------------------------
# What to record
# ---------------------------------------------------------------------------

# The videos live inside the site so Vercel can serve them; .vercelignore
# excludes demos/, and the demo READMEs link here.
VIDEO = "web/public/video"

RECORDINGS = [
    {
        "id": "soc-m1",
        "title": "Mission 1 — Ask Like an Analyst",
        "session": "Empowering SOC Teams",
        "slides": "slides 14–15",
        "parts": [("python triage_walkthrough.py", "soc-triage-walkthrough-0")],
        "out": f"{VIDEO}/demo-08-mission1-triage.mp4",
    },
    {
        "id": "soc-m2",
        "title": "Mission 2 — Auto-Triage + Human on the Trigger",
        "session": "Empowering SOC Teams",
        "slides": "slides 16–18",
        # The stage sequence is both runs: the clean one, then the rejection.
        "parts": [
            ("python soc_triage_agent.py --incident 48213", "soc-triage-agent-1"),
            ("python soc_triage_agent.py --incident 48201  # rejected on purpose",
             "soc-triage-agent-2"),
        ],
        "out": f"{VIDEO}/demo-09-triage-agent-hitl.mp4",
    },
    {
        "id": "hunt-m1",
        "title": "Mission 1 — Speed the Investigation",
        "session": "Using AI for Modern Threat Detection",
        "slides": "slides 14–15",
        "parts": [("python hunt_service_accounts.py", "hunt-mission1-0")],
        "out": f"{VIDEO}/demo-10-hypothesis-hunt.mp4",
    },
    {
        "id": "hunt-m2",
        "title": "Mission 2 — What the Rules Missed",
        "session": "Using AI for Modern Threat Detection",
        "slides": "slides 16–17",
        "parts": [("python anomaly_to_detection.py", "hunt-mission2-0")],
        "out": f"{VIDEO}/demo-11-anomaly-to-detection.mp4",
    },
]

# ---------------------------------------------------------------------------
# Look. Matches the demo site's terminal so the video and the live page agree.
# ---------------------------------------------------------------------------

W, H = 1920, 1080
FPS = 15   # a terminal has no motion; 15 halves the file for no visible loss

BG = (0x00, 0x09, 0x1C)
CHROME = (0x0B, 0x1A, 0x3A)
LINE = (0x2C, 0x41, 0x80)

INK = (0xC9, 0xD6, 0xF0)
COLORS = {
    "dim": (0x8F, 0xA5, 0xD4),
    "bold": (0xFF, 0xFF, 0xFF),
    "red": (0xFF, 0x7A, 0x7A),
    "green": (0x5A, 0xD1, 0x8F),
    "yellow": (0xF2, 0xB1, 0x34),
    "blue": (0x60, 0xA5, 0xFA),
    "magenta": (0xC0, 0x84, 0xFC),
    "cyan": (0x22, 0xD3, 0xEE),
    "white": (0xF1, 0xF5, 0xF9),
}
SGR = {1: "bold", 2: "dim", 31: "red", 32: "green", 33: "yellow",
       34: "blue", 35: "magenta", 36: "cyan", 37: "white"}

FONT_DIR = Path("C:/Windows/Fonts")
FONT_SIZE = 21
LINE_H = 29
PAD_X, TOP = 54, 132
BOTTOM = 56

ANSI = re.compile(r"\x1b\[([0-9;]*)m")


def load_fonts():
    for mono, bold in (("CascadiaMono.ttf", "CascadiaMono.ttf"),
                       ("consola.ttf", "consolab.ttf"),
                       ("cour.ttf", "courbd.ttf")):
        p = FONT_DIR / mono
        if p.exists():
            return (ImageFont.truetype(str(p), FONT_SIZE),
                    ImageFont.truetype(str(FONT_DIR / bold), FONT_SIZE),
                    ImageFont.truetype(str(FONT_DIR / bold), 30),
                    ImageFont.truetype(str(p), 20))
    raise SystemExit("No monospace font found in C:/Windows/Fonts")


MONO, MONO_B, TITLE_F, SMALL_F = load_fonts()
CHAR_W = MONO.getlength("M")
VISIBLE = (H - TOP - BOTTOM) // LINE_H


# ---------------------------------------------------------------------------
# Transcript -> styled spans
# ---------------------------------------------------------------------------


def parse(text: str) -> list[list[tuple[str, tuple, bool]]]:
    """Split ANSI text into lines of (text, rgb, bold) spans."""
    lines: list[list[tuple[str, tuple, bool]]] = []
    colour, bold, dim = INK, False, False

    for raw in text.replace("\r\n", "\n").split("\n"):
        spans: list[tuple[str, tuple, bool]] = []
        pos = 0
        for m in ANSI.finditer(raw):
            chunk = raw[pos:m.start()]
            if chunk:
                spans.append((chunk, COLORS["dim"] if dim and colour is INK else colour, bold))
            pos = m.end()
            codes = [int(c) for c in m.group(1).split(";") if c != ""] or [0]
            for c in codes:
                if c == 0:
                    colour, bold, dim = INK, False, False
                elif c == 1:
                    bold = True
                    colour = COLORS["bold"]
                elif c == 2:
                    dim = True
                elif c in SGR:
                    colour = COLORS[SGR[c]]
        tail = raw[pos:]
        if tail:
            spans.append((tail, COLORS["dim"] if dim and colour is INK else colour, bold))
        lines.append(spans)
    return lines


def plain(spans) -> str:
    return "".join(s[0] for s in spans)


# The same pause rules the live runner uses, so a recording and the page stop
# in the same places. MODE mirrors the site's pause selector.
MODE = "steps"          # "beats" | "steps"

_STEP_AFTER = (
    re.compile(r"^\s*\[\s*(PASS|FAIL|ok|SKIP|WARN)\s*\]", re.I),   # harness results
    re.compile(r"^\s*\[(yes|no)\s*\]", re.I),                      # benign checks
    re.compile(r"^\s*(INJ|HUNT-INJ|LEAK|BENIGN)-\d+"),             # scorecard rows
    re.compile(r"^\s{2,}\[tool\]"),                                # agent tool calls
)

_STEP_BEFORE = (
    re.compile(r"^\s*\d+\.\s+[A-Z]"),          # "4. Seed known bad"
    re.compile(r"^(HUNTER|ANALYST)\s+>"),      # the human's next prompt
)


def pause_after(text: str):
    """Seconds to hold after printing this line, or None."""
    if "STAGE NOTE:" in text:
        return 2.6                             # the big "talk here" moments
    if MODE != "steps":
        return None
    if any(p.match(text) for p in _STEP_AFTER):
        return 1.2                             # step-level: enough for one sentence
    return None


def pause_before(text: str):
    """Seconds to hold before printing this line, or None."""
    if re.match(r"^\s*(STAGE|STEP)\s+\d+/\d+", text) or \
       "REQUIRES HUMAN APPROVAL" in text or \
       re.match(r"^\s*VERDICT:", text):
        return 1.6
    if MODE != "steps":
        return None
    if any(p.match(text) for p in _STEP_BEFORE):
        return 1.4
    return None


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------


def frame(rec, cmd, window, note=None) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # Chrome
    d.rectangle([0, 0, W, TOP - 18], fill=CHROME)
    d.line([0, TOP - 18, W, TOP - 18], fill=LINE, width=2)
    d.text((PAD_X, 30), rec["title"], font=TITLE_F, fill=(0xFF, 0xFF, 0xFF))
    d.text((PAD_X, 74), f"{rec['session']}  ·  {rec['slides']}",
           font=SMALL_F, fill=COLORS["dim"])
    d.text((W - PAD_X - SMALL_F.getlength("MMS 2026 Midway Edition"), 74),
           "MMS 2026 Midway Edition", font=SMALL_F, fill=COLORS["dim"])
    cw = SMALL_F.getlength(cmd)
    d.text((W - PAD_X - cw, 34), cmd, font=SMALL_F, fill=COLORS["yellow"])

    # Body
    y = TOP
    for spans in window:
        x = PAD_X
        for text, rgb, bold in spans:
            d.text((x, y), text, font=MONO_B if bold else MONO, fill=rgb)
            x += CHAR_W * len(text)
        y += LINE_H

    # Footer
    d.line([0, H - BOTTOM + 6, W, H - BOTTOM + 6], fill=LINE, width=2)
    foot = note or "github.com/rod-trent/MMSMOA   ·   synthetic data, no real tenant"
    d.text((PAD_X, H - BOTTOM + 18), foot, font=SMALL_F,
           fill=COLORS["yellow"] if note else COLORS["dim"])
    return img


def title_card(rec) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((PAD_X, H // 2 - 90), rec["session"], font=SMALL_F, fill=COLORS["dim"])
    d.text((PAD_X, H // 2 - 52), rec["title"], font=TITLE_F, fill=(0xFF, 0xFF, 0xFF))
    d.text((PAD_X, H // 2 + 6), rec["slides"], font=SMALL_F, fill=COLORS["yellow"])
    d.text((PAD_X, H // 2 + 62),
           "Recorded from the repository's own demo scripts. No narration.",
           font=SMALL_F, fill=COLORS["dim"])
    d.text((PAD_X, H // 2 + 92),
           "All tenant data is synthetic.", font=SMALL_F, fill=COLORS["dim"])
    return img


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def build_frames(rec):
    """Yield PIL frames for the whole recording."""
    import imageio_ffmpeg  # noqa: F401  (checked early, used by caller)

    card = title_card(rec)
    for _ in range(FPS * 3):
        yield card

    for cmd, key in rec["parts"]:
        path = TRANSCRIPTS / f"{key}.txt"
        if not path.exists():
            raise SystemExit(f"missing transcript {path} - run: python web/build.py")
        lines = parse(path.read_text(encoding="utf-8"))

        shown: list = []
        for i, spans in enumerate(lines):
            text = plain(spans)

            hold_s = pause_before(text) if i > 0 else None
            if hold_s:
                label = re.sub(r"\s+", " ", text).strip()[:70]
                hold = frame(rec, cmd, shown[-VISIBLE:], note=f"next  ·  {label}")
                for _ in range(int(FPS * hold_s)):
                    yield hold

            shown.append(spans)
            f = frame(rec, cmd, shown[-VISIBLE:])
            # Blank lines flick past; content lines get a readable beat.
            for _ in range(1 if text.strip() == "" else 2):
                yield f

            hold_s = pause_after(text)
            if hold_s:
                note = ("stage note  ·  talk here" if "STAGE NOTE:" in text
                        else re.sub(r"\s+", " ", text).strip()[:70])
                hold = frame(rec, cmd, shown[-VISIBLE:], note=note)
                for _ in range(int(FPS * hold_s)):
                    yield hold

        end = frame(rec, cmd, shown[-VISIBLE:])
        for _ in range(FPS * 2):
            yield end


def record(rec, out_root: Path) -> Path:
    import imageio_ffmpeg

    out = out_root / rec["out"]
    out.parent.mkdir(parents=True, exist_ok=True)
    exe = imageio_ffmpeg.get_ffmpeg_exe()

    cmd = [
        exe, "-y", "-loglevel", "error",
        "-f", "rawvideo", "-pix_fmt", "rgb24",
        "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-",
        "-an",
        # -tune stillimage is built for exactly this: large flat areas and
        # sharp text. With crf 30 it halves the file and the glyphs stay
        # crisp - checked by extracting frames, not assumed.
        "-c:v", "libx264", "-preset", "veryslow", "-crf", "30",
        "-tune", "stillimage", "-pix_fmt", "yuv420p",
        # Long GOPs suit near-static content; faststart lets the video play
        # before it has finished downloading from GitHub.
        "-g", str(FPS * 20), "-movflags", "+faststart",
        str(out),
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    n = 0
    for img in build_frames(rec):
        proc.stdin.write(img.tobytes())
        n += 1
    proc.stdin.close()
    if proc.wait() != 0:
        raise SystemExit(f"ffmpeg failed for {rec['id']}")

    size = out.stat().st_size
    print(f"  {rec['id']:<9} {n/FPS:6.1f}s  {size/1_048_576:5.2f} MB  {rec['out']}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Record the Midway mission demos to MP4.")
    ap.add_argument("--only", help="Record just this id.")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--preview", metavar="ID", help="Write one PNG and stop.")
    ap.add_argument("--pauses", choices=("beats", "steps"), default="steps",
                    help="Where to hold. 'steps' matches the site's step-through "
                         "mode: every tool call, check and result. Default: steps.")
    args = ap.parse_args()

    global MODE
    MODE = args.pauses

    if args.list:
        for r in RECORDINGS:
            print(f"  {r['id']:<9} {r['title']:<48} -> {r['out']}")
        return 0

    try:
        import imageio_ffmpeg  # noqa: F401
    except ImportError:
        raise SystemExit("pip install imageio-ffmpeg")

    todo = [r for r in RECORDINGS if args.only in (None, r["id"])
            and args.preview in (None, r["id"])]
    if not todo:
        raise SystemExit(f"no recording matches {args.only or args.preview!r}")

    if args.preview:
        rec = todo[0]
        frames = list(build_frames(rec))
        mid = frames[len(frames) * 2 // 3]
        p = ROOT / f"preview-{rec['id']}.png"
        mid.save(p)
        print(f"wrote {p}")
        return 0

    print(f"\nRecording {len(todo)} demo(s) at {W}x{H} {FPS}fps\n")
    for rec in todo:
        record(rec, ROOT)
    print("\nThese are silent. Do not label them '-voiced'.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
