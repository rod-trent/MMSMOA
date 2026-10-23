# Slide Decks

## MMS 2026 Midway Edition — San Diego, 25–28 October 2026

| Deck | Session | Slot |
|------|---------|------|
| `Empowering SOC Teams - MMS Midway 2026.pptx` | Empowering SOC Teams: How Claude, Copilot, ChatGPT, MCP Servers, and Agents Drive Efficiency | Mon 26 Oct, 3:00pm PDT · Seaport H |
| `Using AI for Modern Threat Detection - MMS Midway 2026.pptx` | Using AI for Modern Threat Detection | Tue 27 Oct, 10:00am PDT · Seaport G |

Both decks carry full speaker notes on every slide, including pre-flight
requirements and fallback plans for each live mission.

**Demo slides map to code:**

| Deck | Slide | Demo |
|------|-------|------|
| Empowering SOC Teams | 14–15 (Mission 1) | [`01-mcp-connection`](../demos/empowering-soc-teams/01-mcp-connection/), [`02-natural-language-triage`](../demos/empowering-soc-teams/02-natural-language-triage/) |
| Empowering SOC Teams | 16–23 (Mission 2) | [`03-triage-agent-hitl`](../demos/empowering-soc-teams/03-triage-agent-hitl/) |
| Empowering SOC Teams | 25 (guardrails) | [`04-guardrails-injection-test`](../demos/empowering-soc-teams/04-guardrails-injection-test/) |
| Empowering SOC Teams | 26–27 (ROI, 30/60/90) | [`05-roi-baseline`](../demos/empowering-soc-teams/05-roi-baseline/) |
| Modern Threat Detection | 11–12 (prompt patterns) | [`01-prompt-patterns`](../demos/modern-threat-detection/01-prompt-patterns/) |
| Modern Threat Detection | 14–15 (Mission 1) | [`02-hypothesis-hunt`](../demos/modern-threat-detection/02-hypothesis-hunt/) |
| Modern Threat Detection | 16–17 (Mission 2) | [`03-anomaly-to-detection`](../demos/modern-threat-detection/03-anomaly-to-detection/) |
| Modern Threat Detection | 19 (validation) | [`04-validation-harness`](../demos/modern-threat-detection/04-validation-harness/) |
| Modern Threat Detection | 20 (leakage, injection) | [`05-injection-redteam`](../demos/modern-threat-detection/05-injection-redteam/) |

## MMS MOA 2026 — Mall of America

| Deck | Session |
|------|---------|
| `Agentic Threat Hunting - MMS MOA 2026.pptx` | Agentic Threat Hunting with Microsoft Sentinel: From MCP Server to Graph Insights (44 slides) |
| `Governing GenAI - MMS MOA 2026.pptx` | Governing GenAI: Monitoring and Securing Copilot with Microsoft Purview (49 slides) |

Demo walkthrough MP4s are embedded on each demo slide and also live in the demo
folders.


### The demo site

Both decks carry **[mms-midway-demos.vercel.app](https://mms-midway-demos.vercel.app)**
on two slides: the *Live Missions* section header (with a QR, so the room can
follow along on their own laptops while you present) and *Takeaways*.

Each deck's QR carries its **own session's** tracked short link, so a scan
lands straight on that session's tab rather than the chooser:

| Deck | QR file | Short link | Lands on |
|------|---------|------------|----------|
| Empowering SOC Teams | `qr-demo-site-soc.png` | `go.rodtrent.com/go/8sxe66m` | `/?s=soc` |
| Modern Threat Detection | `qr-demo-site-hunt.png` | `go.rodtrent.com/go/c638n85` | `/?s=hunt` |

33 modules at error-correction level Q, so they survive projector glare and
a keystoned screen. Regenerate with:

```python
import segno
for name, url in [("qr-demo-site-soc.png",  "https://go.rodtrent.com/go/8sxe66m"),
                  ("qr-demo-site-hunt.png", "https://go.rodtrent.com/go/c638n85")]:
    segno.make(url, error="q").save(
        name, scale=24, border=3, dark="#011230", light="#FFFFFF")
```

*Takeaways* prints the same per-session short link, so both URLs on that
line read the same way:

    Every demo runs in your browser:  go.rodtrent.com/go/8sxe66m
       ·  Demo code:  go.rodtrent.com/go/eje7vdj

*Live Missions* prints the same link under its QR, so every URL a Midway
deck shows is a tracked short link and the two slides read alike.

Because of that, nothing on screen says where the links go. The speaker
notes on both slides spell it out - which short link is which, what each
resolves to, and the plain `mms-midway-demos.vercel.app` to give anyone
who asks.

`qr-demo-site.png` is the original session-neutral, untracked code. No
slide uses it any more; it is kept for when you want a plain one.

### The repo short link

**[go.rodtrent.com/go/eje7vdj](https://go.rodtrent.com/go/eje7vdj)** redirects
to this repository and carries UTM tags, so scans and clicks are countable.
Both Midway decks carry it on *Takeaways*, on the same line as the demo site.
The demo site's own *Source* and footer links point at it too, while still
reading as `rod-trent/MMSMOA` so the destination stays visible.

`qr-repo.png` is the matching QR — same recipe and styling as the demo-site
one. Both Midway decks carry the pair side by side on *Live Missions*:
demo site left, repo right, each with its own two-line caption. Regenerate
with:

```python
import segno
segno.make("https://go.rodtrent.com/go/eje7vdj", error="q").save(
    "qr-repo.png", scale=24, border=3, dark="#011230", light="#FFFFFF")
```

The two MOA decks are unchanged: they already carry the full
`github.com/rod-trent/MMSMOA` URL on their demo and resources slides.

---

### Before you present

- Slide 12 of *Modern Threat Detection* is the one the room photographs. It is
  also in the repo as pasteable text: [`hunting-prompt-template.md`](../demos/modern-threat-detection/01-prompt-patterns/hunting-prompt-template.md). Give them the URL.
- Statistics in both Midway decks were verified on 20 October 2026 against
  primary sources. Thirteen of fifteen held. Two did not and were corrected:
  the SANS card on SOC slide 6 claimed "70% of junior analysts leave within
  three years", which appears nowhere in the 2025 SOC Survey - that report
  gives 62% lacking confidence in retention efforts and 3-5 years as the most
  common tenure; and Modern Threat Detection slide 9 read CrowdStrike's 2.5x
  as a yield per detection when it is a growth *rate* of AI agent-triggered
  leads against human-triggered ones. Re-check the rest the week of the
  conference; the 70/56-minute Cybersecurity Insiders figures rest on
  secondary coverage only.
- Hosted Sentinel MCP endpoint URLs have changed before. Re-check against
  Microsoft Learn before Mission 1.
