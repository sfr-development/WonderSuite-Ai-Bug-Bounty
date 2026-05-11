# WonderSuite — Flex Deck (Skid / LARP audience)

Third campaign. Targets the script-kiddie / cybersecurity-LARP segment on TikTok. Strategy, tone, and slide concepts are all derived from the research doc in this folder.

> **Read this first:** [`MARKET-RESEARCH.md`](MARKET-RESEARCH.md) — full audience profile, competitor landscape, hook archetypes, language patterns.

## The slides

| # | File | Archetype | Hook |
|---|---|---|---|
| 01 | `slide-01-hook.html` | Insult-with-out | "Your stack is mid. Upgrade." |
| 02 | `slide-02-pov.html` | Aesthetic flex | "POV: your demos actually look the part." |
| 03 | `slide-03-afk.html` | AI flex | "Let your AI pop the box while you afk." (with fake terminal) |
| 04 | `slide-04-loadout.html` | Power flex | "69 tools. One binary. $0 invoice." |
| 05 | `slide-05-receipts.html` | Proof | 4-up screenshot grid: Scanner / Intruder / OSINT / Sitemap |
| 06 | `slide-06-cta.html` | Status CTA | "Stop coping. Get the gear." |

## Preview & export

- `index.html` — 3 × 2 grid, click any tile.
- `export-png.cmd` — double-click → `out/*.png` at 1080 × 1920.

## How this deck differs from the other two

| Deck | Tone | Audience | Hook angle |
|---|---|---|---|
| `tiktok-slides/` | Polished, professional | General security/dev | "Free alternative with AI" |
| `tiktok-slides-vs-burp/` | Comparative, receipts | Burp users + team leads | "$475/yr for software your AI can't use" |
| `tiktok-slides-flex/` (this one) | Insider, terminal-coded, slightly cocky | Skids, LARPs, HTB/THM crowd | "Your stack is mid. Upgrade." |

Run them as a **3-week rotation** — not all at once. Different decks for different algorithm cycles. The flex deck is the most likely to fork comment threads (which is good for reach).

## Tone notes (please don't soften)

- Insults are **ego-defense triggers, not bullying**. They make the viewer self-identify into the "now I'm not a skid" camp.
- The terminal output on slide 3 is fake-but-plausible. Don't replace it with real tool output — fake is more readable.
- Slide 6 ends with "the seniors are already using it." That's aspirational social proof. Don't water it down.
- No emojis anywhere in the slides (consistent with your style preference).

## Posting strategy

- Post slide 1 alone as a Reels/Shorts teaser 24 h before the full deck drops. Caption: *"if you flinched at this you needed to see it."*
- Full deck caption: *"market research said this is the deck you'd hate-share. proving them right →"*
- Pin a comment with the GitHub URL. Don't argue feature-by-feature in replies; let the loud threads burn out and bring traffic.
- Hashtags: `#hackertok #cybersecurity #infosec #bugbounty #pentesting #hacking #ctf #htb #tryhackme #kalilinux #opensource #rust`

## Editing

All slides are pure HTML + the shared `styles.css`. Change copy, swap screenshots in `../docs/screenshots/`, or add slides — no build step.
