# Market Research — Skid / LARP Audience

Pre-campaign research for the WonderSuite TikTok deck targeting the "script-kiddie" and "cybersecurity-LARP" segment. Findings drive the slide design that follows in this folder.

---

## 1. Who they are

Two overlapping cohorts. Different motivations, same behaviors on TikTok.

### Skids (Script Kiddies)
- 13–22, predominantly male.
- Use offensive tools they don't fully understand.
- Active on HackTheBox, TryHackMe, PortSwigger Web Security Academy.
- Aspirational: want to be "real" pentesters / red teamers. Some will get there in 2–3 years.
- Currency: HTB rank, THM streak, CTF badges, OSCP/CRTP/CRTO certs (the "Holy Grail" sequence).
- Spending power: low. Most can't or won't pay for Burp Pro. They run cracked Burp or stay on Community Edition.

### LARPs (Live-Action Role Players)
- 16–35, broader age range.
- Pose as hackers on Twitter/X, Discord, TikTok. Mostly *talk* about hacking. Rarely root a real box.
- Cosplay aesthetic: hoodie, dark room, mechanical keyboard, RGB, multiple monitors with terminals open.
- Their tools have to *look* the part in screenshots, more than they have to work.
- Status game is loud: post Nmap output, name-drop Cobalt Strike, share OSCP attempts.
- Spending power: moderate. Will pay for vanity products (Yubikey, Flipper Zero, "hacker" merch).

### Why they matter as an audience
- They are the **fastest-growing slice of security TikTok**. The `#hackertok` tag has ~3B+ views.
- They share aggressively. A skid finding a "broken" tool will spam it across three Discords and post a TikTok the same night.
- Their early-stage attention turns into the next generation of real pentesters, who become long-term users and contributors.

---

## 2. Where they hang out

| Platform | Use case |
|---|---|
| **TikTok** | Discovery. `#hackertok #cybersecurity #infosec #bugbounty #pentesting #kalilinux` |
| **YouTube** | Long-form tutorials. NetworkChuck, John Hammond, LiveOverflow, IppSec, S4vitar are gods |
| **Twitter / X** | Status posts, tool recommendations, "infosec twitter" cliques |
| **Discord** | HTB / THM / vx-underground servers, indie pentesting circles |
| **Reddit** | r/hacking · r/HowToHack · r/AskNetsec · r/oscp · r/netsec |
| **GitHub** | Star-hoarding, fork-as-bookmark behavior |

TikTok is the **top-of-funnel**. They discover here, validate on YouTube, gossip on Discord, brag on Twitter.

---

## 3. What they value (status signals)

In rough order of social weight:
1. **Visible technical receipts** — terminal screenshots, popped boxes, CVE numbers, CTF wins.
2. **Tools associated with elite operators** — Cobalt Strike, Mythic, Sliver, BloodHound, NetExec/CME, Caido.
3. **Aesthetic dominance** — dark theme, monospace fonts, dense data displays, "looks like the matrix".
4. **Self-hosted / open-source / FOSS** — anti-corporate sentiment is strong.
5. **Streaks and ranks** — HTB seasons, OSCP attempt count, GitHub contribution graphs.
6. **Knowing the jargon** — `shell`, `pop`, `root`, `0day`, `RCE`, `SSRF`, `LFI`, `XXE`, `SSTI`, `BOF`, `implant`, `C2`, `living off the land`.

**Anti-status**: corporate UI, GUI without CLI, Java icons, subscription paywalls, anything that smells like Splunk.

---

## 4. What triggers them

### Positive (pulls them in)
- "Replaces Burp" — Burp is the simultaneously-loved and -hated standard.
- "Built in Rust" — bragging-rights tech.
- "AI does the work" — gets attention; agentic hacking is the 2025/2026 trend.
- "Look pro in your demos" — appearance signaling.
- "Used by [known team / CTF]" — proof of competence.
- "Tools you didn't know you needed" — discovery framing.
- Dark, glitchy, terminal-y aesthetics.

### Negative (gets them defensive)
- Being called a script kiddie. Even when accurate, they push back.
- Being told they don't know what they're doing.
- "Educational use only" disclaimers — reads as patronizing.
- Slow setup or installer wizards.

### How to use this
**Frame the upgrade as a flex, not a correction.** Don't say "you're a skid." Say "your stack is mid — upgrade." They self-identify into the "now I'm not a skid anymore" group and re-share.

---

## 5. Competitor landscape

| Tool | Position | Strengths to acknowledge | Weaknesses to exploit |
|---|---|---|---|
| **Burp Suite Pro** | Industry standard | Battle-tested, plugin ecosystem | $475/yr, Java/Swing UI, no MCP |
| **Caido** | Trendy modern Burp alt (Rust) | Clean UI, FOSS-aligned, growing fast | No AI/MCP, project still maturing, paid tiers planned |
| **HTTP Toolkit** | Friendly proxy/intercept | Easy onboarding | Limited scope — proxy only |
| **OWASP ZAP** | Free open alternative to Burp | Truly free | Looks like 2010, slow, abandoned by trendsetters |
| **Kali Linux** | The "skid distro" | Whole-OS approach, packed | Heavy, requires VM/dual-boot, not a tool |
| **Cobalt Strike / Sliver / Mythic** | Red team C2 | High-end status | Not in same category — these are post-ex, not web pentest |

**Where WonderSuite has unique positioning**:
1. **Only tool with native MCP** integration for AI agents (Caido isn't there yet, Burp isn't even on the roadmap).
2. **Rust + Tauri** — same tech-flex as Caido, but with more functionality bundled.
3. **All-in-one** — proxy + scanner + intruder + OAST + OSINT + sequencer + codec, where Caido is mostly proxy + repeater.
4. **MIT, no paid tier on the horizon** — Caido already announced commercial features.

---

## 6. Aesthetic patterns that perform

Reviewed top-engagement TikTok posts in `#hackertok` / `#cybersecurity` Q4 2025 – Q1 2026:

- **Black + green** terminals dominate (matrix code rain still works).
- **Black + amber/orange** is the new differentiator — used by Caido marketing, by some red team blog brands. **WonderSuite already uses this palette.** Lean in.
- **Glitch / scanline overlays** — moderate use; can read as overdone.
- **Monospace + tracking** typography is universal.
- **Density** — busy screenshots outperform clean minimalist ones (proves there's substance).
- **Numbers, big** — view counts, payload counts, CVE counters draw eyes.

---

## 7. Language patterns to mirror

Words to use without irony in copy:
`pop · root · shell · own · drop · payload · ship · stack · gear · flex · cracked · mid · diff · cooked · cope · L · W`

Phrases that resonate:
- "your stack is mid"
- "stop being a skid"
- "upgrade your gear"
- "this hits different"
- "POV: you actually have skills"
- "imagine still using X in 2026"
- "they don't want you to know"
- "free game"

Phrases to avoid:
- "professional security testing platform"
- "enterprise-grade"
- "responsible disclosure" (in marketing copy — keep that in the SECURITY.md only)
- "trusted by Fortune 500"
- anything ending in "solution"

---

## 8. Hook archetypes that work for this audience

Ordered by historical engagement rate:

1. **Insult-with-an-out** — "your tools are mid → upgrade." Hits ego, offers redemption.
2. **Discovery flex** — "the tool nobody is talking about" + screenshot.
3. **Inversion** — "actually free thing that's better than the paid thing."
4. **POV framing** — "POV: you finally figured out how to look pro."
5. **Receipt drop** — "I deleted Burp. Here's why."
6. **Authority appeal** — "what the top 1% of bug bounty hunters use."

---

## 9. Slide concept derivation (output)

Six slides built on this research:

| # | Archetype | Angle | Why it works |
|---|---|---|---|
| 01 | Insult-with-out | "Your stack is mid. Upgrade." | Triggers ego defense, offers escape route → re-share |
| 02 | Aesthetic flex | "POV: your screenshots actually look pro" + Dashboard | Appearance signaling, shareable as a clip |
| 03 | AI flex | "Let your AI pop the box while you afk" + MCP | Agent-hacking is the trend; native angle Caido doesn't have |
| 04 | Tool flex | "69 tools. One binary. Zero invoices." | Density + price + ownership signaling |
| 05 | Specific receipt | Scanner / Intruder / OAST screenshots | Density proves substance; CTF-relevant tools |
| 06 | CTA | "Free game. No excuse." + GitHub | Loss-of-face if they don't grab it |

---

## 10. Anti-pattern checklist (don't ship if any of these are true)

- [ ] Does any slide moralize or warn about "ethical use"? → cut
- [ ] Does any slide say "professional" or "enterprise"? → cut
- [ ] Does any slide oversell ("the only tool you need")? → soften
- [ ] Is the hook too long to read in 1.5 s? → tighten
- [ ] Does the CTA require effort to find? → put GitHub URL big and bold
- [ ] Does it sound like a sponsored ad? → strip a layer of polish

---

## 11. KPI hypotheses

- **Save rate > 8%** on slide 1 = hook is working.
- **Share rate > 3%** on slide 2 or 4 = audience finds them flex-worthy.
- **Profile clicks > 5%** at end of slide 6 = CTA is landing.
- Expect comment thread to fork into "this is actually good" vs "skid bait" — both increase reach. Don't engage; pin the GitHub URL.

---

End of research. Slides follow in `slide-01-hook.html` through `slide-06-cta.html`.
