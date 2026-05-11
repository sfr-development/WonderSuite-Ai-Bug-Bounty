# WonderSuite — TikTok Slide Deck

10 standalone HTML slides at **1080 × 1920** (9:16 TikTok / Reels / Shorts) for promoting the repo.

## What's in the deck

| # | File | Pitch |
|---|---|---|
| 01 | `slide-01-hook.html` | **Hook.** Burp Suite $475/yr vs WonderSuite $0 |
| 02 | `slide-02-intro.html` | What it is — AI-powered offensive security engine |
| 03 | `slide-03-dashboard.html` | Dashboard screenshot, 157k payloads, 22 modules |
| 04 | `slide-04-mcp.html` | 69 MCP tools · Cursor / Claude / VS Code one-click |
| 05 | `slide-05-scanner.html` | Vulnerability scanner — SQLi, XSS, SSTI, LFI, ... |
| 06 | `slide-06-proxy.html` | MITM proxy — dynamic CA, HTTP/2, WS, mTLS |
| 07 | `slide-07-sitemap.html` | Visual attack-surface mapping |
| 08 | `slide-08-oast.html` | OAST listeners + Token sequencer |
| 09 | `slide-09-stack.html` | Stack stats — 24 MB, 70 MB RAM, native Rust |
| 10 | `slide-10-cta.html` | CTA · github URL · star / fork / contribute |

## Quick preview

Open `index.html` in any browser — shows all 10 slides as a scaled grid. Click any tile to open the full-size HTML.

## Export to PNG

### Option A — Headless Chrome (recommended, automated)

Double-click `export-png.cmd`. It finds Chrome or Edge automatically, renders all 10 slides at exact 1080 × 1920, and writes them to `out/`. Each PNG is direct TikTok-upload ready.

### Option B — Chrome DevTools manual capture

1. Open the slide HTML in Chrome (e.g. `slide-01-hook.html`).
2. `F12` → click the device-toolbar icon (or `Ctrl+Shift+M`).
3. Set viewport to **1080 × 1920**.
4. Click the **⋮** menu in the device toolbar → **Capture full size screenshot**.

### Option C — System screenshot

The slides are rendered at a fixed pixel size, so any screen-capture tool (Snipping Tool, ShareX, macOS Cmd+Shift+4) works — just maximise the browser tab and capture the slide canvas.

## TikTok upload tips

- TikTok slideshows accept **JPG and PNG**. PNG keeps the text crisp.
- Upload all 10 PNGs at once in the TikTok app (`+` → **Photo**). Order is preserved by filename.
- Keep slide-01 punchy — that's your hook. Most viewers will swipe past in <1.5 s if it doesn't grab them.
- For voice-over, leave 2.5–3 s per slide. The whole deck = ~25–30 s.
- Recommended hashtags: `#bugbounty #pentesting #hacking #infosec #opensource #rust #cybersecurity #ai #mcp #burpsuite`

## Editing

- **Colors & typography** — change once in `styles.css`. The brand accent is `--accent: #e8a145` (WonderSuite orange).
- **Text** — edit any slide directly. Each slide is self-contained, no JS framework.
- **Add slides** — copy any existing slide HTML, increment the filename (`slide-11-foo.html`), and update `index.html`.
- **Reorder** — just rename the files. The exporter uses alphabetical order.

## Tech

- Pure HTML + CSS. Inter + JetBrains Mono via Google Fonts CDN.
- No build step, no JS dependencies.
- Screenshots pulled from `../docs/screenshots/` — the same set used in the main README.
