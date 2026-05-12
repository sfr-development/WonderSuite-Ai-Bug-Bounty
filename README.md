<div align="center">

<img src="public/wondersuite_logo.png" alt="WonderSuite" width="420" />

### AI-Powered Offensive Security Research Engine

A desktop-native security testing platform built on Rust and Tauri with native Model Context Protocol (MCP) integration for AI-driven vulnerability research.

[![Rust](https://img.shields.io/badge/Rust-1.78+-DE5C0B?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2.x-24C8D8?style=flat-square&logo=tauri&logoColor=white)](https://tauri.app/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![MCP](https://img.shields.io/badge/MCP-JSON--RPC_2.0-8B5CF6?style=flat-square)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-success?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](#contributing)

[**Features**](#core-capabilities) ·
[**Screenshots**](#screenshots) ·
[**Getting Started**](#getting-started) ·
[**MCP Tools**](#mcp-server--83-tools) ·
[**Contributing**](#contributing)

</div>

---

## Overview

**WonderSuite** is a desktop-native offensive security engine that combines Burp Suite-class tooling with autonomous AI agent capabilities. It provides a fully integrated environment for web application security testing, network reconnaissance, and exploit development — all orchestrated through an MCP-compatible AI interface.

The platform ships with **84 purpose-built security tools** accessible via JSON-RPC, a full MITM proxy with **Chrome 137 JA3/JA4 + HTTP/2 fingerprint impersonation** (defeats Cloudflare, Akamai Bot Manager, DataDome, PerimeterX), a **bundled Chrome-for-Testing 148** with stealth extension and per-version isolation, a pentest-grade browser MCP surface with stable element refs and OAST-integrated blind-vuln detection, and automated vulnerability scanning across SQLi, XSS, SSTI, LFI, CRLF, Open Redirect, plus blind cmdi / SSRF / Log4Shell via the bundled OAST listener.

<div align="center">
<img src="docs/screenshots/dashboard.png" alt="WonderSuite Dashboard" width="900" />
</div>

## Core Capabilities

### Intercepting Proxy

Full man-in-the-middle proxy with TLS interception and dynamic certificate authority generation. Supports real-time request and response modification, match-and-replace rules with regex (5 targets: request_header/body/url, response_header/body), WebSocket message capture, upstream proxy chaining (HTTP/SOCKS5), traffic annotation with color highlighting, and proper HAR/JSON export (headers, queryString, statusText all populated). Upstream requests can be re-originated through a **BoringSSL stack tuned to match Chrome 137's exact ClientHello, JA3/JA4 fingerprint and HTTP/2 SETTINGS frame ordering** — bypasses Cloudflare, Akamai Bot Manager, DataDome, and PerimeterX.

### WonderBrowser — Bundled Chrome-for-Testing 148

A pinned Chromium build (CfT 148.0.7778.97) shipped inside WonderSuite — version-locked, SHA-256-verified, never auto-updates, per-version cached. Uses a separate `.wondersuite/` profile so it doesn't touch the user's system Chrome. The bundled WonderSuite extension applies minimal stealth at `document_start` (deletes `navigator.webdriver` from the prototype, purges automation globals) — verified `isBot: false` on all 18 deviceandbrowserinfo.com checks. All outbound requests flow through the WonderSuite proxy for capture and TLS impersonation.

### Browser MCP — Human-Native Agent Surface (v0.3.3+)

24 browser tools driving WonderBrowser via a single persistent CDP WebSocket. **All input goes through Chrome's real input pipeline** (CDP `Input.dispatchMouseEvent` / `dispatchKeyEvent` / `insertText`) so resulting DOM events have `event.isTrusted === true` — indistinguishable from a physical keyboard and mouse, defeats the class of fraud SDKs (FriendlyCaptcha, DataDome, Cloudflare Bot Management, Imperva) that silently drop programmatic form submissions. On top: humanlike Bezier mouse trajectories with Gaussian jitter, per-character typing cadence drawn from a normal distribution, configurable pre-action dwell, focus emulation so `document.hasFocus()` reports true. Three **stealth profiles** (`fast` / `human` / `paranoid`) trade speed against detection-resistance — pick one in Settings → Browser, or override per call. The **AI cursor overlay lives in a closed Shadow DOM** so it's visible to the user but completely invisible to page-JS. `browser_stealth_check` self-tests the stack and reports an `isTrusted` score with verdict (`indistinguishable` / `good` / `partially-detectable` / `detectable`). Plus everything from v0.3.2: ref-based snapshots, `browser_fill_form` accepting ref/selector/name, `browser_storage_full` one-shot auth dump, `browser_replay_to_proxy`, `browser_dom_sinks`, CSP-violation-forwarding console, `browser_resource_hints`, CDP-native scroll wheel events.

### Crawler

Multi-level fetcher with robots.txt + sitemap.xml + `/.well-known/` + JS endpoint extraction discovery, soft-404 detection, SPA-aware rendering hooks, cookie + path canonicalization. Regex-based fast path for static apps; for SPAs the browser MCP surface is the better tool.

### MCP Server — 85 Tools + Operator Skill

Native Model Context Protocol server enabling AI agents (Claude, Cursor, Windsurf, VS Code, Antigravity, Gemini CLI, …) to autonomously conduct security research against WonderSuite's tool surface. Ships with a project-level Claude skill ([`.claude/skills/wondersuite.md`](.claude/skills/wondersuite.md)) that teaches the AI workflows, error-recovery, and when-to-ask-vs-act — see [Skill File](#skill-file--teach-your-ai-how-to-use-wondersuite) below.

| Category | Tools |
|----------|-------|
| HTTP | `send_request` · `send_to_repeater` · `send_to_intruder` (auto-categorises payloads per param name) · `h2_send_request` · `mtls_send_request` |
| Proxy | `proxy_start` · `proxy_stop` · `proxy_status` · `proxy_toggle_intercept` · `proxy_get_traffic` · `proxy_search_traffic` · `proxy_clear_traffic` · `proxy_export_traffic` (JSON / **HAR** with full headers + queryString) · `proxy_get_statistics` · `proxy_add_match_replace` · `proxy_add_interception_rule` · `proxy_add_tls_passthrough` · `proxy_set_upstream` · `proxy_annotate_traffic` · `proxy_get_websocket_messages` · `get_intercepted` · `forward_intercepted` |
| Scanner | `active_scan` (SQLi · XSS · SSTI · LFI · Open Redirect · CRLF) with optional `with_oast:true` for **blind cmdi, blind SSRF, Log4Shell** via the bundled OAST listener · `passive_scan` (headers, cookies, CORS, info disclosure) |
| Intruder | `fuzz_request` — Sniper · Battering Ram · Pitchfork · Cluster Bomb |
| Browser (24) | `browser_open` · **`browser_attach`** (reuse running WonderBrowser; `auto_launch:true` spawns) · `browser_close` · `browser_navigate` · **`browser_snapshot`** (a11y tree + ref=eN + forms-with-labels + honeypot detection + security block) · `browser_screenshot` (writes JPEG to disk, returns path) · **`browser_click`** (CDP-native, isTrusted:true, humanlike trajectory) · **`browser_type`** (CDP `insertText` with Gaussian cadence) · **`browser_fill_form`** (ref/selector/name + auto-submit; ref path goes through humanlike CDP input) · `browser_press_key` (CDP `dispatchKeyEvent`) · `browser_scroll` (CDP `mouseWheel` event) · `browser_select_option` · `browser_set_file_input` · `browser_get_outer_html` · `browser_evaluate` · **`browser_storage_full`** (cookies+LS+SS+IDB+SW+caches+cookie_header) · `browser_console` (incl. CSP violations) · `browser_dom_sinks` (innerHTML/eval/postMessage enum) · `browser_network_traffic` (CDP ring buffer) · **`browser_replay_to_proxy`** (hand browser request to Repeater) · `browser_resource_hints` (robots/well-known/sourcemaps) · `browser_wait_for` · `browser_tabs` · **`browser_stealth_check`** (self-test the human-emulation stack) |
| Recon | `crawl_target` · `discover_content` · `discover_subdomains` (concurrent DNS) · `find_secrets` · `dns_resolve` (with CDN detection) · `js_link_finder` |
| OSINT | `whois_lookup` · `asn_lookup` · `crtsh_search` · `wayback_lookup` · `hackertarget_lookup` · `ip_geolocation` · `tech_detect` · `favicon_hash` · `reverse_ip_lookup` · `graphql_introspect` |
| Codec | `encode` · `decode` · `hash` · `smart_decode` · **`analyze_jwt`** (alg=none, kid SQLi/traversal, jku/x5u SSRF, HS/RS confusion) |
| OAST | `oast_verify` (auto-bind HTTP listener, self-test, get_interactions) · `oast_start_dns_server` · `oast_start_smtp_server` · `oast_generate_payload` (auto-bind + path-correlated `callback_url` per payload) |
| Exploit | `race_request` · `raw_tcp_send` · `websocket_connect` · `analyze_cdn_waf` (with CDN bypass strategies) |
| Reporting | `generate_report` (markdown / JSON / summary) · `bambda_filter` · `payload_manager` · `get_traffic_log` |

### Autonomous Security Research

The AI agent operates independently through the MCP interface. It can launch WonderBrowser, walk the app with `browser_snapshot`'s stable refs, drive forms with `browser_fill_form` (by ref OR selector OR name), capture the authenticated session via `browser_storage_full` (cookies + LS + SS + IDB + SW + Cache in one call, ready-to-replay `Cookie:` header), and hand any browser-discovered request to the proxy's Repeater via `browser_replay_to_proxy`. From there: `active_scan with_oast:true` fires error+time-based SQLi, reflected XSS, SSTI, LFI, Open Redirect, **AND** blind-injection probes (curl/wget/JNDI-LDAP/Log4Shell-style) that callback to the bundled OAST listener — every callback becomes a critical-severity, certain-confidence finding. `analyze_jwt` flags alg=none, kid-as-SQLi-sink, jku/x5u SSRF, and HS/RS key-confusion classes. `analyze_cdn_waf` returns actionable bypass strategies cross-referenced to other tools (origin discovery via `dns_history`/`crtsh_search`/`favicon_hash`, header-manipulation evasion, payload obfuscation, protocol-level bypass).

## Screenshots

<table>
<tr>
<td align="center" width="50%">
<strong>Project Launcher</strong><br/>
<img src="docs/screenshots/project-launcher.png" alt="Project Launcher" width="100%" />
</td>
<td align="center" width="50%">
<strong>Dashboard</strong><br/>
<img src="docs/screenshots/dashboard.png" alt="Dashboard" width="100%" />
</td>
</tr>
<tr>
<td align="center">
<strong>Intercepting Proxy</strong><br/>
<img src="docs/screenshots/intercept-proxy.png" alt="Intercept Proxy" width="100%" />
</td>
<td align="center">
<strong>Traffic History · Context Menu</strong><br/>
<img src="docs/screenshots/traffic-context-menu.png" alt="Traffic Context Menu" width="100%" />
</td>
</tr>
<tr>
<td align="center">
<strong>Repeater</strong><br/>
<img src="docs/screenshots/repeater.png" alt="Repeater" width="100%" />
</td>
<td align="center">
<strong>Intruder · Sniper Mode</strong><br/>
<img src="docs/screenshots/intruder.png" alt="Intruder" width="100%" />
</td>
</tr>
<tr>
<td align="center">
<strong>Scanner</strong><br/>
<img src="docs/screenshots/scanner.png" alt="Scanner" width="100%" />
</td>
<td align="center">
<strong>Vulnerability Templates</strong><br/>
<img src="docs/screenshots/templates.png" alt="Templates" width="100%" />
</td>
</tr>
<tr>
<td align="center">
<strong>Sitemap · Tree View</strong><br/>
<img src="docs/screenshots/sitemap-tree.png" alt="Sitemap Tree" width="100%" />
</td>
<td align="center">
<strong>Sitemap · Diagram View</strong><br/>
<img src="docs/screenshots/sitemap-diagram.png" alt="Sitemap Diagram" width="100%" />
</td>
</tr>
<tr>
<td align="center">
<strong>OSINT · DNS Records</strong><br/>
<img src="docs/screenshots/osint-dns.png" alt="OSINT DNS" width="100%" />
</td>
<td align="center">
<strong>Token Sequencer</strong><br/>
<img src="docs/screenshots/sequencer.png" alt="Sequencer" width="100%" />
</td>
</tr>
<tr>
<td align="center">
<strong>Decoder / Codec Tools</strong><br/>
<img src="docs/screenshots/tools-decoder.png" alt="Tools Decoder" width="100%" />
</td>
<td align="center">
<strong>Sitemap · Mixed Explore View</strong><br/>
<img src="docs/screenshots/sitemap-mixed.png" alt="Sitemap Mixed" width="100%" />
</td>
</tr>
</table>

<details>
<summary><strong>Settings Panels</strong> (click to expand)</summary>

<table>
<tr>
<td align="center" width="50%">
<strong>General · System Info</strong><br/>
<img src="docs/screenshots/settings-general.png" alt="Settings General" width="100%" />
</td>
<td align="center" width="50%">
<strong>MCP Server · IDE Integration</strong><br/>
<img src="docs/screenshots/settings-mcp.png" alt="Settings MCP" width="100%" />
</td>
</tr>
<tr>
<td align="center">
<strong>Proxy Configuration</strong><br/>
<img src="docs/screenshots/settings-proxy.png" alt="Settings Proxy" width="100%" />
</td>
<td align="center">
<strong>Appearance · Themes</strong><br/>
<img src="docs/screenshots/settings-appearance.png" alt="Settings Appearance" width="100%" />
</td>
</tr>
</table>

</details>

## Architecture

```mermaid
flowchart TB
    pentester(["Pentester"])
    ai(["AI Client<br/><sub>Claude · Cursor · Windsurf · VS Code · Antigravity</sub>"])

    subgraph DT["WonderSuite Desktop · Tauri 2"]
        direction TB

        FE["<b>React 19 Frontend</b><br/><sub>22 modules · TypeScript · Vite · Zustand</sub>"]

        FE <==>|"Tauri IPC<br/>~100 commands"| BE

        subgraph BE["Rust Backend Engine"]
            direction TB

            subgraph CORE[" "]
                direction LR
                Proxy["<b>MITM Proxy</b><br/><sub>tokio · native-tls · dynamic CA<br/>+ Chrome 137 JA3/JA4 + HTTP/2<br/>upstream impersonation (BoringSSL)</sub>"]
                Browser["<b>WonderBrowser</b><br/><sub>Bundled Chrome-for-Testing 148<br/>Stealth extension · CDP capture<br/>Per-version SHA-256-verified cache</sub>"]
            end

            subgraph TOOLS[" "]
                direction LR
                Scanner["<b>Scanner</b><br/><sub>SQLi · XSS · SSTI · LFI<br/>CRLF · Open Redirect<br/>+ OAST blind cmdi/SSRF/Log4Shell</sub>"]
                Intruder["<b>Intruder / Fuzzer</b><br/><sub>Sniper · Battering Ram<br/>Pitchfork · Cluster Bomb<br/>Auto payload-category inference</sub>"]
                Crawler["<b>Crawler</b><br/><sub>robots · sitemap · .well-known<br/>JS endpoint extraction · soft-404</sub>"]
                OAST["<b>OAST Listener</b><br/><sub>HTTP · DNS · SMTP<br/>Path-correlated callbacks</sub>"]
            end

            MCP["<b>MCP Server</b><br/><sub>Axum · JSON-RPC 2.0 · :3100<br/><b>84 security tools</b><br/>+ 22 pentest-grade browser tools</sub>"]

            Payloads[("Payload Arsenal<br/><sub>SecLists · PayloadsAllTheThings<br/>157k payloads</sub>")]
        end
    end

    target[("Target Web Apps<br/><sub>HTTP/1.1 · HTTP/2 · WebSocket · mTLS</sub>")]
    osint[/"OSINT Sources<br/><sub>crt.sh · RDAP · Wayback · ASN · HackerTarget</sub>"/]
    callbacks[/"Out-of-Band Callbacks<br/><sub>DNS · HTTP · SMTP</sub>"/]

    pentester ==> FE
    ai <==>|"HTTP / JSON-RPC"| MCP

    Proxy <==>|"intercept · TLS MITM"| target
    Browser <==>|"CDP · network capture"| target
    Scanner -.->|"vulnerability probes"| target
    Intruder -.->|"payload waves"| target
    OAST <==>|"out-of-band"| callbacks
    MCP -.->|"lookup"| osint
    Scanner --- Payloads
    Intruder --- Payloads

    classDef person fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#d1fae5
    classDef desktop fill:#0f172a,stroke:#1e40af,stroke-width:2px,color:#e0e7ff
    classDef frontend fill:#1e3a8a,stroke:#60a5fa,stroke-width:2px,color:#dbeafe
    classDef engine fill:#451a03,stroke:#fb923c,stroke-width:2px,color:#fed7aa
    classDef mcp fill:#3b0764,stroke:#a855f7,stroke-width:3px,color:#f3e8ff
    classDef payload fill:#1f2937,stroke:#94a3b8,stroke-width:1px,color:#e2e8f0
    classDef external fill:#1f2937,stroke:#94a3b8,stroke-width:1.5px,color:#e2e8f0
    classDef hidden fill:transparent,stroke:transparent

    class pentester,ai person
    class DT desktop
    class FE frontend
    class BE,Proxy,Browser,Scanner,Intruder,OAST engine
    class MCP mcp
    class Payloads payload
    class target,osint,callbacks external
    class CORE,TOOLS hidden
```

**How it flows.** The pentester drives the React UI; every action travels through Tauri IPC into the Rust engine. The MITM proxy MITM-decrypts the browser's TLS, then re-originates each upstream request through a BoringSSL stack tuned to Chrome 137's exact ClientHello + JA3/JA4 + HTTP/2 SETTINGS fingerprint — so Cloudflare/Akamai/DataDome/PerimeterX see real Chrome. WonderBrowser is the bundled Chrome-for-Testing 148 with a stealth extension shipped in the install (no system Chrome dependency). Scanner and intruder probe the target, posting blind-vuln callbacks to the integrated OAST listener via path-correlated `callback_url`s. In parallel, any MCP-compatible AI client speaks JSON-RPC to the same 84-tool surface — including 22 pentest-grade browser tools that share state with the proxy via a stable request-ID space — so a human and an AI agent can investigate the same target with the exact same primitives.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Rust 1.78+ |
| Framework | Tauri 2.x |
| Frontend | React 19, TypeScript, Vite, Zustand |
| Proxy | tokio, native-tls, rsa/x509-cert (dynamic CA) |
| TLS impersonation | `wreq` + `boring-sys2` (BoringSSL), `webpki-root-certs` (Mozilla CA bundle) — win+mac only, Linux fallback to native-tls |
| Browser | Bundled Chrome-for-Testing 148.0.7778.97 (SHA-256-verified lazy download) + WonderSuite extension (MV3) |
| Browser MCP | Persistent CDP WebSocket (tokio-tungstenite) with multiplexed request correlation + a11y-tree snapshot engine |
| MCP | Axum HTTP server (JSON-RPC 2.0), dedicated thread/runtime |
| HTTP Client | reqwest with TLS 1.3 |
| OAST | Embedded axum HTTP listener + tokio UDP DNS server + raw-TCP SMTP listener, shared `INTERACTIONS` log |

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) 1.78 or later
- [Node.js](https://nodejs.org/) 18 or later
- On **Windows**: Microsoft Visual Studio Build Tools (Desktop C++ workload) and WebView2 Runtime
- On **Linux**: `webkit2gtk-4.1`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `build-essential`
- On **macOS**: Xcode Command Line Tools

### Installation

```bash
git clone https://github.com/sfr-development/WonderSuite-Ai-Bug-Bounty.git
cd WonderSuite-Ai-Bug-Bounty
npm install
```

### Development

```bash
npm run tauri dev
```

### Production Build

```bash
npm run tauri build
```

Output is written to `src-tauri/target/release/bundle/` (`.msi`, `.exe`, `.dmg`, `.AppImage`, `.deb`, depending on platform).

A helper `build-release.cmd` is provided for Windows developers (opens a visible console window, prints the artifact paths when done).

### Connecting an AI Client to MCP

The MCP server auto-starts on `http://127.0.0.1:3100/mcp`. The **Settings → MCP Server** tab auto-detects supported IDEs (Cursor, Windsurf, VS Code, Antigravity, Gemini CLI, Void) and offers one-click install. Manual config snippet:

```json
{
  "mcpServers": {
    "wondersuite": {
      "url": "http://127.0.0.1:3100/mcp"
    }
  }
}
```

### Skill File — Teach Your AI How to Use WonderSuite

WonderSuite ships a project-level Claude skill that turns your AI client into a senior pentester instead of a tool-calling chatbot. The skill is at [`.claude/skills/wondersuite.md`](.claude/skills/wondersuite.md) and contains:

- The pre-flight sequence (proxy check + recon basics) the AI should run on every new engagement
- Workflows: recon→crawl→triage, manual browser testing, OAST blind-vuln hunt, JWT analysis, SQLi/XSS hunting, race conditions, HTTP smuggling
- A decision tree for `browser_open` vs `browser_attach` vs `browser_attach({auto_launch, use_real_profile})`
- Tool-by-tool reference for all 84 MCP tools (parameters, when to use, killer-feature notes)
- Error-code recovery table (`PROXY_DOWN`, `STALE_REF`, `CDP_LOST`, `PROFILE_LOCKED` …)
- Anti-patterns and ask-vs-act guidance

**Install into your own project (one-time):**

```powershell
# Windows PowerShell
mkdir .claude\skills -Force
iwr https://raw.githubusercontent.com/sfr-development/WonderSuite-Ai-Bug-Bounty/main/.claude/skills/wondersuite.md -OutFile .claude\skills\wondersuite.md
```

```bash
# macOS / Linux
mkdir -p .claude/skills
curl -fsSL https://raw.githubusercontent.com/sfr-development/WonderSuite-Ai-Bug-Bounty/main/.claude/skills/wondersuite.md -o .claude/skills/wondersuite.md
```

Or clone the repo and copy the file:
```bash
cp WonderSuite-Ai-Bug-Bounty/.claude/skills/wondersuite.md .claude/skills/
```

**Use:** open a Claude Code / compatible session in that directory. The skill auto-loads — its frontmatter tells Claude to apply it whenever the user says things like "test this target", "scan", "pentest", "find vulnerabilities", "attach to my browser". You can also force-invoke it with `/wondersuite`.

**Keep it current:** the skill is versioned with the rest of the repo. After a release, re-run the install command above to pick up new tools / workflow improvements.

## Project Structure

```
wondersuite/
├── src/                          # React frontend
│   ├── components/               # Shared UI components
│   ├── modules/                  # Feature modules (dashboard, intercept,
│   │                             #   traffic, repeater, intruder, scanner,
│   │                             #   sitemap, discovery, osint, sequencer,
│   │                             #   comparer, logger, templates, organizer,
│   │                             #   agent, tools, findings, websocket,
│   │                             #   oast, settings)
│   └── stores/                   # State management (zustand)
├── src-tauri/
│   ├── resources/
│   │   ├── chromium_pin.json     # Pinned CfT version + SHA-256
│   │   └── wondersuite-extension/ # Bundled MV3 stealth extension
│   └── src/
│       ├── mcp/                  # MCP server engine
│       │   ├── browser/          # Human-native browser MCP (24 tools, CDP-Input, Shadow-DOM cursor)
│       │   │   ├── session.rs    #   CDP WS lifecycle + event dispatch
│       │   │   ├── snapshot.rs   #   a11y tree + ref=eN + forms + security
│       │   │   ├── network.rs    #   request capture ring buffer
│       │   │   └── handlers.rs   #   tool handlers
│       │   ├── handlers/         # Other tool handlers (proxy, scanner, …)
│       │   ├── router.rs         # JSON-RPC dispatcher
│       │   └── mod.rs            # Tool definitions (84 tools)
│       ├── proxy/                # MITM proxy engine
│       │   ├── engine.rs         # Core proxy logic + impersonate branch
│       │   ├── ca.rs             # Certificate authority
│       │   └── state.rs          # Traffic storage
│       ├── chromium/             # Bundled Chromium download/verify/extract/GC
│       ├── crawler/              # Robots/sitemap/well-known/JS-endpoint crawler
│       ├── oast.rs               # Shared HTTP/DNS/SMTP listeners + INTERACTIONS
│       ├── tls_impersonate.rs    # wreq + BoringSSL Chrome-137 emulation (win+mac)
│       ├── browser.rs            # Browser process launcher + CDP helpers
│       └── lib.rs                # Tauri application entry
├── docs/screenshots/             # README assets
└── .github/workflows/release.yml # Cross-platform CI release
```

## Responsible Use

WonderSuite is intended for **authorized security testing**, defensive research, and educational use. Only test systems you own or have explicit written permission to assess. The authors and contributors are not responsible for misuse.

## Contributing

**Contributions are welcome and very much appreciated.** WonderSuite is open source under the MIT License and we'd love your help to make it better.

Whether you want to:

- **Fix a bug** — open a [Pull Request](https://github.com/sfr-development/WonderSuite-Ai-Bug-Bounty/pulls) (small fixes don't need an issue first)
- **Propose a new feature** — open an [Issue](https://github.com/sfr-development/WonderSuite-Ai-Bug-Bounty/issues) to discuss the design before sending a PR
- **Report a bug** — open an [Issue](https://github.com/sfr-development/WonderSuite-Ai-Bug-Bounty/issues) with reproduction steps, expected vs. actual behavior, and your OS/version
- **Add a new MCP tool** — see `src-tauri/src/mcp/handlers/` for examples, and register the tool in `src-tauri/src/mcp/mod.rs::tool_definitions()`
- **Improve documentation, screenshots, or examples** — PRs go straight in
- **Share an idea** — open a [Discussion](https://github.com/sfr-development/WonderSuite-Ai-Bug-Bounty/discussions) (or an Issue if discussions are off)

There's no CLA. By contributing, you agree that your contributions will be licensed under the project's MIT License.

Please run `npm run tauri build` locally before submitting a PR to make sure it still builds across the full pipeline. If you touch the Rust side, `cargo check --manifest-path src-tauri/Cargo.toml` is a quick sanity check.

### Copyright

The WonderSuite name and the original codebase are © SFR Development (<https://sfr-development.de>). The project is licensed under the [MIT License](LICENSE) — you may use, modify, fork, and redistribute it under those terms. Contributions remain copyrighted by their respective authors but are licensed to the project (and downstream users) under the same MIT terms.

## Star History.

[![Star History Chart](https://api.star-history.com/svg?repos=sfr-development/WonderSuite-Ai-Bug-Bounty&type=Date)](https://www.star-history.com/#sfr-development/WonderSuite-Ai-Bug-Bounty&Date)

## License

Released under the [MIT License](LICENSE) © 2026 SFR Development.

---

<div align="center">
<sub>Built with Rust, Tauri, and React · Made by <a href="https://sfr-development.de">SFR Development</a></sub>
</div>
