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
[**MCP Tools**](#mcp-server--69-tools) ·
[**Contributing**](#contributing)

</div>

---

## Overview

**WonderSuite** is a desktop-native offensive security engine that combines Burp Suite-class tooling with autonomous AI agent capabilities. It provides a fully integrated environment for web application security testing, network reconnaissance, and exploit development — all orchestrated through an MCP-compatible AI interface.

The platform ships with **69 purpose-built security tools** accessible via JSON-RPC, a full MITM proxy with real-time request interception, a stealth-patched Chromium browser with CDP network capture, and automated vulnerability scanning across multiple injection categories.

<div align="center">
<img src="docs/screenshots/dashboard.png" alt="WonderSuite Dashboard" width="900" />
</div>

## Core Capabilities

### Intercepting Proxy

Full man-in-the-middle proxy with TLS interception and dynamic certificate authority generation. Supports real-time request and response modification, match-and-replace rules with regex, WebSocket message capture, upstream proxy chaining (HTTP/SOCKS5), traffic annotation with color highlighting, and HAR/JSON export.

### WonderBrowser (CDP Integration)

Built-in Chromium instance with stealth anti-detection patches injected at the protocol level. Features live network traffic capture via the CDP Network domain — every XHR, Fetch, and Document request is automatically recorded and made available to the AI agent. Includes cookie, localStorage, and sessionStorage extraction, JavaScript execution via `Runtime.evaluate`, and automatic authentication token discovery from browser sessions.

### MCP Server — 69 Tools

Native Model Context Protocol server enabling AI agents (Claude, Cursor, Windsurf, VS Code, Antigravity, Gemini CLI, …) to autonomously conduct security research against WonderSuite's tool surface.

| Category | Tools |
|----------|-------|
| HTTP | `send_request` · `send_to_repeater` · `h2_send_request` · `mtls_send_request` |
| Proxy | `proxy_start` · `proxy_stop` · `toggle_intercept` · `get_traffic` · `match_replace` · `intercept_rules` |
| Scanner | `active_scan` (SQLi, XSS, SSTI, LFI, CRLF, Open Redirect) · `passive_scan` |
| Intruder | `fuzz_request` — Sniper · Battering Ram · Pitchfork · Cluster Bomb |
| Browser | `browser_navigate` · `browser_execute_js` · `browser_network_traffic` · `session_from_browser` |
| Recon | `crawl_target` · `discover_content` · `discover_subdomains` · `js_link_finder` |
| OSINT | `whois_lookup` · `dns_resolve` · `asn_lookup` · `crtsh_search` · `wayback_lookup` · `hackertarget_lookup` · `ip_geolocation` · `tech_detect` · `favicon_hash` · `reverse_ip_lookup` |
| Codec | `encode` · `decode` · `hash` · `smart_decode` · `analyze_jwt` |
| OAST | `oast_start_server` · `oast_start_dns_server` · `oast_start_smtp_server` · `oast_generate_payload` · `oast_poll_interactions` |
| Exploit | `race_request` · `raw_tcp_send` · `websocket_connect` · `graphql_introspect` |
| Session | `session_manage` · `session_from_browser` · `payload_manager` |
| Reporting | `generate_report` · `bambda_filter` |

### Autonomous Security Research

The AI agent operates independently through the MCP interface. It can launch the stealth browser, navigate to targets, and capture all network traffic in real time. It extracts authentication tokens from live sessions, discovers API endpoints from captured traffic, crafts and sends modified requests with method switching and parameter manipulation, fuzzes endpoints using payloads from SecLists and PayloadsAllTheThings, detects vulnerabilities including IDOR, mass assignment, 2FA bypass, and CORS misconfiguration, and generates structured security reports.

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
                Proxy["<b>MITM Proxy</b><br/><sub>tokio · native-tls<br/>Dynamic CA · WS · HTTP/2</sub>"]
                Browser["<b>WonderBrowser</b><br/><sub>Chromium via CDP<br/>Stealth patches · Net capture</sub>"]
            end

            subgraph TOOLS[" "]
                direction LR
                Scanner["<b>Scanner</b><br/><sub>SQLi · XSS · SSTI<br/>LFI · CRLF · Open Redirect</sub>"]
                Intruder["<b>Intruder / Fuzzer</b><br/><sub>Sniper · Battering Ram<br/>Pitchfork · Cluster Bomb</sub>"]
                OAST["<b>OAST Server</b><br/><sub>HTTP · DNS · SMTP<br/>Blind callback collector</sub>"]
            end

            MCP["<b>MCP Server</b><br/><sub>Axum · JSON-RPC 2.0 · :3100<br/><b>69 security tools</b></sub>"]

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

**How it flows.** The pentester drives the React UI; every action travels through Tauri IPC into the Rust engine. The MITM proxy and the CDP-controlled stealth browser handle live traffic against the target. The scanner and intruder run their own probes, drawing from a 157k-payload arsenal and posting blind-vuln callbacks to the OAST server. In parallel, any MCP-compatible AI client speaks JSON-RPC to the same 69-tool surface — so a human and an AI agent can investigate the same target with the exact same primitives.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Rust 1.78+ |
| Framework | Tauri 2.x |
| Frontend | React 19, TypeScript, Vite |
| Proxy | tokio, native-tls, rsa/x509-cert (dynamic CA) |
| Browser | Chromium via CDP (tokio-tungstenite) |
| MCP | Axum HTTP server (JSON-RPC 2.0) |
| HTTP Client | reqwest with TLS 1.3 |

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

## Project Structure

```
wondersuite/
├── src/                          # React frontend
│   ├── components/               # Shared UI components
│   ├── modules/                  # Feature modules (dashboard, intercept,
│   │                             #   traffic, repeater, intruder, scanner,
│   │                             #   sitemap, discovery, osint, sequencer,
│   │                             #   comparer, logger, templates, organizer,
│   │                             #   session, agent, tools, findings,
│   │                             #   websocket, oast, settings)
│   └── stores/                   # State management (zustand)
├── src-tauri/
│   └── src/
│       ├── mcp/                  # MCP server engine
│       │   ├── handlers/         # Tool handlers (69 tools)
│       │   ├── router.rs         # JSON-RPC dispatcher
│       │   └── mod.rs            # Tool definitions
│       ├── proxy/                # MITM proxy engine
│       │   ├── engine.rs         # Core proxy logic
│       │   ├── ca.rs             # Certificate authority
│       │   └── state.rs          # Traffic storage
│       ├── agent_browser.rs      # Stealth Chromium control
│       ├── browser.rs            # CDP browser + network capture
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
