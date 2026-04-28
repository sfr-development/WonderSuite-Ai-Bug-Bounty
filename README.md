<div align="center">

# ⚡ WonderSuite

### AI-Powered Offensive Security Research Engine

[![Rust](https://img.shields.io/badge/Rust-1.78+-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2.x-blue?style=flat-square&logo=tauri)](https://tauri.app/)
[![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react)](https://react.dev/)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)](#)

*A next-generation, autonomous security testing platform built on Rust/Tauri with native MCP (Model Context Protocol) integration for AI-driven vulnerability research.*

</div>

---

## 🎯 Overview

WonderSuite is a desktop-native offensive security engine that combines the power of Burp Suite-class tooling with autonomous AI agent capabilities. It provides a fully integrated environment for web application security testing, network reconnaissance, and exploit development — all orchestrated through an MCP-compatible AI interface.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   WonderSuite UI                     │
│              React 18 + TypeScript + Vite            │
├─────────────────────────────────────────────────────┤
│                  Tauri IPC Bridge                     │
├─────────────────────────────────────────────────────┤
│                 Rust Backend Engine                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
│  │  Proxy   │ │ Browser  │ │   MCP Server (JSON-  │ │
│  │  Engine  │ │   CDP    │ │   RPC over HTTP)     │ │
│  │ (MITM)   │ │ Control  │ │   50+ Security Tools │ │
│  └──────────┘ └──────────┘ └──────────────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
│  │ Scanner  │ │  OAST    │ │   Session / Payload  │ │
│  │  Engine  │ │  Server  │ │     Management       │ │
│  └──────────┘ └──────────┘ └──────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## ⚡ Core Capabilities

### 🔀 Intercepting Proxy
- Full MITM proxy with TLS interception & dynamic CA generation
- Request/response interception with real-time modification
- Match & Replace rules (regex-capable)
- WebSocket message capture
- Upstream proxy chaining (HTTP/SOCKS5)
- Traffic annotation & highlighting
- HAR/JSON export

### 🌐 WonderBrowser (CDP Integration)
- Built-in Chromium with stealth anti-detection patches
- **Live Network Traffic Capture** — CDP `Network.enable` captures all HTTP traffic
- Cookie/localStorage/sessionStorage extraction
- JavaScript execution via `Runtime.evaluate`
- Automatic auth token discovery from browser sessions

### 🤖 MCP Server (50+ Tools)
Native Model Context Protocol server enabling AI agents to autonomously:

| Category | Tools |
|----------|-------|
| **HTTP** | `send_request`, `send_to_repeater`, `h2_send_request`, `mtls_send_request` |
| **Proxy** | `proxy_start/stop`, `toggle_intercept`, `get_traffic`, `match_replace` |
| **Scanner** | `active_scan` (SQLi, XSS, SSTI, LFI, CRLF), `passive_scan` |
| **Intruder** | `fuzz_request` (Sniper, Battering Ram, Pitchfork, Cluster Bomb) |
| **Browser** | `browser_navigate`, `browser_execute_js`, `browser_network_traffic` |
| **Recon** | `crawl_target`, `discover_content`, `discover_subdomains`, `js_link_finder` |
| **OSINT** | `whois`, `dns_resolve`, `asn_lookup`, `crtsh_search`, `wayback_lookup`, `hackertarget`, `ip_geolocation`, `tech_detect`, `favicon_hash` |
| **Codec** | `encode/decode`, `hash`, `smart_decode`, `analyze_jwt` |
| **OAST** | `oast_start_server`, `oast_generate_payload`, `oast_poll_interactions` |
| **Exploit** | `race_request`, `raw_tcp_send`, `websocket_connect` |
| **Session** | `session_manage`, `session_from_browser`, `payload_manager` |
| **Reporting** | `generate_report`, `bambda_filter` |

### 🕵️ Autonomous Security Research
The AI agent can independently:
- Launch the stealth browser, navigate to targets, and capture all network traffic
- Extract authentication tokens from live browser sessions
- Discover API endpoints from captured traffic
- Craft and send modified requests (method switching, parameter manipulation)
- Fuzz endpoints with payloads from SecLists/PayloadsAllTheThings
- Detect vulnerabilities (IDOR, Mass Assignment, 2FA Bypass, CORS misconfig)
- Generate professional security reports

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Rust 1.78+ |
| Framework | Tauri 2.x |
| Frontend | React 18, TypeScript, Vite |
| Proxy | `tokio`, `rustls`, `rcgen` (dynamic CA) |
| Browser | Chromium via CDP (`tokio-tungstenite`) |
| MCP | Axum HTTP server (JSON-RPC 2.0) |
| HTTP Client | `reqwest` with TLS 1.3 |

## 🚀 Getting Started

### Prerequisites
- [Rust](https://rustup.rs/) (1.78+)
- [Node.js](https://nodejs.org/) (18+)
- [Tauri CLI](https://tauri.app/start/)

### Installation

```bash
# Clone the repository
git clone https://github.com/sfr-development/wondersuite.git
cd wondersuite

# Install frontend dependencies
npm install

# Run in development mode
npm run tauri dev
```

### Build for Production

```bash
npm run tauri build
```

## 📝 License

This software is proprietary and confidential. Unauthorized copying, distribution, or use of this software is strictly prohibited.

**© 2024-2026 SFR Development. All rights reserved.**

---

<div align="center">
<sub>Built with 🦀 Rust + ⚡ Tauri + ⚛️ React</sub>
</div>
