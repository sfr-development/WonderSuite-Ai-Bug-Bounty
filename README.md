<div align="center">

<img src="docs/screenshots/dashboard-sidebar.png?v=1" alt="WonderSuite" width="100%" />

<br />
<br />

**Intercept, replay, scan, and fuzz HTTP traffic from a native desktop app.**<br />
Open source web security toolkit built with Tauri, React, and Rust.

<br />

[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tauri](https://img.shields.io/badge/Tauri-v2-orange?style=flat-square&logo=tauri&logoColor=white)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-stable-B7410E?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![MCP](https://img.shields.io/badge/MCP-88%20tools-22c55e?style=flat-square)](#mcp-tool-reference)
[![Platform](https://img.shields.io/badge/Windows-x64%20%7C%20ARM64-0078D4?style=flat-square&logo=windows&logoColor=white)](#getting-started)

<br />

[Getting started](#getting-started) - [Screenshots](#screenshots) - [Modules](#modules) - [MCP tool reference](#mcp-tool-reference) - [Architecture](#architecture) - [Contributing](#contributing)

</div>

<br />

---

<br />

## About

WonderSuite is a desktop app for web security testing. It sits between your browser and the target, captures every HTTP/S request passing through, and gives you tools to inspect, modify, replay, and fuzz them.

I built this because I wanted something like Burp Suite that runs natively, doesn't need Java, and works with AI coding assistants out of the box. The proxy itself is Rust. The frontend is React on Tauri v2. There is no Electron, no JVM, no remote backend. Everything runs locally on your machine.

It also runs an MCP server with 88 tools, meaning you can point Cursor, Windsurf, or any MCP-compatible IDE at it and let the assistant control the proxy, scanner, and OSINT tools through chat. That changes the workflow quite a bit -- you can describe what you want to test in plain language and the AI handles the rest.

<br />

## Getting started

You need [Node.js](https://nodejs.org/) 18+, [Rust](https://rustup.rs/) stable, and the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform.

```bash
git clone https://github.com/SFRDevelopment/wondersuite.git
cd wondersuite
npm install
npm run tauri dev
```

First build takes a few minutes while Cargo pulls in dependencies. After that, the dev server starts in seconds.

For a release build:

```bash
npm run tauri build
```

Output goes to `src-tauri/target/release/bundle/`.

<br />

---

<br />

## Screenshots

<div align="center">

### Dashboard

<img src="docs/screenshots/dashboard-sidebar.png?v=1" alt="Dashboard with expanded sidebar showing all modules" width="880" />

<sub>System info, browser detection, proxy status, quick actions. The sidebar lists every module with keyboard shortcuts.</sub>

<br />
<br />

### Intercept proxy

<img src="docs/screenshots/intercept-proxy.png?v=1" alt="Request interception view with queue panel" width="880" />

<sub>Pause HTTP/S requests mid-flight, edit headers or body, then forward or drop. Queue panel on the right shows pending requests.</sub>

<br />
<br />

### Traffic history

<img src="docs/screenshots/traffic-history.png?v=1" alt="HTTP traffic log with context menu open" width="880" />

<sub>Full request/response log with filtering. Right-click to copy URL, send to repeater, export as cURL, or highlight rows by color.</sub>

<br />
<br />

### Repeater

<img src="docs/screenshots/repeater.png?v=1" alt="HTTP repeater with raw request editor" width="880" />

<sub>Manually craft requests, edit headers, send, and inspect the response. Tabbed interface for working on multiple requests at once.</sub>

<br />
<br />

### Sitemap

<img src="docs/screenshots/sitemap.png?v=1" alt="Sitemap tree grouped by host and path" width="880" />

<sub>All captured endpoints organized by host. Click any path to see matching requests, methods, and status codes.</sub>

<br />
<br />

### Scan templates

<img src="docs/screenshots/scan-templates.png?v=1" alt="77 vulnerability scan templates" width="880" />

<sub>77 built-in scan templates: exposure checks, default credentials, CVEs, misconfigs, and fuzzing payloads. Filter by severity or tag.</sub>

<br />
<br />

### MCP server settings

<img src="docs/screenshots/mcp-server.png?v=1" alt="MCP server settings with IDE auto-detection" width="880" />

<sub>One-click MCP setup for Cursor, Windsurf, VS Code, Void, and Gemini CLI. Auto-detects installed IDEs and writes the config for you.</sub>

<br />
<br />

### MCP tools

<img src="docs/screenshots/mcp-tools.png?v=1" alt="88 MCP tools listed with descriptions" width="880" />

<sub>88 tools exposed via MCP. Proxy control, traffic search, scanning, OSINT, encoding, JWT analysis, WebSocket, and more.</sub>

<br />
<br />

### Proxy settings

<img src="docs/screenshots/proxy-settings.png?v=1" alt="Proxy engine configuration panel" width="880" />

<sub>Listen port, TLS pass-through, upstream proxy chaining, match and replace rules, and interception filters.</sub>

<br />
<br />

### Project launcher

<img src="docs/screenshots/project-launcher.png?v=1" alt="Project launcher with new and recent projects" width="880" />

<sub>Each project stores its own traffic, findings, and session data separately.</sub>

</div>

<br />

---

<br />

## Modules

| Module | What it does |
|:---|:---|
| **Intercept** | MITM proxy that captures and optionally pauses requests for manual editing before forwarding |
| **Traffic** | Searchable, sortable log of all proxied requests with export (JSON, CSV, cURL) |
| **Repeater** | HTTP client with tabbed sessions for crafting and resending requests manually |
| **Intruder** | Payload fuzzer supporting sniper, battering ram, pitchfork, and cluster bomb attack modes |
| **Scanner** | Active vulnerability scanner with 77 built-in Nuclei-style templates |
| **Sitemap** | Tree view of all discovered hosts and paths, built automatically from proxy traffic |
| **OSINT** | DNS, WHOIS, subdomain enumeration, tech stack detection, port scanning, cert transparency |
| **OAST** | Out-of-band interaction testing with HTTP, DNS, and SMTP callback servers |
| **Session** | Cookie jar, session macros, and automated session handling rules |
| **Comparer** | Diff two requests or responses side by side |
| **Logger** | Centralized traffic log aggregating data from proxy, scanner, intruder, and repeater |
| **Organizer** | Save, tag, and annotate interesting requests into collections |
| **Templates** | Nuclei-style scan template library with severity ratings and category tags |
| **WonderBrowser** | Built-in Chromium with the proxy CA pre-installed, no manual cert setup needed |

<br />

### Tech stack

<div align="center">

![Tauri](https://img.shields.io/badge/Tauri-24C8D8?style=for-the-badge&logo=tauri&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-B7410E?style=for-the-badge&logo=rust&logoColor=white)
![React](https://img.shields.io/badge/React-20232a?style=for-the-badge&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white)

</div>

<br />

---

<br />

## How the proxy works

WonderSuite runs a local HTTP/S proxy on `127.0.0.1:8080` by default. Point a browser at it and every request flows through the Rust backend:

1. **TLS interception** -- a CA cert is generated once per project. For each new host, the proxy creates a signed cert on the fly and terminates TLS. WonderBrowser trusts the CA automatically; other browsers need the cert installed manually (export button in proxy settings).

2. **Logging** -- full request and response (headers + body) are stored in memory and available in the traffic module. Filter by host, path, method, status, or content type.

3. **Intercept mode** -- when enabled, requests pause in a queue. You can view the raw request, edit anything, then forward or drop it. Responses can be intercepted too.

4. **Match and replace** -- rules that modify headers or body content automatically without pausing, useful for things like swapping auth tokens or injecting custom headers across all traffic.

5. **TLS pass-through** -- skip MITM for specific hosts (like `*.google.com`). Traffic still flows through the proxy but the TLS session is tunneled directly without decryption.

6. **Upstream proxy** -- chain all traffic through another HTTP or SOCKS5 proxy if you need to route through a VPN, Tor, or corporate proxy.

<br />

---

<br />

## MCP integration

The MCP (Model Context Protocol) server starts with the app and listens on `http://127.0.0.1:3100/mcp`. Add this to your IDE's MCP config:

```json
{
  "mcpServers": {
    "wondersuite": {
      "url": "http://127.0.0.1:3100/mcp"
    }
  }
}
```

After that, your AI assistant can call any of the 88 tools directly. The settings page auto-detects installed IDEs (Cursor, Windsurf, VS Code, Void, Gemini CLI) and can write the config for you automatically.

<br />

---

<br />

## MCP tool reference

All 88 tools available through the MCP server, grouped by category.

### HTTP and codec

| Tool | Description |
|:---|:---|
| `send_request` | Send an HTTP request to any URL and return the full response |
| `repeat_request` | Send requests via the Repeater with tabbed sessions, history, and redirects |
| `encode` | Encode data using Base64, URL, HTML, or Hex |
| `decode` | Decode data from Base64, URL, HTML, or Hex |
| `hash` | Hash data with SHA-256, SHA-1, or SHA-512 |
| `smart_decode` | Auto-detect and decode encoding chains (nested Base64, URL, JWT, etc.) |
| `analyze_jwt` | Decode and analyze a JWT token, showing header, payload, and expiry |
| `process_payload` | Chain payload transformations: encode, decode, hash, prefix, suffix, replace |
| `generate_payload` | Generate security testing payloads for XSS, SQLi, path traversal, SSTI, XXE |
| `inspect_message` | Parse raw HTTP messages into structured components (headers, params, cookies) |
| `compare_data` | Diff two data items using word-level or line-level comparison |
| `grep_extract` | Extract data from HTTP responses using regex patterns with capture groups |

### Proxy engine

| Tool | Description |
|:---|:---|
| `proxy_start` | Start the MITM proxy on a specified port |
| `proxy_stop` | Stop the running proxy |
| `proxy_status` | Get proxy running state, port, request count, intercept state, and config |
| `proxy_toggle_intercept` | Enable or disable request/response interception |
| `proxy_get_traffic` | Get all captured HTTP traffic from the proxy |
| `proxy_search_traffic` | Search captured traffic by URL, host, headers, or body content |
| `proxy_clear_traffic` | Clear all captured proxy traffic |
| `proxy_export_traffic` | Export captured traffic as JSON or CSV |
| `proxy_add_match_replace` | Add automatic match and replace rules for in-flight traffic modification |
| `proxy_get_match_replace` | List all active match and replace rules |
| `proxy_add_tls_passthrough` | Add a host to the TLS pass-through list (bypass MITM) |
| `proxy_set_upstream` | Configure upstream proxy chaining (HTTP or SOCKS5) |
| `proxy_get_websocket_messages` | Get all captured WebSocket messages |
| `proxy_add_interception_rule` | Add rules to control which requests get intercepted |
| `proxy_get_capabilities` | List all proxy engine capabilities and feature support |
| `proxy_get_statistics` | Get proxy runtime statistics (requests, bandwidth, timing, errors) |
| `bambda_filter` | Custom traffic filter expressions with operators (==, !=, contains, matches) |

### Scanner and intruder

| Tool | Description |
|:---|:---|
| `active_scan` | Full active vulnerability scan with payload injection (SQLi, XSS, SSRF, SSTI, XXE, path traversal, command injection, open redirect, CORS, headers, cookies) |
| `scan_target` | Start, manage, and query vulnerability scans with configurable scan types |
| `full_auto_scan` | Complete automated pipeline: subdomain enum, content discovery, crawling, scanning, report generation |
| `fuzz_request` | Create and run fuzzing attacks with sniper, battering ram, pitchfork, and cluster bomb modes |
| `custom_attack` | Execute custom attacks with AI-crafted payloads against injection points |
| `template_list` | List available Nuclei vulnerability templates filtered by category, severity, or tags |
| `template_search` | Full-text search across all Nuclei templates by name, description, CVE reference |
| `template_scan` | Run specific Nuclei templates or entire categories against a target |

### Reconnaissance and OSINT

| Tool | Description |
|:---|:---|
| `crawl_target` | Active site crawler: follows links, discovers endpoints, extracts forms, finds API routes |
| `discover_subdomains` | Subdomain enumeration via DNS bruteforce, certificate transparency logs, and wordlists |
| `discover_content` | Directory and file brute-force (like ffuf/gobuster), finds admin panels and backup files |
| `discover_parameters` | Discover hidden GET/POST parameters by testing common names and analyzing response diffs |
| `dns_resolve` | DNS resolution for A, AAAA, CNAME, MX, TXT, NS records. Finds origin IPs behind CDN/WAF |
| `crtsh_search` | Certificate transparency log search via crt.sh for subdomain enumeration |
| `wayback_lookup` | Query the Wayback Machine for historical URLs, deleted endpoints, and old API versions |
| `whois_lookup` | RDAP/WHOIS lookup returning registrar, creation date, nameservers, and organization |
| `asn_lookup` | Autonomous System Number lookup for IP addresses, returns ASN, org, country, prefixes |
| `favicon_hash` | Compute MurmurHash3 of a favicon for origin IP discovery via Shodan/FOFA/ZoomEye |
| `graphql_introspect` | GraphQL introspection to extract full schema including queries, mutations, and types |
| `js_link_finder` | Extract URLs, API endpoints, and secrets from linked JavaScript files |
| `reverse_ip_lookup` | Reverse DNS and virtual host discovery on an IP address |
| `find_secrets` | Scan responses and JS files for leaked API keys, tokens, passwords, AWS keys, private keys |
| `analyze_target` | Technology detection, WAF fingerprinting, security headers audit, SSL analysis, server fingerprinting |
| `analyze_tokens` | Token entropy analysis using Shannon entropy, FIPS 140-2 tests, and per-position bit analysis |

### Exploit testing

| Tool | Description |
|:---|:---|
| `test_auth_bypass` | Test for IDOR, privilege escalation, and BOLA by replaying requests with different auth contexts |
| `detect_smuggling` | Detect HTTP request smuggling (CL.TE, TE.CL, TE.TE, H2.CL) with timing analysis |
| `smuggling_send` | Send two HTTP requests on the same TCP connection for smuggling PoC with byte-level control |
| `raw_tcp_send` | Send raw bytes over TCP/TLS for smuggling PoC, custom protocols, and malformed requests |
| `timing_attack` | Differential timing analysis with statistical significance testing (mean, stdev, t-test) |
| `race_request` | Send N requests simultaneously with nanosecond synchronization for race condition testing |
| `test_open_redirect` | Test for open redirect vulnerabilities with multiple bypass techniques |
| `dom_invader` | Headless DOM XSS detection scanning for DOM sink/source patterns and parameter reflection |
| `generate_csrf_poc` | Generate CSRF proof-of-concept HTML pages from a target request |
| `mtls_send_request` | Send HTTP requests with client certificates for mutual TLS authentication testing |

### OAST (out-of-band testing)

| Tool | Description |
|:---|:---|
| `oast_generate_payload` | Generate blind vulnerability detection payloads for SSRF, XXE, SQLi, command injection |
| `oast_poll_interactions` | Poll for OAST callbacks to confirm blind vulnerabilities triggered |
| `oast_start_server` | Start the HTTP callback server for receiving interactions |
| `oast_start_dns_server` | Start a DNS callback server for blind DNS-based detection |
| `oast_start_smtp_server` | Start an SMTP callback server for email-based blind detection |
| `oast_get_payloads` | List all generated OAST payloads and their interaction status |
| `oast_verify` | Verify OAST callback server is working with a self-test request |
| `collaborator_everywhere` | Auto-inject OAST payloads into 14+ HTTP headers to detect blind SSRF/XSS |

### Browser and WebSocket

| Tool | Description |
|:---|:---|
| `browser_navigate` | Open URLs in WonderBrowser, navigate pages, get DOM, list tabs, take screenshots |
| `browser_execute_js` | Execute JavaScript in the active browser tab for CORS PoC, DOM manipulation, cookie extraction |
| `session_from_browser` | Capture authenticated session (cookies, localStorage, tokens) from the browser |
| `websocket_connect` | Initiate WebSocket connections, send messages, receive responses |
| `websocket_edit` | Modify and replay WebSocket frames |
| `websocket_advanced` | WebSocket match and replace rules, frame injection, binary editing |

### HTTP/2

| Tool | Description |
|:---|:---|
| `h2_detect_support` | Detect if a server supports HTTP/2 via ALPN negotiation |
| `h2_send_request` | Send HTTP/2 requests with proper pseudo-headers and prior knowledge support |
| `h2_translate` | Translate between HTTP/1.1 and HTTP/2 request formats |

### Session, scope, and reporting

| Tool | Description |
|:---|:---|
| `session_manage` | Cookie jar, session macros, and automated session handling rules |
| `scope_manage` | Define and manage target scope with include/exclude patterns |
| `organize_findings` | Save, annotate, and manage findings in collections |
| `query_logs` | Query centralized HTTP traffic logs from all tools |
| `generate_report` | Generate vulnerability reports in HTML or JSON from scan findings |

<br />

---

<br />

## Architecture

```
wondersuite/
|-- src/                          # React frontend (TypeScript)
|   |-- components/layout/        # Shell, sidebar, titlebar, status bar
|   |-- modules/                  # One directory per module
|   |   |-- intercept/            # Proxy intercept UI + queue
|   |   |-- traffic/              # Traffic history table + filtering
|   |   |-- replay/               # HTTP repeater with tabs
|   |   |-- attack/               # Intruder/fuzzer configuration
|   |   |-- osint/                # OSINT tools UI
|   |   |-- scan/                 # Scanner controls
|   |   |-- templates/            # Scan template browser
|   |   |-- oast/                 # OAST callback management
|   |   |-- session/              # Session/cookie management
|   |   |-- comparer/             # Request/response diff
|   |   |-- sitemap/              # Endpoint tree
|   |   |-- findings/             # Vulnerability findings
|   |   |-- websocket/            # WebSocket message viewer
|   |   |-- dashboard/            # System overview
|   |   |-- settings/             # Proxy + MCP settings
|   |   +-- tools/                # Codec utilities
|   |-- stores/                   # Zustand state management
|   +-- types/                    # Shared TypeScript types
|
|-- src-tauri/                    # Rust backend
|   +-- src/
|       |-- proxy/                # MITM proxy engine
|       |   |-- engine.rs         # Core proxy loop, TLS termination
|       |   |-- ca.rs             # Certificate authority, cert generation
|       |   +-- state.rs          # Shared proxy state (traffic, rules)
|       |-- scanner.rs            # Active scanner with template execution
|       |-- intruder.rs           # Fuzzer engine (payload injection, attack modes)
|       |-- mcp.rs                # MCP server (88 tools, JSON-RPC, activity log)
|       |-- oast.rs               # Out-of-band testing (HTTP, DNS, SMTP servers)
|       |-- session.rs            # Cookie jar, macros, session rules
|       |-- reporting.rs          # HTML/JSON report generation
|       |-- browser.rs            # WonderBrowser management
|       |-- http2.rs              # HTTP/2 support
|       |-- commands.rs           # Tauri IPC command handlers
|       +-- system.rs             # System detection (OS, arch, browsers)
|
+-- docs/
    +-- screenshots/              # Application screenshots
```

<br />

---

<br />

## Contributing

WonderSuite is an open source project and contributions from the community are what will make it better. Whether you are a security researcher, a developer, or someone who just wants to learn, there is room for you.

Things that would help the most right now:

- **Bug fixes** -- if something crashes, behaves unexpectedly, or produces wrong results, please open an issue with steps to reproduce
- **New scan templates** -- the built-in template library covers common checks but there are thousands of CVEs and misconfigurations still missing
- **Cross-platform builds** -- the app is currently tested on Windows only. macOS and Linux builds need validation and possibly Tauri config adjustments
- **Protocol support** -- HTTP/2 support exists but is basic. gRPC, WebSocket inspection improvements, and HTTP/3 are all on the roadmap
- **MCP tool expansion** -- new tools, better parameter validation, more informative error messages
- **OSINT modules** -- additional data sources, API integrations, better result correlation
- **Documentation** -- usage guides, video tutorials, scan template authoring docs
- **UI/UX improvements** -- dark theme refinements, keyboard shortcut coverage, accessibility

The goal is to build a complete, AI-native security testing platform that anyone can pick up, extend, and use. If you have an idea for something that isn't listed here, open an issue and describe what you have in mind.

### How to contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a pull request

Please keep the existing code style. If you are adding a new MCP tool, make sure to add the tool definition in `mcp.rs` and implement the handler in the `handle_tool_call` match block.

<br />

---

<br />

## License

[MIT](LICENSE)

<br />

---

<div align="center">

<sub>Built by <a href="https://github.com/SFRDevelopment">SFRDevelopment</a></sub>

</div>
