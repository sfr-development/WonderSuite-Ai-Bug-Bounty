# Changelog

All notable changes to WonderSuite are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.14] — 2026-05-18

### Fixed — Changelog tab showed boilerplate instead of real release notes
- **Every release on the GitHub release page (and therefore in the in-app
  Changelog tab fetched via the GitHub API) had the same generic
  boilerplate body** — "This is an automated release for WonderSuite.
  Downloads available: …" — because the workflow's `releaseBody:` was a
  static literal. The actual rich CHANGELOG.md sections only existed in
  the offline-bundled copy, but the frontend's merge logic preferred
  GitHub-fetched data over bundled, so the boilerplate won.
- **Backfilled all 19 existing GitHub releases** (v0.1.1 → v0.3.13) with
  their real CHANGELOG.md sections via `gh release edit --notes-file`.
  No frontend update needed for the user — refresh the Changelog tab and
  rich content appears for every past release.
- **Workflow updated** — new `Extract release notes from CHANGELOG` step
  runs before `tauri-action`, awks the body between `## [<version>]` and
  the next `## [` header, and feeds it as `releaseBody`. Future releases
  automatically get the right content on GitHub and in the Changelog tab.
- **Frontend defensive merge logic** — when the GitHub-fetched body
  matches the legacy boilerplate (`"This is an automated release"` or
  `"Downloads available:"`) OR is significantly shorter than the bundled
  version, the bundled body wins. GitHub metadata (URL, publish time,
  date) is always preferred. Future releases use GitHub's body directly
  since it'll be the real content; this fallback covers any legacy /
  manually-edited releases that still have boilerplate.

### Internal
- `.github/workflows/release.yml` — `Extract release notes from CHANGELOG`
  step + `releaseBody: ${{ steps.notes.outputs.body }}`
- `src/modules/changelog/Changelog.tsx` — `looksLikeBoilerplate()` helper
  + merge by source-richer-wins
- `scripts/backfill-release-notes.ps1` — one-shot script that backfilled
  the 19 historical releases. Kept in repo for future use if needed.

## [0.3.13] — 2026-05-17

### Fixed — Changelog tab (v0.3.12 follow-up)
- **`GitHub fetch failed: Failed to fetch`** in the new What's New tab is gone.
  The webview's default CSP blocked direct cross-origin `fetch()` calls to
  `api.github.com`, so the GitHub releases data never loaded — only the
  offline-bundled changelog rendered with an error banner. The fetch now
  routes through a new `fetch_github_releases` Tauri command (Rust-side
  reqwest, 10 s timeout, no CORS), and the frontend `invoke()`s it. Online
  data + offline fallback both work as designed now.
- **Decorative Sparkles icon removed** from the hero card — the page reads
  cleaner without it. The sidebar tab still uses the icon (it needs *one*).

### Changed — Changelog tab modernized
- **Bigger hero**: dropped the icon box, restored the eyebrow / title /
  subtitle hierarchy (RELEASE NOTES → "What's new" → version + just-updated
  pill). Title is 32 px Inter 800 instead of cramped 17 px.
- **Cards have spines** instead of a busy header gradient — a thin 3 px
  vertical bar on the left side that lights up orange on the latest
  release and on hover. Cleaner, more Linear / Vercel-style.
- **Hover state**: cards lift 1 px and pick up a soft drop-shadow.
- **H3 sub-section headers inside release bodies** get a small orange dot
  prefix so dense changelogs (like v0.3.10's seven-cluster sweep) are
  easier to skim.
- **Tag system** simplified: "NEW" → "Latest", "INSTALLED" stays, GitHub
  link is now a tag-shaped chip with consistent treatment.
- **Just-updated indicator** moved from a separate banner to an inline
  orange-pulse pill in the subtitle ("You're on v0.3.13 · ● just updated").
  Less visual noise.

### Internal
- `commands::fetch_github_releases` — new Tauri command that proxies the
  GitHub releases API through reqwest, returns raw JSON.
- `lib.rs` registers it in `invoke_handler!`.
- Frontend `Changelog.tsx` uses `@tauri-apps/api/core::invoke` instead of
  `fetch()` — no more browser-side CSP concerns.

## [0.3.12] — 2026-05-17

### Added — In-app changelog tab
- **New sidebar tab "What's New"** (with `Sparkles` icon, bottom of the
  sidebar between Documentation and Settings) renders the full per-release
  changelog inside the app — no need to leave WonderSuite or open a browser
  to see what changed.
- **Live data**: fetches the GitHub releases API on open for the freshest
  release notes (rich markdown bodies, per-release URLs, publish times) and
  falls back to the offline-bundled `CHANGELOG.md` when offline or rate-
  limited. The two sources are merged by version so nothing's missing
  either way.
- **"1" notification badge** on the sidebar appears whenever the installed
  version is newer than the version the user last opened the Changelog tab
  for. Driven by a `ws_last_seen_changelog_version_v1` localStorage key
  (in the expanded sidebar a pill-shaped "1" appears next to the label; in
  the collapsed sidebar a pulsing orange dot in the corner of the icon).
  Opening the tab clears the badge.
- **"You just updated"** banner highlights the new release at the top of
  the list for 14 days after publication when the installed version matches
  the latest GitHub release.
- **Search field** filters releases by version number or body content.
- Each release card shows a version chip, publish date + relative time
  ("3d ago"), a `NEW` badge on the latest, an `INSTALLED` badge on the one
  the user is running, and a direct link to the release page on GitHub.
- Markdown rendered through the existing react-markdown + remark-gfm stack,
  styled to match the rest of the app (dark mode, accent color, JetBrains
  Mono for code, dashed-underline links).

### Internal
- New `src/stores/changelogStore.ts` — Zustand store wrapping
  `localStorage` for the "last seen version" tracking + a single
  `hasUnseenChangelog` selector the sidebar subscribes to.
- New module under `src/modules/changelog/` (TSX + CSS).
- `src/types/index.ts` adds `'changelog'` to the `ModuleId` union.
- `src/components/layout/moduleMap.tsx` and `Sidebar.tsx` register the new
  tab + badge.
- `CHANGELOG.md` is bundled into the binary at build time via Vite's
  `?raw` import suffix, so the offline fallback ships with every release.

## [0.3.11] — 2026-05-17

Three roll-ups in one tag: a self-audit pass over the v0.3.10 changes (perf
+ robustness), the AI-cursor duplication bug, and an MCP tool-list trim
that reduces context-window pressure for agents.

### MCP tool surface — 100 → 91 (context-budget cut)
The agent's tool list crossed 100 entries with v0.3.10's new exposures and
started crowding out the conversation window for most AI clients (Claude
4.5 / 4.6 / 4.7 included). Trimmed the niche surface area — functionality
stays, just no longer in the AI's primary tool catalogue.

- **8 OAST tools removed**: `oast_generate_payload`, `oast_start_dns_server`,
  `oast_start_smtp_server`, `oast_start_http_server`, `oast_poll_interactions`,
  `oast_verify`, `oast_status`, `oast_clear`. The OAST listeners themselves
  (DNS, HTTP, SMTP) still run in-process. AI agents drive the blind-vuln
  chain via `active_scan({with_oast: true})` (which generates correlation
  IDs, fires blind probes, and reports callbacks back as findings — one
  tool call instead of six). The UI's OAST panel still exposes the raw
  payload + listener controls for manual operation. Un-comment the
  dispatch + tool_definitions blocks in `mcp/handlers/mod.rs` and
  `mcp/mod.rs` to bring them back per-deployment.
- **1 browser tool removed**: `browser_stealth_check`. The actual stealth
  implementation runs automatically inside the bundled WonderBrowser
  extension; the self-test moved to the UI as a manual "Run stealth check"
  button. Niche diagnostic, not a workflow primitive.

### Fixed — performance regressions
- **`InterceptionRuleType::UrlRegex` was recompiled per request** (`proxy/state.rs::rule_matches`). The new v0.3.10 default `skip-trackers` rule is an 80-host alternation regex — at 500 req/s × N rules that's thousands of regex compilations per second on the proxy hot path. Fixed with a process-wide `RwLock<HashMap<String, Regex>>` compile-once cache.
- **`apply_replacement` for match-and-replace rules** had the same per-request `Regex::new` cost. Now also uses the shared cache.
- **`jslib` static `<script src>` / inline-`<script>` regexes** were rebuilt on every `detect_in_html` call. Moved to `Lazy<Regex>` statics.

### Fixed — startup robustness
- **`jslib::FINGERPRINTS` panicked via `.expect()`** if the compile-time-embedded `fingerprints.json` was malformed. Now logs the error to stderr and returns an empty fingerprint list — `js_library_audit` degrades gracefully instead of poisoning the MCP tool surface.

### Fixed — AI cursor duplication bug (user report)
The visible AI cursor overlay sometimes appeared twice in the browser — one at the top-left default position, one tracking the actual action — and the duplicate disappeared when the parent context unloaded. Root cause: `Page.addScriptToEvaluateOnNewDocument` fires in **every frame** of the page, including auth-widget iframes (Circle, Stripe, Auth0, …). Each frame installed its own cursor element, and since CDP mouse events are in top-frame viewport coordinates, the sub-frame cursors sat on their own (default 80, 80) position and were visible as ghosts.

Fix in `mcp::browser::session::ai_cursor_overlay`:
- **`if (window.top !== window.self) return;`** — the IIFE no-ops in sub-frames.
- **Defensive dedup** at install time — `querySelectorAll('#__ws_ai_cursor')` removes stragglers from previous sessions (`document.write` / `documentElement` swaps).
- **Single MutationObserver per frame** — the reconnect path re-evaluated the IIFE each time, leaking observers; now `window.__ws_mo.disconnect()` before installing a new one.
- **`__ws_cursor_animate` generation token** — back-to-back move-then-click triggered two concurrent rAF loops both setting `transform` on the same element, looking jittery. New animations bump `__ws_cursor_anim_gen` and previous loops self-cancel on next frame.

### Note
v0.3.10 was tagged but its release pipeline was superseded by this tag — the audit-fix-driven gap between commit + release made v0.3.10 effectively pre-release. The published v0.3.11 contains everything from the v0.3.10 changelog plus the above.

## [0.3.10] — 2026-05-17

### Security — fixed via full code + workflow audit (35 findings, agent + live-run cross-verified)

- **`validate_path` Tauri IPC arbitrary-file bypass** (`commands.rs`). The path-validation function had no `Err` after its allowed-prefix loop and fell through to `Ok(())` — `save_file_bytes` / `save_file_text` / `read_file_content` accepted any absolute path. The IDE-config allowlist also matched `.cursor` / `.vscode` / `.claude` as substrings anywhere in the path. Now: explicit `Err` fall-through and segment-level IDE-dir match (`/.cursor/` not `*.cursor*`).
- **OAST listeners now bind 127.0.0.1 by default** (`oast.rs`). DNS/HTTP/SMTP callback servers were hardcoded `0.0.0.0` — any peer on the same LAN/WiFi could hit your laptop's SMTP / DNS / HTTP listener without consent. Now: loopback by default, `0.0.0.0` only when `WS_OAST_HOST` is set to a non-loopback hostname (= user opted in) or `WS_OAST_BIND` is explicit.
- **`mcp_execute_tool` dev-mode gate** (`commands.rs`). The IPC bridge gave any compromised webview the full 90-tool MCP surface including `proxy_set_upstream` (traffic re-routing), `browser_evaluate` (arbitrary JS in user's browser), `oast_start_*` (open public listeners), `raw_tcp_send` (raw bytes anywhere). Now: a small high-privilege denylist that requires `WS_MCP_DEV_MODE=1` (env var, set before launch) or use of the dedicated `#[tauri::command]` directly.

### Fixed — data integrity, dead UI, drift

- **`scanner_stop` Tauri command was defined but never registered** in `invoke_handler` (`lib.rs`). UI Stop button silently no-op'd. Now wired.
- **`apply_match_replace_response` corrupted binary responses** (`proxy/state.rs`). The function did an unconditional `String::from_utf8_lossy(body).to_string().into_bytes()` round-trip on every response even when zero `response_body` rules were active — `U+FFFD` injected into images, gzip blobs, protobuf, SHA-pinned downloads. Now: skip the round-trip entirely when no body rule exists; only enter the lossy path when the user has explicitly configured a body rule.
- **Scanner real-time finding emit** (`scanner_commands.rs`). `Findings.tsx` listened for `'scanner-finding'` events since v0.3.0 but the Rust side never emitted them — UI only refreshed via polling. New sidecar task emits each new finding within ~250 ms of `findings.push`.
- **`find_secrets` pattern bugs + severity ladder** (`mcp/handlers/recon.rs`). Added `slack_webhook`, `discord_webhook`, `azure_storage_key`, `npm_token`, `sentry_dsn`, `firebase_url`, `mssql`/`oracle`/`clickhouse` to `database_url`, `OPENSSH`/`PGP` to `private_key`. Fixed `internal_ip` regex (was 3-octet only — `10.5.42.7` partial-matched). Suppressed `email` false-positive when it sits inside a URL authority (`user:pass@host`). Split `stripe_key` into `stripe_live_key` (critical — charges real money) and `stripe_test_key` (high).
- **`proxy_get_capabilities` stale counts** — used to report a hardcoded `mcp_tools: 18, ipc_commands: 34` regardless of reality (real numbers: 100 / 134+). Now: `mcp_tools` from `mcp::tool_count()` (dynamic from tool_definitions), `ipc_commands` from a single-source-of-truth function.

### Workflow / agent surface

- **Default interception rule `skip-trackers`** (`proxy/state.rs`). 50+ tracker/ad/analytics hosts (doubleclick, googletagmanager, bat.bing, facebook.com/tr, hotjar, fullstory, mixpanel, segment, amplitude, sentry, datadog, intercom, usercentrics, hooks.slack.com, etc.) auto-pass-through. Live test on a real session showed ~50% of captures were tracker noise pre-fix.
- **`proxy_get_traffic` filters + `mode: "summary" | "detail"`** (`mcp/handlers/proxy.rs`). Previously a `limit: 5` could blow >30 KB of response (YouTube telemetry, GraphQL mutations). Now: `host`, `method`, `mime`, `status_min`/`max`, `exclude_static`, `exclude_third_party` + `primary_host`, plus a summary mode that returns metadata only (~30× smaller).
- **`send_to_intruder` JSON body recursive descent + GraphQL awareness** (`mcp/handlers/proxy.rs`). Previously only marked top-level object keys — nested `{ variables: { settingsId, targets } }` got a single `§variables§` marker that replaced the whole sub-object with a string, breaking JSON shape upstream (400 every probe). Now: descend through nested objects and arrays, mark only scalar leaves with JSON-pointer paths (`variables.settingsId`, `variables.targets[3]`), and for GraphQL bodies (`query` + `variables` shape) skip the structural `query` field and descend only into `variables`. Hard cap at 40 leaves so a 50-element array doesn't explode the config.
- **Intruder real concurrency** (`intruder.rs`). The runner was a single sequential `for` loop ignoring `config.threads` — the documented multi-thread feature was a lie. Now: bounded concurrency via `tokio::Semaphore` so `threads` is honored (defaults to 10 if 0), `throttle_ms` still drip-feeds dispatch, pause/stop checks survive in-flight.

### Added — MCP coverage gaps closed

- **Intruder driver tools** (5 new): `intruder_start`, `intruder_status`, `intruder_results`, `intruder_stop`, `intruder_list`. Agent can now fire + observe + cancel Intruder attacks — previously it could only call `send_to_intruder` and had nowhere to send the resulting config.
- **OAST coverage** (4 new): `oast_start_http_server`, `oast_poll_interactions`, `oast_status`, `oast_clear`. The missing `oast_poll_interactions` was the workflow-blocker — agent fired blind payloads but had no MCP-accessible way to see callbacks. Poll model is offset-based (pass `since_offset`, get `next_offset`).
- **`js_library_audit`** — detect frontend libraries + versions (jQuery, AngularJS, Vue, React, Bootstrap, lodash, moment, axios, PDF.js, CKEditor, Handlebars, Knockout, Backbone, Ember, MooTools, Prototype, Dojo, EJS, Select2, DataTables, marked, DOMPurify, three.js, d3, chart.js, plotly, MathJax, Next.js, Nuxt, Gatsby, Polymer, Alpine.js, htmx, Stimulus, Swiper, Highcharts, Popper.js, fontawesome, WordPress, Drupal, Joomla, Magento, Shopify, and ~20 more — 62 libraries total). **Detection only — NO bundled CVE / vulnerability data**, by design. The AI agent does CVE research separately (web search + own knowledge). Keeps the detection layer evergreen and the vulnerability assessment fresh. Input modes: `url`, `html`, `js`, or `traffic_id`; optional `follow_scripts` fetches each external script src to catch minified libs whose URL is generic.
- **AI skill workflow update** (`.claude/skills/wondersuite.md`): new "Library Inventory → Outdated → CVE Hunt" workflow. Tool count bumped from 90 to 100.

### Persistence

- **`globalScope` (in-scope rules) persisted to `ws_global_scope_v1`** — restart no longer loses your scope.
- **Repeater tabs persisted to `ws_replay_tabs_v1`** — N drafted tabs survive app restart. Transient fields (response, statusCode, isLoading) get reset on rehydrate.

### Internal

- New `src-tauri/src/jslib/` module — compile-time-embedded fingerprint DB (`resources/jslib/fingerprints.json`) + lazy regex compilation.
- New `src-tauri/src/mcp/handlers/intruder.rs` — agent-side wrappers around the Tauri Intruder engine.
- `intruder::create_intruder_state` now also seeds a global `OnceLock` so MCP handlers can drive the engine without Tauri State<>.
- `scanner_start_active` now takes an AppHandle so it can emit `scanner-finding` events.
- `proxy_commands::proxy_get_capabilities` reports dynamic counts from a single source of truth.

## [0.3.9] — 2026-05-17

### Fixed — Proxy upstream-request reliability (wreq path)
Two sporadic upstream-side errors disappear with this release. Both were first-release-of-the-feature gaps in the Chrome-TLS-impersonation path (introduced in v0.3.0, 4 days ago) — the reqwest fallback path was already correct.

- **`502 - http2 error → stream error received: unspecific protocol error detected`** on hosts behind aggressive H2-idling CDNs (Cloudflare, Akamai, etc.). Root cause: wreq's connection pool reused a half-closed H2 socket *after* the server had sent a GOAWAY frame mid-idle, getting `REFUSED_STREAM` / `PROTOCOL_ERROR` on the next request. wreq 5.x has no `http2_keep_alive_*` PING knobs to detect this proactively, so we attack it three ways:
  - `pool_idle_timeout`: **30 s → 5 s** — well under typical CDN idle-GOAWAY thresholds (10–20 s), so stale conns are evicted before they can be reused.
  - `http2_max_retry_count(2)` — wreq's built-in transparent retry on transient h2 errors.
  - **App-level retry-once** in `forward_via_impersonate` — sniffs the formatted error chain for `unspecific protocol error` / `PROTOCOL_ERROR` / `REFUSED_STREAM` / `GOAWAY` / `connection reset` / `broken pipe` / `unexpected eof` and resends the request on a fresh connection (50 ms cool-off so pool eviction has time to land).
  - `tcp_keepalive(15s)` + `tcp_keepalive_interval(5s)` + `tcp_keepalive_retries(3)` — TCP-level dead-conn detection for NAT timeouts and load-balancer session-table expiry.

- **`502 - TLS handshake failed: cert verification failed - IP address mismatch [CERTIFICATE_VERIFY_FAILED]`** when proxying direct-IP URLs (e.g. `https://212.72.183.88/`). Root cause: BoringSSL inside wreq strictly validates the upstream cert's SAN against the URL host — but when the user navigates by IP, the real cert is for a domain, never the IP literal. The reqwest fallback path already did `.danger_accept_invalid_certs(true)` (see `engine.rs` build_default_client); the wreq path was missing the equivalent. Fixed by adding `.cert_verification(false)` to the wreq builder.
  - **Why this is the correct default for a pentest tool**: Burp Suite, mitmproxy, and Caido all disable upstream cert validation by default — security testers need to MITM self-signed certs, expired certs, hostname/SAN mismatches, and direct-IP connections. The browser→proxy hop is still validated through the user's OS trust store via WonderSuite's local CA; only the proxy→origin hop is affected.

### Internal
- `src-tauri/src/tls_impersonate.rs::build_client` — new connection-pool/keep-alive/TLS-validation policy documented inline.
- `src-tauri/src/proxy/engine.rs::forward_via_impersonate` — new retry loop with `is_h2_transient_error` classifier (matches against the formatted wreq error chain).

## [0.3.8] — 2026-05-16

### Fixed — Intercept → Attack body-bridge (critical)
- **The bug**: With the proxy interceptor turned on, virtually **every attack tool was unable to reach the request body of the held request**. `send_to_intruder` required a numeric `traffic_id`, but intercepted requests have a UUID `id` — the bridge between the on-hold-intercept world and the attack chain literally didn't exist. `passive_scan` / `active_scan` always re-fetched the URL as a clean unauthenticated GET, dropping cookies, Authorization headers, CSRF tokens, JSON bodies, form bodies, and method. Net effect: POST APIs, GraphQL endpoints, and any authenticated flow were unscannable from a held intercept.
- **The fix**: introduce a unified *source* abstraction (`mcp::handlers::scanner::source::ResolvedSource`) that resolves an attack target from any of `intercept_id` (UUID), `traffic_id` (numeric), or explicit `target`/`method`/`headers`/`body`. All three attack tools now consume it.
  - **`send_to_intruder`** — accepts `intercept_id` *or* `traffic_id`. Body-injection markers now cover **POST, PUT, PATCH, DELETE** (was POST-only). Detects and marks injection points in: JSON object keys, **form-urlencoded fields** (`a=1&b=2`), multipart-form-data part names, and **every Cookie name** in the Cookie header. Previously: query-string-only on POSTs with JSON-object bodies.
  - **`passive_scan`** — replays the intercepted method + headers + body for the baseline fetch and the CORS-origin probe. Authenticated-flow header analysis (CORS, cookies, info-disclosure) now works on POST/PUT endpoints and behind login.
  - **`active_scan`** — fuzzes **both URL query parameters AND body parameters** (form-urlencoded + JSON keys) for SQLi (error + time-blind), XSS, SSTI (7 engines), LFI (7 techniques), Open Redirect, CRLF/Header Injection, and OAST blind probes (cmdi / SSRF / log4shell / shellshock). Replays original method + cookies + auth headers on every probe.
- **MCP schema upgrades** — `get_intercepted` description now documents the `parsed.body` / `parsed.headers` / `parsed.query_params` shape and the `intercept_id` attack path. `send_to_intruder`, `passive_scan`, and `active_scan` advertise the new `intercept_id` / `traffic_id` / `method` / `headers` / `body` parameters.
- **No more "forward-then-attack" race** — previously the only path to body data was: intercept → `forward_intercepted` (poll up to 5 s for response) → grab `response.traffic_id` → call attack tool. Slow targets that took >5 s left the agent with `resolved_no_response_yet` and no traffic_id, breaking the chain. The new path lets attacks fire **directly against a still-held intercept**, with zero forwarding required.

### Internal
- New module `src-tauri/src/mcp/handlers/scanner/source.rs` — central `ResolvedSource` + helpers `parse_form_body`, `replace_form_param`, `replace_json_param`.
- `src-tauri/src/mcp/handlers/proxy.rs` exposes `parse_raw_request` + `fetch_intercepted` for cross-module reuse.
- `src-tauri/src/mcp/handlers/scanner/active.rs` — introduces `InjectionPoint` (query / body-form / body-json), `collect_injection_points`, `mutate`, `dispatch_req`. Every existing scan-type loop now goes through the dispatcher, so each probe inherits the original request's method, headers, cookies, body.

## [0.3.7] — 2026-05-16

### Added — Ports module (new sidebar entry, Testing group)
- **TCP Connect engine** — Tokio + dynamically-sized semaphore. AdaptiveTiming controller floats permits live via Little's Law (`in_flight = target_pps × RTT_p50`), re-evaluated every 2 s with a ±20 % dead-band, floor 64 / ceiling 65535. Stop button now `close()`s the semaphore so in-flight `acquire_owned` returns instantly — cancel feels sub-500 ms even at T5/T6.
- **Real TCP SYN engine (raw sockets)** — not a stub:
  - **Linux**: pnet `transport_channel(Layer4(Ipv4(TCP)))` over a kernel L3 raw socket. CAP_NET_RAW detected via the `caps` crate; if missing we surface a copy-paste `sudo setcap` command and gracefully fall back to TCP connect for this scan.
  - **macOS**: same pnet code path (BPF under the hood). `geteuid() == 0` check; non-root path prints the `sudo` invocation.
  - **Windows**: **WinDivert 2.2.2** (bundled, LGPLv3, EV-signed by Reqrypt LLC). The userspace driver is dlopened at runtime via the `windivert` crate — zero compile-time link against any pcap/Packet/wpcap library. RX uses a `NetworkLayer` handle with filter `inbound and ip and tcp and tcp.DstPort == <scanid> and (tcp.Syn or tcp.Rst)`; TX uses a separate handle with filter `"false"` (we only inject, never capture user traffic). Replaces the previous Npcap dependency — Npcap's free-edition licence forbids bundling without a $11,400/yr OEM contract, WinDivert's LGPLv3 permits redistribution unmodified.
  - **Stateless cookies**: each SYN's `seq` = `SipHash(src_ip, dst_ip, dst_port, scan_secret)`. RX verifies `ack - 1 == cookie` → spoofs are filtered and per-probe state is zero bytes. Source port (40000–60000) doubles as a scan-ID filter.
- **One-click "Install network driver" on Windows** — Settings → Ports SYN mode → ElevationModal detects missing WonderSuite network driver service and shows a "Install network driver" button. Tauri commands `portscan_driver_status` + `portscan_driver_install` copy the bundled `WinDivert.dll` next to our exe and `WinDivert64.sys` into `%ProgramData%\WonderSuite\drivers\`, then call `CreateServiceW` + `StartServiceW` via the Win32 SCM API. Single UAC prompt for life. "Re-check" button polls service status. HVCI / Memory Integrity detected via `HKLM\...\HypervisorEnforcedCodeIntegrity\Enabled`; on HVCI-strict machines we surface a clear "disable Memory Integrity in Windows Security to enable raw SYN" message and fall back to TCP connect.
- **No external download required for WinDivert** — `WinDivert.dll` (46 KB), `WinDivert64.sys` (92 KB) and `WinDivert.lib` ship inside the WonderSuite installer's `resources/drivers/windivert/x64/` directory. Total bundled-driver footprint ~140 KB.
- **UDP engine** — `tokio::net::UdpSocket` + protocol-specific probes for **14 services**: DNS (`.version.bind` CHAOS TXT), DHCP, TFTP RRQ, NTP v2 client, NetBIOS-NS wildcard, SNMP v1 GET `sysDescr.0` (community `public`), IKE/IPSec (500, 4500), RIP request, IPMI v2 RMCP+, OpenVPN v1 hard-reset, SSDP M-SEARCH, SIP OPTIONS, mDNS service enumeration, QUIC initial. Response → Open, ICMP-unreachable → Closed, timeout → OpenFiltered.
- **Service detection now uses real `nmap-service-probes`** — bundled at build time (`include_str!`, 2.46 MB, **187 probes + 11 971 match patterns + 203 softmatches** from the canonical nmap repo). `service_probes.rs` parses the format (Probe / rarity / ports / sslports / totalwaitms / fallback / match / softmatch / Exclude) and compiles all regexes once on first access via `Lazy<ProbeDb>`. `$1..$9` capture-interpolation into `p/`, `v/`, `i/`, `h/`, `o/`, `d/`, `cpe:/` follows nmap's semantics. Drops the 15 hand-rolled v0.3.7-prerelease probes.
- **All 3 scan modes now selectable** in the Ports UI — `Connect` (default, no admin), `SYN` (raw, admin/Npcap), `UDP` (no admin). ElevationModal calls `portscan_capability_check` to render OS-aware status (capabilities present? Npcap installed? version hint from registry).
- **5 MCP tools** — `port_scan`, `port_scan_range`, `service_detect`, `banner_grab`, `port_scan_results`. Tool count **85 → 90**. AI can drive scans with `mode: "connect" | "syn" | "udp"`; UDP supported unprivileged on the MCP path.
- **5 output formats** — JSONL, CSV, Nmap XML, gnmap, plain `ip:port`. Live-streamed JSONL during scan; the rest materialize on Export.
- **Ports state lifted to a global zustand store** (`src/stores/portscanStore.ts`) — scan survives module-unmount, so popping the Ports module into a separate Tauri window mid-scan keeps it running and results stream into both windows.

### Added — Multi-Window workspace
- Right-click any sidebar module → **"Pop out to window"** spawns a native Tauri WebviewWindow with just that module. Detached state shows as a `window` pill (expanded) or gold dot (collapsed) on the sidebar item.
- Cross-window state bridge for `sendTo` / `deleteSitemapNode` via Tauri events — "Send to Repeater" from Comparer in the main window still works when Repeater is in a separate window. Self-echo guarded by window-label comparison.
- Geometry persists per moduleId in `localStorage ws_detached_layout_v1`; on app boot the main shell respawns each persisted window at its last position.
- 240 ms cubic-bezier pop-in + 240 ms scale-down re-dock animations.
- 6 new Tauri commands: `window_detach_module`, `window_redock_module`, `window_focus_detached`, `window_list_detached`, `window_move_detached`, `window_resize_detached`.

### Added — UX polish
- **Desktop notifications** via `tauri-plugin-notification` — Settings → General → "Desktop notifications" toggle. Fires a native OS toast on long-running task completion (port scan done, etc.). Auto-requests OS permission on first enable; persists state in `localStorage ws_desktop_notifications_enabled`.
- **Live ticker** in Ports — pulsing pill stream of the last 8 results, state-colored.
- **PPS sparkline** (160×32 SVG) over the last 60 s, peak label.
- **Scan-completion summary** — donut chart of services by count (12-color palette) + horizontal-bar legend with relative scaling.
- **Modern checkboxes + sliders** — custom-styled `.ports-modern-check` with checkmark pop-in animation; range slider with gradient fill + glowing thumb.
- **"?" Unverified pill** on results that are open but lack a service banner or probe match, so the user knows which rows to spot-check manually.
- **Splash titlebar logo removed** — drag area only, less visual noise.
- **Zabbix-agent probe** (port 10050/10051) — ZBXD\x01-framed `agent.version` request, parses Zabbix version string from the response. Distinguishes legitimately-open-but-firewalled Zabbix agents (silent: marked unverified) from agents that whitelist our IP (marked `zabbix-agent` with version).

### Changed
- AI skill (`.claude/skills/wondersuite.md`) — Port Recon section rewritten with the real SYN/UDP engines, decision tree, auto-vuln-hunt hooks. Tool count 85 → 90. Description/trigger phrases extended ("port scan", "what's running on").
- README — added Port Scanner + Multi-Window sections; MCP tool count 85 → 90; new "Port Recon (5)" row in the tool table; architecture diagram updated.
- In-app docs (`src/modules/docs/content/ports.md`) — full Ports module documentation with mode / timing / probe details + auto-Npcap-install flow.
- Tauri capability `default.json` extended to `main` + `detached-*` window labels with `create-webview-window`, `set-position`, `set-size`, `scale-factor`, `outer-position`, `inner-size`, `event listen/unlisten/emit`. Added `notification:default` + permission ops.
- Sidebar items get a right-click context menu rendered via `createPortal(..., document.body)` so the menu is no longer clipped by the `zoom: var(--ui-scale)` containing-block on `.shell-body`.

### Fixed
- **Sidebar context menu shifted below the cursor** — `.shell-body` uses Chromium-native `zoom: var(--ui-scale)` which creates a new containing block for `position: fixed` descendants, so `top: y` was being computed from the zoomed-shell origin (below the titlebar). Fix: portal the menu into `document.body`.
- **Stop button latency at high concurrency** — closing the semaphore (`scan.timing.permits.close()`) on stop wakes every blocked `acquire_owned()` with an error so the engine drains immediately instead of waiting on permits.
- **Pop-out used to kill the running scan** — Ports state was React-local; now lives in a zustand store with global Tauri-event listeners attached once at first import. Scans run regardless of which window owns the UI.

### Backend internals
- New `src-tauri/src/portscan/` — `engine/connect.rs` (Tokio CONNECT scanner with adaptive permits), `engine/syn.rs` (cfg-gated per OS: Linux pnet transport, macOS bpf via pnet, Windows pcap + L2 frames + ARP gateway resolution), `engine/udp.rs` (Tokio `UdpSocket` with 14 protocol probes), `timing.rs` (T0–T6 templates + `RttStats` EWMA controller), `probes/` (TLS DER subject extraction; service-probe glue), `service_probes.rs` (nmap-service-probes parser + compiled regex match engine, `Lazy<ProbeDb>`), `npcap.rs` (Windows installer download + UAC-launch), `orchestrator.rs` (AppHandle-optional emit so MCP handlers can drive scans without a frontend), `targets.rs` (CIDR / range / hostname expansion + DNS resolve), `output.rs` (5 formats), `types.rs`.
- New `src-tauri/src/window_manager.rs` — WebviewWindowBuilder-based detach lifecycle, `DashMap<module_id, window_label>` registry, on-destroy cleanup + `window:redocked` event broadcast.
- New `src-tauri/build.rs` — auto-resolves Npcap SDK on Windows: respects `PCAP_LIBDIR`; falls back to `src-tauri/.npcap-sdk/`; lazy-downloads `npcap-sdk-1.13.zip` from `npcap.com/dist/` via PowerShell `Invoke-WebRequest` + `Expand-Archive` if neither is present.

### Cargo deps added
- `pnet 0.35` + `pnet_transport` + `pnet_packet` + `pnet_datalink` (cross-platform raw packet TX/RX + interface enumeration).
- `socket2 0.5` (raw socket setup), `siphasher 1` (stateless SYN seq cookies), `once_cell 1` (`Lazy<ProbeDb>`).
- Linux: `caps 0.5` + `libc`.
- macOS: `libc`.
- Windows: `windivert 0.6` (with `windivert-sys` bundled WinDivert SDK) + `windows 0.58` (SCM service API) + `windows-registry 0.5` (HVCI detection).
- `tauri-plugin-notification 2` (desktop notifications).

### CI / release pipeline
- `release.yml` + `ci.yml` install `libpcap-dev` on Linux (pnet on Linux still uses libpcap headers for some build paths).
- Windows runners need NO third-party SDK install — WinDivert SDK is vendored into the repo at `src-tauri/resources/drivers/windivert/`, and the `.cargo/config.toml` points `WINDIVERT_PATH` at it via `relative = true`.

## [0.3.6] — 2026-05-16

### Added
- WebSocket **Replay** tab — sequence editor with reorderable frames, per-frame delay (ms), and `${variable}` substitution. Variables are named key=value pairs referenced as `${name}` in any frame payload. Loop count, Run/Stop, run log with per-frame send confirmation. Import / export sequences as `.replay.json`. "From Last Sent" pulls the most recent sent frame from the Messages tab. Sequences persist in `localStorage` under `ws_replay_sequences_v1`.
- Cookie **Live-sync to WonderBrowser** — `session_set_cookie` / `remove` / `clear` / `import` now also push the change to a live WonderBrowser CDP session if one is open, via `Network.setCookie` / `Network.deleteCookies` / `Network.clearBrowserCookies`.
- New `session_browser_sync_status` Tauri command for the UI badge. The cookie panel toolbar shows "Live-sync to browser" (green) when a CDP session is connected, "Jar-only (no browser)" (grey) otherwise — polled every 4 s while the tab is visible.
- Splash screen now shows one of 26 curated one-liner pentest tips per launch (Lightbulb icon, italic, 0.4 s delayed fade-in below the progress bar).

### Changed
- Cookie sync failure is non-fatal: jar mutation always succeeds; CDP errors surface in `sync_error` on the operation result.

### Security
- Closed 12 npm Dependabot alerts via `mermaid` bump + `protobufjs` / `postcss` overrides.
- Closed 8 code-scanning HIGH / MED alerts (XSS sinks, unsafe regex, prototype pollution).
- Bumped `actions/checkout` 4 → 6 and `actions/setup-node` 4 → 6.

## [0.3.5] — 2026-05-15

### Added
- Modern Stealth-profile picker — Settings → Browser. Responsive 3-card grid with Lucide icon chips (Gauge / UserCheck / ShieldAlert), "Default" badge on Human, active-state accent strip + glow, and visible Speed and Stealth meter bars with numeric scores and gradient fills (cyan → blue for Speed, purple → red for Stealth). Speed: Fast 100 / Human 60 / Paranoid 25. Stealth: Fast 25 / Human 85 / Paranoid 100.
- README *Verified Undetected* section; MCP tool count bumped to 85.

### Fixed
- UI Zoom Scale at non-100 % values (e.g. 80 %) left a dead black region at the bottom-right of the window. Replaced the fragile `transform: scale()` + hardcoded titlebar math on `.shell-body` with Chromium-native `zoom: var(--ui-scale, 1)`. Content now fills the full window at every zoom value from 80 % to 130 %.

## [0.3.4] — 2026-05-15

### Added
- In-app **Documentation** tab — 33 pages of theme-aware, searchable reference for every WonderSuite feature.
- Coverage: Getting Started, Core, Testing, Recon, Analysis, Workflow, Settings, Reference — one page per module, six for the Settings sub-tabs, plus an MCP Tools reference and a Glossary.
- Two-pane layout: grouped TOC with per-page heading sub-nav and full-text search on the left; rendered markdown with in-page anchors and internal `page:` cross-links on the right.
- 33 markdown content files bundled at build time via `import.meta.glob`.
- `F1` keyboard shortcut to jump to docs.

### Changed
- Sidebar pin order: Documentation now sits beneath Settings.
- Reused already-installed `react-markdown` + `remark-gfm`; no new dependencies.

## [0.3.3] — 2026-05-12

### Added
- **Human-native browser input** — every `browser_click` / `browser_type` / `browser_press_key` / `browser_scroll` / `browser_fill_form` now goes through Chrome's real input pipeline via CDP `Input.dispatchMouseEvent` / `dispatchKeyEvent` / `insertText`. Resulting DOM events have `event.isTrusted === true` — indistinguishable from a physical keyboard and mouse. Unlocks the class of forms that were silently dropped by fraud SDKs (FriendlyCaptcha, DataDome, Cloudflare Bot Mgmt, Imperva).
- New `input.rs` module (~440 lines): element coords via `DOM.getBoxModel`, humanlike Bezier mouse trajectories with ease-out cubic timing and Gaussian jitter, per-character typing cadence drawn from a Gaussian, optional overshoot in paranoid mode.
- **Stealth profiles** (Fast / Human / Paranoid) trade speed for evasion. Persisted via localStorage + new `mcp_browser_set_stealth_profile` command.
- New tool `browser_stealth_check` — loads an in-memory `data:` URL test page that records every event with its `isTrusted` flag, navigator.webdriver state, `cdc_*` globals, overlay leak detection. Reports counts per event type, stealth_score, verdict (indistinguishable / good / partially-detectable / detectable).
- Cursor overlay v3.1 — Rust-driven: cursor moves only when Rust dispatches `Input.dispatchMouseEvent`. New JS API `__ws_cursor_set` / `animate` / `ripple` / `typehint` / `label` / `__ws_set_busy`. MutationObserver + 1.5 s polling self-heal stays.
- AI Skill download card redesigned: primary action vs secondary, both with icon + main label + subtitle, hover lift, responsive grid.
- Skill: Human-Native Input section explaining the `isTrusted` contract; Auto-Vulnerability-Hunt-During-Browser-Flow workflow (every login/register/auth flow becomes a vuln hunt — JWT analysis on every token, cookie flag audit, IDOR-by-predictable-ID, browser_replay_to_proxy on every interesting endpoint, passive_scan on the response).

### Changed
- Virtual cursor position now tracked in `BrowserSession` so successive moves start from the actual last position, not a hardcoded origin.
- `Emulation.setFocusEmulationEnabled` on session init so `document.hasFocus()` reports true even when the OS focus is elsewhere.
- `browser_evaluate` description hardened: marked `[escape-hatch, LAST RESORT]`, warns that `el.click()` and `el.value = ...` from this tool produce `isTrusted:false` events that fraud SDKs silently drop.
- README Browser MCP section rewritten around the human-native input pipeline. Tool table bumped to 24 with `browser_stealth_check`. Tool count 84 → 85.

### Fixed
- `press_key` correctly uses `rawKeyDown` + omits `text` when modifiers != 0 so `Ctrl+A` doesn't ALSO type an "a" (the famous "aErnst / aGuttenbrunner" 0.3.3-alpha prefix bug).
- Cursor overlay no longer tracks the user's real mouse — the 0.3.3-alpha mousemove-listener approach merged real user input with CDP input because both arrive as `isTrusted:true`.
- Banner is now a small chip top-right with `pointer-events:none` — purely a visual indicator, NOT a click-blocker (a blocking banner intercepted the AI's own CDP-dispatched clicks).

## [0.3.2] — 2026-05-12

### Added
- Settings → **AI Skill** (new tab) — bundles `.claude/skills/wondersuite.md` into the binary via `include_str!`. "Pick project folder + install" via Tauri dir-picker → writes to `<chosen>/.claude/skills/wondersuite.md` (path-traversal-safe, auto-creates dirs). "Save wondersuite.md elsewhere..." via save-as dialog. Quick-reference snippets for Claude Code, Cursor, Windsurf / Antigravity and a generic fallback prompt — each row has a one-click copy button. External link to the canonical skill on GitHub.
- New Tauri commands: `skill_content()` (bundled markdown) and `install_skill(directory)`.

### Changed
- `browser_attach` scope tightened — now exclusively drives the bundled WonderBrowser. Cleaner contract: attach reuses an existing WonderBrowser CDP session, or with `auto_launch:true` spawns a fresh one exactly like `browser_open`. Touching the user's system Chrome opened a class of "wrong window" UX bugs and risked the user's daily-driver profile data.
- Port scan order is now 9333 → 9222 → 9223 (WonderBrowser default first).
- `probe_cdp_port` now identifies WonderBrowser via `/json/version` Browser field (HeadlessChrome marker) plus port-knock on 9333; any other browser on those ports is rejected with `code=NOT_WONDERBROWSER`.
- `auto_launch` path reuses `crate::browser::launch_browser` through `BrowserSession::launch` so proxy wiring, stealth extension and isolated profile are identical to `browser_open`.
- Skill content updated to match the new attach contract: decision tree no longer mentions system Chrome or `use_real_profile`; error table swaps `PROFILE_LOCKED` for `NOT_WONDERBROWSER`.

### Removed
- `AttachArgs.use_real_profile` / `prefer` / `use_proxy` and the `find_system_chrome` / `find_real_chrome_profile` / `is_browser_process_running` helpers.

## [0.3.1] — 2026-05-12

### Added
- **Browser MCP** (`mcp/browser/`, replaces old `agent_browser`) — 23 tools backed by one persistent CDP socket per session.
- Auto-reconnect on closed connection: detect dropped WS, re-dial same CDP port, re-enable domains + re-inject scripts, retry the failed cmd.
- `browser_attach` scans ports 9222 / 9333 / 9223 for existing Chrome; with `auto_launch:true` spawns a system Chrome with `--remote-debugging-port` and a persistent attach-profile (logins survive between attaches).
- Visual AI cursor overlay: 28 px gold-gradient cursor + pulsing halo + AI badge. Persistent via MutationObserver + 1.5 s polling — survives SPA reroutes and hostile DOM teardown.
- rAF-driven scroll animation (700 ms ease-out) so motion is visible even on pages with `scroll-behavior:auto`, plus on-screen scroll banner.
- Honeypot detection in `browser_snapshot` form analyser (`display:none` / 0-size / off-screen / hidden ancestor / suspicious name / `tabindex=-1` sans label).
- `browser_screenshot` writes JPEG to `~/.wondersuite/screenshots` and returns path + size_bytes instead of giant base64; opt-in `return_base64`.
- `browser_fill_form` accepts `ref` / `selector` / `name` with single-form fallback.
- **Templates module rewrite** — real probe engine with status / body / header / regex expectations. Target URL + per-template Run + bulk Run-all (concurrency 6, cancellable). Live hit/miss/pending/error badges, hits-only filter, results history. Send-to-Findings / Send-to-Repeater / Copy-as-curl on every template.
- Catalog grew from 75 → **110 templates**: `.env` variants, Dockerfile, htpasswd, IDE files, composer / yarn / gemfile, actuator heapdump / httptrace, mongo-express, redis-commander, jenkins-script, jboss / weblogic / glassfish, docker-api, k8s-apiserver / kubelet, consul / nomad / vault, prometheus targets, sonarqube, gitlab / gitea, rabbitmq, swagger v3, graphiql, graphql introspection / batching, wp-debug-log, laravel / symfony debug, host / X-Forwarded-Host injection, fastly / shopify takeovers, GCP / Azure SSRF, missing xcto / referrer / permissions-policy, mssql / oracle SQLi hints, fastapi / flask / aspnet / imperva / sucuri detection.
- **OAST mode** in active scanner (`with_oast:true`): blind cmdi / blind ssrf / log4shell / blind sqli DNS probes with shared INTERACTIONS log + path correlation.
- **JWT vulnerability detection**: alg-none, HS-key-confusion, suspicious kid, jku / x5u SSRF, empty sig, expired.
- `send_to_intruder` infers payload category from param name (`user_id` → sqli, `q` → xss, `redirect` → open_redirect, `path` → lfi, `cmd` → cmdi, `user` / `pwd` → auth).
- Settings toggle for headless default (visible by default — user can intervene on captchas / 2FA).

### Changed
- Right-click context menu: click-toggle submenus (no more hover-only), fixed Compare Site Maps / Engagement Tools / Request in Browser / Send to Comparer / Documentation / Save / Delete. Extended to Discovery, Findings, Logger.
- Repeater paste-import: raw HTTP / cURL / fetch auto-detected, no need to enter URL separately.
- Sitemap toolbar buttons modernised (26×26 icon style with accent bg).
- Agent: `Loader2` spinner replaces hourglass emoji, `Check` / `X` icons for success / error states.
- Dashboard MCP tool count now dynamic (was hardcoded 66).
- Interactive flag on probes that need param injection (SQLi / XSS / LFI / etc) with manual hint pointing at Intruder / Repeater.

### Fixed
- Linux release: `cfg`-gate `wreq` / `wreq-util` / `webpki-root-certs` to non-linux so BoringSSL doesn't collide with native-tls.
- `truncate_utf8` helper for binary body display (prevents char-boundary panics in `proxy_get_traffic` on GIF89a / PNG bodies).
- Forward-intercepted race fix via URL + method + timestamp polling.
- OAST listener IP-host correlation via path-first extraction.

## [0.3.0] — 2026-05-12

> Skipped 0.2.x — `v0.2.0` was a dedicated branch for BoringSSL CI work; everything landed directly in 0.3.0.

### Added
- **Bundled WonderBrowser** — pinned Chrome-for-Testing 148 with SHA-256 verified lazy download.
- WonderSuite extension with minimal stealth (`webdriver` delete, no UA / plugin / permissions spoofing).
- Settings panel for the bundled browser: download status, cache reveal, reinstall, system-browser preference.
- **Crawler** — multi-level fetcher with robots, sitemap, well-known and JS endpoint discovery. Soft-404 detection, SPA-aware rendering hook, cookie + path canonicalization.
- **TLS / HTTP-2 fingerprint impersonation** (proxy upstream) — `wreq` + BoringSSL via `boring-sys2` with Chrome 137 emulation profile. JA3 / JA4 / Akamai H2 fingerprint matches real Chrome (verified against `tls.peet.ws`). Mozilla `webpki-root-certs` bundle fed via `wreq` CertStore so BoringSSL validates without the OS trust store.
- `proxy_get_tls_impersonate` / `proxy_set_tls_impersonate` Tauri commands + Settings toggle (default on).

### Changed
- Legacy CA migration: detect + remove the old v0.1.x trust-store CA from the OS.
- CI: `ci.yml` + `release.yml` install `nasm` + `cmake` + `clang` + `libclang-dev` (linux), `nasm` + `cmake` (macOS), `nasm` + LLVM (Windows via choco) plus `LIBCLANG_PATH` for `boring-sys2`.

## [0.1.5] — 2026-05-11

### Added
- Scanner **real presets** — `ScanConfig` gains `scan_type` (`crawl_and_audit`, `passive_audit`, `lightweight`, `owasp_top10`, `api_scan`), forwarded from the UI dropdown which was previously dead. `apply_preset` overrides relevant flags per mode (passive disables all injection checks, lightweight caps requests at 150 and skips heavy checks, `api_scan` skips HTML crawl, etc.).
- Hard-coded RDAP server table for ccTLDs not in IANA bootstrap (`de`, `at`, `ch`, `nl`, `fr`, `se`, `dk`, `no`, `pl`, `cz`, `hu`, `it`, `es`, `be`, `ie`, `gr`, `uk`, `ca`, `br`, `ar`, etc.). `.de` now resolves via `rdap.denic.de` instead of failing through to `rdap.org` 404.
- Wayback module: all failure paths surface toasts (non-200 status, parse error, empty result, request error). Success case toasts the count.

### Changed
- Scanner crawl is now proper BFS bounded by `config.crawl_depth`. Discovered links on a page actually get enqueued and visited until `max_requests` or the queue is drained. Visited set is a `HashSet` to dedupe properly. Live progress flushes every ~10 requests during crawl so the bar moves.
- JSON pretty-print in Raw editor: intercepted JSON requests are now pretty-printed (2-space indent) with `Content-Length` rewritten to match.
- JSON Body Editor visual refresh: type selector is now a color-coded badge with a popup menu; "Add child" is a single `+` trigger with a popup menu (was 5 stacked buttons per row); type-colored badges — `str` (green), `num` (orange), `bool` (purple), `null` (grey), `obj` (cyan), `arr` (accent).

### Fixed
- Scanner stops-at-40-requests bug — removed the premature `max_requests/2` break on the crawl loop.
- `Shell.tsx` `visitedRef` `useRef` moved above early returns to keep hook order stable.

### Deferred
- JA3 / JA4 TLS fingerprint spoofing — moved to a dedicated v0.2.0 branch (landed in v0.3.0).

## [0.1.4] — 2026-05-11

### Added
- **Tab-switch state persistence** — `Shell.tsx` keeps every visited module mounted with `display:none` when inactive. Active Scanner no longer loses its findings / live log / polling timer when you switch tabs. Same fix applies to Intruder, Discovery, Sequencer, Comparer, OSINT, Tools and every other module that held data in local `useState` (~10 modules total). Inactive modules still lazy-load on first visit.
- **Scanner → proxy traffic integration** — active scanner now emits every request it makes into `ProxyState::add_traffic` tagged `source=scanner`. Sitemap and Dashboard read the same traffic vec, so scanner requests now show up in the sitemap tree and count toward the dashboard request counter live. Done via new `emit_scanner_traffic()` called from `bump_req!` macro (single touch point, covers all 20+ request sites).

### Changed
- **Browser launcher Burp-style rewrite**:
  - Dropped `certutil` CA-trust-store install (was leaving a MITM root trusted system-wide).
  - Uses `--ignore-certificate-errors` on the isolated per-launch profile instead.
  - Adds `--proxy-bypass-list=<-loopback>` so `localhost` / `127.0.0.1` targets actually get proxied (Chrome 72+ silently bypassed them before).
  - Adds `--disable-features=HttpsUpgrades` so `http://` nav cannot silently jump to `https://` and skip the proxy.
  - Adds Burp's full noise-suppression flag set (`no-pings`, `no-experiments`, `no-service-autorun`, `disable-domain-reliability`, `disable-crash-reporter`, `disable-ipc-flooding-protection`, `disk-cache-size=0`, `media-cache-size=0`, etc.).
  - Profile dir stays under `.wondersuite/` so user's real Chrome profile is never touched.
- `ProjectLauncher` now pulls the version dynamically via `invoke(current_version)` instead of the hardcoded `v0.1.0` string.

## [0.1.3] — 2026-05-11

### Added
- **Auto-updater** (Tauri `plugin-updater`) — signed updates via minisign keypair, public key embedded in `tauri.conf.json`. `latest.json` published as release asset; app checks it on launch + hourly. In-app modal: download progress bar, install, relaunch — no manual `.exe` download.
- **JSON body editor** in Intercept tab — auto-shown when body parses as JSON. Tree view with per-node type switcher (`str` / `num` / `bool` / `null` / `obj` / `arr`), add string / number / bool / object / array children, rename keys, delete nodes. Format / minify toggle, byte counter, clipboard copy. Auto-syncs `Content-Length` on every change.

### Fixed
- Intercept Raw editor highlighter: detect both CRLF and LF header / body separators (textarea normalizes `\r\n` to `\n`). JSON body no longer rendered as headers (was turning everything orange).
- Port-conflict modal: locale-independent `LISTEN` detection (was matching English `LISTENING` only, broke on German `ABHOEREN`). Skip the check when our own proxy already holds the requested port. Filter our own PID out of the holders list before firing the modal.

## [0.1.2] — 2026-05-11

### Added
- Browser **cleanup on exit** — track launched browser PIDs and kill them on `RunEvent::ExitRequested` / `Exit`.
- `port_commands` module (`port_status`, `kill_process`) for cross-platform port → PID lookup.
- `browser_launch` returns structured JSON error `{kind:port_in_use, role, port, holders}` when ports are taken.
- Dashboard surfaces a modal listing blocking processes with one-click terminate-and-retry.

### Fixed
- OSINT RDAP IANA bootstrap fallback chain so .org / .com lookups don't 404 through to `rdap.org`.
- `crt.sh` requests now send a browser-like User-Agent (Cloudflare was returning 403 on the default reqwest UA).
- Live request log polling actually picks up new entries between scanner phase boundaries.

## [0.1.1] — 2026-05-11

### Added
- In-app updater popup that checks the GitHub releases API on startup and offers the right installer for the user's platform.
- Live Request Log tab in the Scanner — every probe streams in real time with status / method / url / time / size.
- Per-category info modal in the Payloads module with real-world breach examples and example payloads.
- New `current_version` Tauri command; the status bar now reads the version from the binary at runtime.

### Changed
- Scanner now fires a `tick_live` update after every counted request, so progress and findings appear continuously instead of jumping at phase boundaries.
- Auto-crawl bumped from 30 to 100 URLs; budget changed from `max_requests/3` to `max_requests/2`.
- Fallback parameter list grew from 17 to 45 names so static targets still get meaningful coverage.
- Release workflow now syncs the chosen version into `package.json`, `Cargo.toml` and `tauri.conf.json` before the build, so installer filenames match the release tag.

### Fixed
- OAST HTTP catch-all route also covers `/` now (was 404 on bare host hits).
- OAST RNG replaced with `rand::thread_rng()` — collisions on adjacent calls are gone.
- `chrono_now` placeholders replaced with RFC 3339 timestamps in scanner + OAST.
- Scanner master-toggle now also disables response interception and drains the pending intercept queue.

## [0.1.0] — 2026-05-11

### Added
- Initial open-source release.
- Desktop application (Tauri 2.x, Rust 1.78+, React 19).
- MITM proxy engine with dynamic CA, TLS interception, match-and-replace, WebSocket capture, HAR/JSON export.
- Stealth Chromium control via CDP (network capture, JS evaluation, session extraction).
- MCP server (JSON-RPC 2.0) exposing 69 security tools to AI agents.
- Active and passive vulnerability scanner (SQLi, XSS, SSTI, LFI, CRLF, Open Redirect).
- Intruder / fuzzer with Sniper, Battering Ram, Pitchfork, Cluster Bomb modes.
- OAST listeners (HTTP, DNS, SMTP) for blind vulnerability detection.
- OSINT toolkit (crt.sh, WHOIS/RDAP, ASN, Wayback, favicon hash, reverse IP, tech detect).
- Codec / decoder utilities (Base64, URL, hex, hash, JWT, smart-decode).
- Sitemap viewer (tree + interactive flowchart diagram).
- Token sequencer with entropy analysis.
- Vulnerability template library.
- One-click MCP config installer for Cursor, Windsurf, VS Code, Antigravity, Gemini CLI, Void.
- Cross-platform release workflow (Windows MSI/NSIS, macOS DMG, Linux AppImage/.deb).
- CI workflow (typecheck, fmt, check, clippy).
- CodeQL security scanning.
- Dependabot for Cargo, npm, and GitHub Actions.
