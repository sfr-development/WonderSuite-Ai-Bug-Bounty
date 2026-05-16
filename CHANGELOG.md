# Changelog

All notable changes to WonderSuite are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
