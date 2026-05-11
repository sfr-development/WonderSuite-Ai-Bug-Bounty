# Changelog

All notable changes to WonderSuite are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
