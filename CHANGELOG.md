# Changelog

All notable changes to WonderSuite are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
