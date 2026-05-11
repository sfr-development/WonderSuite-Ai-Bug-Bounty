# Security Policy

## Supported Versions

WonderSuite is in active development. Security fixes are applied to the latest `main` branch and rolled into the next release. Older releases do not receive backports.

| Version       | Supported          |
| ------------- | ------------------ |
| `main` / latest | :white_check_mark: |
| older tags    | :x:                |

## Reporting a Vulnerability

**Please do not file a public issue for security vulnerabilities.**

Report privately via one of:

- **GitHub Security Advisories** (preferred): use the [**Report a vulnerability**](../../security/advisories/new) button on the Security tab. This keeps the report private until a fix is ready.
- **Email**: `security@sfr-development.de` (PGP key available on request).

Include in the report:

1. A clear description of the issue and its impact.
2. Reproduction steps or a proof-of-concept.
3. The version / commit SHA you tested against.
4. Your name and how you'd like to be credited (or "anonymous").

## What to Expect

- **Acknowledgement**: within 72 hours.
- **Triage and severity rating**: within 7 days.
- **Fix timeline**: depends on severity. Critical issues get a same-week patch where feasible.
- **Public disclosure**: coordinated with you. We'll credit you in the release notes unless you prefer otherwise.

## Scope

In scope:

- The WonderSuite desktop application (Tauri binary).
- The MCP server (JSON-RPC handlers, proxy engine, scanner, OAST listeners).
- The Tauri IPC surface (commands callable from the renderer).

Out of scope:

- Findings *produced by* WonderSuite when scanning third-party targets — that's the tool doing its job.
- Issues in upstream dependencies (Tauri, Rust crates, npm packages) — please report those to the respective project, but feel free to also let us know so we can pin or patch.
- Social engineering of project maintainers.

## Hall of Fame

Researchers who report valid vulnerabilities will be credited here (with consent) after the fix ships.

_Be the first._
