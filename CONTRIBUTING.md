# Contributing to WonderSuite

First off — **thank you** for considering a contribution. WonderSuite is open source under the MIT License and we genuinely want your help to make it sharper, faster, and more useful for the security community.

## Ways to contribute

- **Fix a bug** — small fixes don't need a prior issue. Open a PR.
- **Propose a feature** — open an [Issue](../../issues/new/choose) first so we can align on scope before you sink time into a PR.
- **Report a bug** — use the [Bug Report template](../../issues/new?template=bug_report.yml) with reproduction steps, expected vs. actual behavior, OS and version.
- **Add an MCP tool** — see `src-tauri/src/mcp/handlers/` for examples. Don't forget to register it in `src-tauri/src/mcp/mod.rs::tool_definitions()`.
- **Improve docs, screenshots, examples** — PRs go straight in. The README and the screenshots gallery (`docs/screenshots/`) are fair game.
- **Share an idea** — [Discussions](../../discussions) is the right place.

## Development setup

```bash
git clone https://github.com/sfr-development/WonderSuite-Ai-Bug-Bounty.git
cd WonderSuite-Ai-Bug-Bounty
npm install
npm run tauri dev          # live-reload dev build
```

Build a release locally before submitting larger PRs:

```bash
npm run tauri build
```

### Pre-flight checks

Run these before pushing:

```bash
# Frontend
npx tsc --noEmit

# Rust
cargo check --manifest-path src-tauri/Cargo.toml
cargo fmt   --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings
```

CI runs the same checks on every PR — green CI is a hard requirement to merge.

## Code style

- **Rust**: `cargo fmt` (project ships a `rustfmt.toml`). Aim for clippy-clean code.
- **TypeScript / React**: Functional components, no class components. Hooks over HOCs.
- **Comments**: Default to no comments. Add one only when the **why** is non-obvious (a hidden constraint, a subtle invariant, a workaround for a specific bug). Don't write comments that just restate the code.
- **No proprietary integrations**: WonderSuite is a security tool, not a billing platform. Anything that calls home, phones a license server, or tracks the user belongs in a separate downstream fork, not upstream.

## Commit style

Conventional-ish, but pragmatic:

```
feat: add WebRTC traffic capture handler
fix(proxy): handle WebSocket close frame correctly
docs: clarify Linux build prerequisites
chore(deps): bump tauri from 2.x to 2.y
```

One logical change per PR. If you find yourself writing "and also" in the description, it's two PRs.

## PR checklist

- [ ] CI is green
- [ ] You've actually run the app locally and verified the change works (not just "it compiles")
- [ ] No dead code, no leftover debug prints, no `console.log` spam
- [ ] If you touched a feature with a screenshot in the README, the screenshot still matches reality

## Licensing & copyright

By submitting a PR you agree that your contribution is licensed under the project's [MIT License](LICENSE). No CLA is required. Your contribution remains your copyright; the **WonderSuite** name and the original codebase are © SFR Development (<https://sfr-development.de>).

## Security

Found a vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for the responsible-disclosure process.

## Code of Conduct

Be excellent to each other. Full text in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
