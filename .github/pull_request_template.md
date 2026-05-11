<!-- Thanks for sending a PR! Please fill out the sections below. -->

## What does this PR do?

<!-- 1-3 sentences. Focus on the why, not the diff. -->

## Related issue

Closes #

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] New MCP tool
- [ ] Documentation / screenshots
- [ ] Build / CI

## How I tested this

<!-- Did you run the app? On which OS? What scenarios did you cover? -->

## Checklist

- [ ] I ran `npm run tauri build` locally and it succeeded
- [ ] `npx tsc --noEmit` is green
- [ ] `cargo check --manifest-path src-tauri/Cargo.toml` is green
- [ ] If I added an MCP tool, I registered it in `mcp/mod.rs::tool_definitions()` and added a handler in `mcp/handlers/`
- [ ] If I changed UI, the screenshot in `docs/screenshots/` still matches (or I updated it)
- [ ] No dead code, no leftover debug prints
