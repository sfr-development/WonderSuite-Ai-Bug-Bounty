# Settings — AI Skill

The **AI Skill** tab installs a project-level Claude skill that teaches an AI assistant how to drive WonderSuite properly.

## What the skill is

Connecting an AI over the [MCP server](page:settings-mcp) gives it *access* to WonderSuite's tools — but not the knowledge of how to use them like a pentester. The skill file (`wondersuite.md`) closes that gap. It teaches the AI:

- The pre-flight sequence to run on every engagement (proxy check, recon basics).
- Workflows — recon → crawl → triage, manual browser testing, OAST blind-vuln hunting, JWT analysis, injection hunting, race conditions.
- A decision tree for when to launch vs. attach to a browser.
- A tool-by-tool reference for every MCP tool — parameters, when to use it, the killer-feature notes.
- An error-recovery table and ask-vs-act guidance.

It works with any Claude-compatible agent that reads `.claude/skills/`.

## Installing it

Two buttons:

- **Pick project folder + install** — choose your project's root directory; WonderSuite writes the skill to `<folder>/.claude/skills/wondersuite.md`.
- **Save wondersuite.md elsewhere…** — a plain Save-As dialog to put the file wherever you want.

Once installed, the panel confirms the path.

## Using the skill

In agents that scan `.claude/skills/` (like Claude Code) the skill **auto-loads** — its frontmatter triggers it whenever you ask the AI to test, scan, or pentest a target. For agents that need an explicit reference, the tab provides copy-paste snippets per tool (e.g. `/wondersuite` to force-invoke in Claude Code).

> Keep the skill current — re-install it after a WonderSuite update to pick up new tools and workflow improvements.
