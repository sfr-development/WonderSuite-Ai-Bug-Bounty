# Agent

The Agent module is the live monitor for AI activity. When an AI client is connected to WonderSuite over the [MCP server](page:settings-mcp), every tool call it makes streams into this view in real time — it's how you watch what an autonomous agent is actually doing on your target.

## MCP Activity feed

The main table is a live feed, polled continuously. Each row is one MCP tool call:

| Column | Meaning |
|---|---|
| **#** | Sequential call ID. |
| **Time** | When the call was made. |
| **Category** | Tool category (proxy, scanner, browser, recon, …). |
| **Tool** | The exact tool name. |
| **Details** | Summary of the call's parameters. |
| **Result** | Outcome — `Processing…`, a success summary, or an error. |
| **Duration** | How long the call took (color-coded fast / medium / slow). |

The header shows live stat pills: **active** (running), **done** (succeeded), and **err** (failed) counts. The feed auto-scrolls to the newest entry unless you scroll up.

## Filtering & detail

- **Search** matches tool name, parameters, result, target URL, and category.
- **Filters** reveals category chips to narrow the feed to one tool group.
- **Clear** empties the log.

Click any row for the detail pane, with three tabs:

- **Parameters** — the call's input parameters and target URL.
- **Result** — the full result returned by the tool.
- **Raw** — the complete call record as JSON.

## How it relates to the rest of WonderSuite

The Agent feed is read-only — it observes, it doesn't drive. The AI itself connects through the [MCP Server](page:settings-mcp) and uses the same tool surface a human drives through the UI. The compact version of this feed also appears on the [Dashboard](page:dashboard) as **Live Activity**. To teach your AI client *how* to use WonderSuite well, see the [AI Skill](page:settings-skill) settings.
