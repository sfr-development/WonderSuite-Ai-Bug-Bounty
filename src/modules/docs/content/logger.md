# Logger

The Logger is a unified, chronological feed of HTTP activity from across WonderSuite. Where [Traffic](page:traffic) is the detailed proxy history, the Logger is the lightweight running log — one line per request, tagged by which tool made it.

## What it shows

Every request is captured live from the proxy event stream and the existing traffic history, tagged by **tool source** — `Proxy`, `Repeater`, and so on. The table columns: `#`, **Tool**, **Method**, **URL**, **Status**, **Size**, **Time**, and **Clock**.

## Toolbar

- **Tool filter** — chips for `All` plus every tool that has logged activity; click one to narrow the feed.
- **Auto-scroll** — keep the newest entry in view as the log grows.
- **Clear** — empties the log.
- **Export CSV** — downloads the (filtered) log as a CSV file.
- **Search** — filters by URL, host, or method.

## Context menu

Right-click any row for the shared context menu — send the request to [Repeater](page:repeater), [Intruder](page:intruder), and the rest, or delete the entry.

> The Logger is the place to get a quick, cross-tool picture of "what has WonderSuite been talking to". For deep per-request inspection — full headers, body, params, hex — open the request in [Traffic](page:traffic) instead.
