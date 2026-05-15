# Traffic

Traffic — also called **HTTP History** — is the full log of every request that has passed through WonderSuite. Unlike [Intercept](page:intercept), it never pauses anything; it records. Every proxied request and every request an AI agent makes through the [MCP server](page:settings-mcp) lands here.

Open it with <kbd>Ctrl+3</kbd>.

## How traffic gets here

- **Proxy traffic** streams in live as your browser makes requests through `127.0.0.1:8080`.
- **MCP traffic** — requests made by connected AI tools — is polled in and merged automatically, so a human and an agent share one history.

If the table is empty, start the proxy and route a browser through it (the [Dashboard](page:dashboard)'s **Launch Browser** button does both).

## Toolbar

| Control | Action |
|---|---|
| **Count** | `filtered / total` entries currently shown. |
| **In-scope only** (lock) | Hides everything outside your defined [scope](page:workspace). |
| **Filters** | Shows/hides the method + status filter bar. |
| **Clear** | Wipes the captured traffic. |
| **Export** | Downloads the full history as a JSON file. |
| **Search** | Full-text search across URL, headers, **and** request/response bodies and MIME type. |

### Filter bar

When **Filters** is on, two rows of chips appear:

- **Method** — `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, or `All`.
- **Status** — `2xx`, `3xx`, `4xx`, `5xx`, or `All`.

Filters, search, and the in-scope toggle combine.

## The table

Each row is one request. Columns: `#`, **TLS** (lock icon for HTTPS), **Method**, **Host**, **Path**, **Status**, **Size**, **Time** (ms — turns red over 500 ms), **MIME**, and **Clock** (wall-clock time). Click any column header to sort by it; click again to flip direction.

Rows annotated with a color (via the right-click menu or other modules) show a colored left border.

## Detail pane

Click a row to open its detail pane below the table, with five tabs:

- **Request** — the full raw request (headers + body).
- **Response** — the full raw response.
- **Headers** — request and response headers parsed into clean key/value tables.
- **Params** — every query and body parameter, tagged by source.
- **Hex** — a hex + ASCII dump of the request.

The pane header repeats the method, URL, status, timing, and size for quick reference.

## Context menu

Right-click any row for the shared WonderSuite context menu — send the request to [Repeater](page:repeater), [Intruder](page:intruder), the [Comparer](page:comparer), [Scanner](page:scanner), and more, or delete the entry. This is the main way traffic flows from passive observation into active testing.
