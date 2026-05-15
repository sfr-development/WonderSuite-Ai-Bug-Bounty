# Repeater

Repeater is for hand-crafting a single request, sending it, reading the response, and iterating — the workhorse for manually probing one endpoint. Each request lives in its own tab so you can keep several lines of investigation open at once.

Open it with <kbd>Ctrl+4</kbd>.

## Tabs

The tab bar across the top holds independent requests. Each tab shows the method, a name, and the last status code.

- **+** opens a new blank tab.
- **Double-click** a tab to rename it.
- Tabs are auto-named after the target host on first send.
- Requests sent here from other modules (Intercept, Traffic, Scanner…) open as new tabs automatically.

## Sending a request

1. Pick the **method** and type a **URL** in the bar.
2. Edit the raw request in the **Request** panel — request line, headers, and body.
3. Click **Send** (or press <kbd>Enter</kbd> in the URL field).

The **Response** panel fills with the result, and the header shows status, timing, and size.

## Importing requests

Click the **paste** (import) button to open the import panel. It auto-detects and converts three formats into an editable request:

- **Raw HTTP** — `POST /api HTTP/1.1` with headers and body.
- **cURL** — a `curl '...' -X POST -H ... -d '...'` command.
- **fetch()** — a JavaScript `fetch(url, { method, headers, body })` snippet.

Pasting into the empty import box auto-imports immediately. Imported requests reuse the current tab if it's blank, otherwise open a new one.

## Toolbar actions

| Button | Action |
|---|---|
| **Duplicate** | Clones the current tab. |
| **Copy as cURL** | Copies the request as a `curl` command. |
| **Import** | Opens the raw / cURL / fetch import panel. |
| **History** | Per-tab send history — every send is recorded; click an entry to reload that exact request/response. |
| **Settings** | Toggle **Follow redirects** and **Auto Content-Length**. |

## Request & Response views

The **Request** panel has `raw`, `headers`, and `hex` views. The **Response** panel has `raw`, `pretty` (pretty-printed JSON body), `headers`, and `hex` views. Each panel has a copy button.

> To run the same request with many payloads, send it to the [Intruder](page:intruder). To compare two responses side by side, use the [Comparer](page:comparer).
