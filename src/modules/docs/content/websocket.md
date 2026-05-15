# WebSocket

The WebSocket Inspector lets you open WebSocket connections, watch every frame in both directions, send your own frames, and rewrite frames in transit with match & replace rules.

## Connecting

Type a `ws://` or `wss://` URL in the toolbar and click **Connect**. The connection opens and you're dropped into the **Messages** tab. Connections persist until you close them.

## Connections tab

Lists every open or closed connection — a status dot (open / closed / error), the URL, message count, and connection ID. Click a connection to inspect its messages; the `×` closes it.

## Messages tab

The live frame log for the selected connection. Each frame shows:

- **Direction** — `C→S` (client → server, sent) or `S→C` (server → client, received), with an up/down arrow.
- **Type** — text, binary, etc.
- **Size** in bytes.
- A preview of the payload.

Click any frame for the full untruncated payload in the detail pane. The log auto-scrolls as new frames arrive (polled every second).

### Composer

The box at the bottom sends a frame on the selected connection — type your message and click **Send** (or press <kbd>Enter</kbd>; <kbd>Shift+Enter</kbd> for a newline).

## Match & Replace tab

Rules here automatically rewrite WebSocket frames as they pass through. To add a rule:

1. **Name** it.
2. Pick a **direction** — `Both`, `Client → Server`, or `Server → Client`.
3. Enter a **match pattern** and a **replace value**.
4. Tick **Regex** if the match pattern is a regular expression.

Active rules apply to all frames in the chosen direction. Remove a rule with its trash button. This is the WebSocket equivalent of the proxy's [match & replace](page:settings-proxy) — useful for tampering with messages a client sends without touching the client code.
