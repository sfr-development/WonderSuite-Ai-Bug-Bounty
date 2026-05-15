# Intercept

Intercept is WonderSuite's man-in-the-middle gate. With it enabled, every request your browser makes is paused mid-flight so you can inspect, edit, attack, or drop it before it reaches the server — and optionally pause responses on the way back.

Open it with <kbd>Ctrl+2</kbd>.

## Prerequisites

Intercept needs the proxy running and a browser routed through it:

1. Click **Start Proxy** in the toolbar (binds `127.0.0.1:8080`).
2. Click **WonderBrowser** to launch a browser already wired to the proxy — or point any browser at `127.0.0.1:8080` manually and trust the WonderSuite CA.
3. Click **Intercept Off** to flip it to **Intercept On**.

From then on, requests stack up in the **Queue** on the right.

## Toolbar

| Control | Action |
|---|---|
| **Intercept On / Off** | Master switch. Turning it **off** auto-forwards every pending request and tells you how many were drained. |
| **Forward** | Sends the currently selected request (with your edits) to the server. |
| **Drop** | Discards the selected request — it never reaches the server. |
| **Forward All / Drop All** | Appears when more than one request is queued; acts on the whole queue. |
| **Resp** | Toggles response interception — responses are paused on the way back so you can inspect them before the browser renders them. |
| **Copy URL / Copy raw** | Copy the selected request's URL or full raw text. |
| **Start / Stop Proxy** | Controls the MITM proxy lifecycle. |
| **WonderBrowser** | Launches the bundled browser through the proxy. |

The status indicator on the far right shows proxy state plus `N queued · M total`.

## The editor

When you select a queued item, it opens in the editor with these tabs:

### Raw

The full HTTP message in an editable, syntax-highlighted text area. Edit anything — method, path, headers, body. JSON bodies are auto-pretty-printed on load and `Content-Length` is kept in sync when you use the structured editors.

### Headers

A two-column editable table of every request header. Change keys/values inline, remove a header with `×`, or **+ Add Header**. Edits sync back to the Raw view.

### Params

A read-only breakdown of every parameter found in the request, tagged by source: `query`, `body`, or `cookie`.

### JSON

Appears only when the body is JSON. A structured tree editor where you can:

- Edit string/number/boolean values inline.
- Change a value's **type** (string ↔ number ↔ boolean ↔ null ↔ object ↔ array).
- **Add**, **delete**, and **rename** keys; append array items.
- Toggle **pretty / minified** serialization and **copy** the body.

### Hex

A hex + ASCII dump of the raw message — useful for spotting non-printable bytes.

### Attacks

A one-click attack workbench — see [Quick Attacks](#quick-attacks) below.

### Response

Shows the captured response once the request has been forwarded (or immediately, if Response Intercept is on). Includes status, size, **Copy**, and **Send to [Repeater](page:repeater) / [Intruder](page:intruder)** buttons.

## Quick Attacks

The **Attacks** tab is a table of 28 one-click request transforms. Each row carries a category, a risk dot (Critical/High/Medium/Low), and a **Run** button that mutates the current request in place — then drops you back on the Raw tab to review before forwarding.

WonderSuite **auto-detects** which attacks are relevant to the selected request (based on its content type, parameters, headers, JWTs, emails, etc.) and marks them `MATCH`, sorting them to the top. Attacks with extra options show an expandable config row.

Filter the table by category: **Auth**, **Inject**, **Access**, **Server**, **Client**.

### Injection
Content-Type Converter (form ↔ JSON), JSON Array Injection, Mass Assignment, Prototype Pollution, SQL Injection probe, XSS probe, SSTI, Command Injection, CRLF / Response Splitting, XXE, HTTP Parameter Pollution, JSON Duplicate Keys, Path Traversal / LFI.

### Auth
Email Swap, Token / Auth Tampering (incl. JWT `alg:none`), OAuth `redirect_uri` Hijack.

### Access
Role / Privilege Escalation, CSRF Token Removal, IDOR Parameter Tampering, HTTP Method Swap, 403 Bypass (path mutations), 403 Bypass (headers), HTTP Method Override, CORS Misconfiguration.

### Server
Host Header Injection, IP Spoofing Headers (8 headers at once), SSRF Probe (cloud metadata URLs), Open Redirect.

### Client
Clickjacking Test (checks for missing `X-Frame-Options` / CSP).

After running an attack, **Forward** the request and check the **Response** tab for the result. For deeper, automated coverage, send the request to the [Scanner](page:scanner) instead.

## The Queue

The right-hand panel lists every paused request: method, host, path, and a `RESP` badge for intercepted responses. Click to select; right-click for the shared context menu (send to other modules, delete).

> Turning the master toggle **off** does not lose your queue — every pending request is forwarded automatically so the browser never hangs.
