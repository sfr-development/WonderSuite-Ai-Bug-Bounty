# Settings — Proxy

The **Proxy** tab is the full control panel for WonderSuite's MITM proxy engine. Sections are collapsible — click a header to expand or collapse it.

## Proxy Engine

The core listener:

- **Status** — Running / Stopped, with live counts of requests, cached certificates, and WebSocket messages. The **Start / Stop** button controls it.
- **Listen port** — the TCP port the proxy binds (default `8080`).
- **Listen interface** — the network interface to bind (default `127.0.0.1`).
- **Intercept responses** — also pause and edit server responses, not just requests (mirrors the [Intercept](page:intercept) module's Resp toggle).

## Match & Replace

Rules that automatically rewrite HTTP traffic in flight — no manual interception needed. Each rule has:

- **Name**
- **Target** — `Req Header`, `Req Body`, `Resp Header`, `Resp Body`, or `Req URL`.
- **Match** and **Replace** values (with an optional **Regex** flag).
- **Direction** — `Request`, `Response`, or `Both`.

Use these for things like stripping a header on every request, forcing a response value, or injecting a token globally.

## TLS Pass Through

Hosts listed here are **not** MITM-intercepted — the proxy tunnels raw TCP straight through. Add hosts (wildcards like `*.google.com` work) for endpoints with certificate pinning, or third-party domains you don't want to decrypt.

## Upstream Proxy

Chain WonderSuite's proxy through another proxy. Enable it, choose **HTTP** or **SOCKS5**, and set host, port, and optional username/password. All proxy traffic is then routed onward through that upstream.

## Interception Rules

Fine-grained rules controlling which requests/responses are intercepted versus passed through automatically — each with a name and an action.

## CA Certificate

To intercept HTTPS, the proxy generates a Certificate Authority. This section shows the CA file path and a **Copy PEM** button. Install this certificate as a Trusted Root CA in any *external* browser you route through the proxy. (The bundled [WonderBrowser](page:settings-browser) handles this automatically and needs no manual install.)
