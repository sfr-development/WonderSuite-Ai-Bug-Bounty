# Glossary

Common terms used throughout WonderSuite and this documentation.

## CA / Certificate Authority
The root certificate WonderSuite's [proxy](page:settings-proxy) generates so it can decrypt HTTPS traffic. External browsers must trust it; the bundled [WonderBrowser](page:settings-browser) handles it automatically.

## CDP — Chrome DevTools Protocol
The protocol WonderSuite uses to drive [WonderBrowser](page:settings-browser). The MCP browser tools send real input events through CDP so resulting DOM events are `isTrusted`.

## Findings
Confirmed vulnerabilities. The [Findings](page:findings) module aggregates them from the [Scanner](page:scanner) and [Templates](page:templates).

## Intercept
Pausing a request (or response) mid-flight so you can inspect, edit, or drop it before it continues. See the [Intercept](page:intercept) module.

## JA3 / JA4
TLS fingerprints derived from how a client negotiates a connection. WonderSuite's proxy can impersonate Chrome's JA3/JA4 to defeat bot-detection — see [Browser settings](page:settings-browser).

## MCP — Model Context Protocol
The standard WonderSuite uses to expose its tools to AI assistants. See [MCP Server settings](page:settings-mcp) and the [MCP Tools Reference](page:mcp-tools).

## MITM — Man-in-the-Middle
The proxy sits between the browser and the server, decrypting and re-encrypting traffic so it can be observed and modified.

## OAST — Out-of-band Application Security Testing
A technique for catching *blind* vulnerabilities by listening for callbacks (DNS / HTTP / SMTP) the target makes. See the [OAST](page:oast) module.

## Payload
An attack string injected into a request to test for a vulnerability. WonderSuite's [Payloads](page:payloads) module is a library of them.

## Position (§)
In the [Intruder](page:intruder), a spot in the request template — marked with `§…§` — where payloads are injected.

## Proxy
The MITM HTTP proxy at the centre of WonderSuite. It captures traffic into [Traffic](page:traffic), feeds the [Sitemap](page:sitemap), and powers [Intercept](page:intercept). Configured in [Proxy settings](page:settings-proxy).

## Quick Session
An in-memory, unsaved [project](page:projects) — for fast one-off work.

## Scope
The set of URL patterns that are *in bounds* for an assessment. Defined in [General settings](page:settings-general); used to filter noise across modules.

## Soft 404
A page that returns HTTP `200` but is really a "not found" page. The [Scanner](page:scanner) fingerprints these so they aren't mistaken for real content.

## TLS Pass Through
Telling the proxy *not* to intercept certain hosts — it tunnels their traffic raw instead. Configured in [Proxy settings](page:settings-proxy).

## WonderBrowser
WonderSuite's bundled, pinned Chromium build. Isolated from your system Chrome, pre-wired to the proxy. See [Browser settings](page:settings-browser).
