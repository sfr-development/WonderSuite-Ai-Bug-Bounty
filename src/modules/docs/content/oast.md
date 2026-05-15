# OAST

OAST — **Out-of-band Application Security Testing**, also known as a Collaborator — catches *blind* vulnerabilities. When an injection doesn't produce a visible response but does make the target reach out over the network, OAST is the listener that catches that callback.

WonderSuite runs its own HTTP, DNS, and SMTP callback servers, generates correlation-tagged payloads, and logs every interaction back to the payload that caused it.

## Server tab

Three callback servers, each with its own start/stop control and status dot:

| Server | Default port | Catches |
|---|---|---|
| **HTTP Callback Server** | 8888 | HTTP/HTTPS requests — blind SSRF, blind XSS, blind command injection that fetches a URL. |
| **DNS Callback Server** | 8853 | DNS lookups — the most reliable signal, fires even when egress HTTP is blocked. |
| **SMTP Callback Server** | 2525 | Inbound mail — blind injection in mail-sending features. |

### Callback domain

Set the **callback domain** that payloads embed. For *real* out-of-band testing this must be a domain whose NS records point at this machine on the configured DNS port. The default `oast.wondersuite.local` only works for local probes hitting `127.0.0.1` directly.

### Quick Generate

Enter a target URL and **Generate Scan Payloads** to produce a ready-made batch of SQLi, SSRF, XXE, and Command Injection OAST payloads for that target.

## Payloads tab

Generate individual payloads: type a **description**, pick a **type** (Generic, Blind SQLi, Blind SSRF, Blind XXE, Blind CMDi, Blind XSS), and **Generate**.

Each payload carries a unique **correlation ID** and gives you three ready-to-paste forms — **HTTP**, **DNS**, and **SMTP**. Click a payload to open its detail pane and copy any form. The hit counter shows how many interactions that payload has triggered.

## Interactions tab

The live log of every callback received, polled every 3 seconds. Each row shows the interaction type (HTTP / DNS / SMTP), the correlation ID that fired it, the source IP, and a timestamp. Click one for the raw callback data and parsed details.

**An interaction here is proof** — it means your payload reached a server-side sink and that sink made a network call. That is a confirmed blind vulnerability.

Filter interactions by correlation ID, type, or IP. **Poll Now** forces an immediate refresh.

## Collaborator Everywhere tab

One click generates OAST payloads injected into **14 common HTTP headers** (`Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, and more). Drop these into a request — via [Repeater](page:repeater) or [Intruder](page:intruder) — and any header the server blindly trusts and fetches will light up in the Interactions tab. Each generated header has its own hit counter.
