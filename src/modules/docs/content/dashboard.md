# Dashboard

The Dashboard is the landing screen of every project. It gives you a live, at-a-glance view of the engine — proxy state, system info, MCP activity — and one-click access to the rest of WonderSuite.

Open it any time with <kbd>Ctrl+1</kbd>.

## Header strip

At the top:

- **Session uptime** — a running clock (`HH:MM:SS`) that counts how long the current WonderSuite session has been open.
- **Launch Browser** — starts [WonderBrowser](page:settings-browser) pre-wired to the proxy. The button label reflects state: `Launch Browser` → `Starting…` → `Browser Open`.

When you click **Launch Browser**, WonderSuite:

1. Starts the MITM proxy on port `8080` if it is not already running.
2. Applies your Browser settings (system-browser preference, no-sandbox flag, TLS impersonation).
3. Spawns the browser with its proxy and certificate already configured — no manual setup.

### Port conflict

If port `8080` is already taken, a modal appears listing the process(es) holding it (name, PID, address). You can **Terminate** a holder directly from the modal and **Retry**, or close it and free the port yourself.

## Status bar

A compact strip of environment facts:

| Field | Meaning |
|---|---|
| **Proxy** | `:8080` when running, `Off` otherwise |
| **Arch** | CPU architecture (e.g. x64, arm64) |
| **Cores** | Logical CPU core count |
| **OS** | Operating system version |
| **Browsers** | Number of system browsers detected for fallback |
| **MCP Tools** | Number of tools the [MCP server](page:settings-mcp) currently exposes |

## Metrics row

Five live counters, refreshed every 2 seconds:

- **Requests** — total requests seen by the proxy.
- **Intercepted** — requests currently sitting in the [Intercept](page:intercept) queue.
- **Scans OK** — successful MCP tool calls in the recent activity window.
- **Errors** — failed MCP tool calls.
- **MCP Calls** — size of the recent MCP activity feed.

## Modules panel

A quick-launch grid for the most-used modules — [Intercept](page:intercept), [HTTP History](page:traffic), [Repeater](page:repeater), [Intruder](page:intruder), [Scanner](page:scanner), [Discovery](page:discovery), [OSINT](page:osint), [OAST](page:oast), [WebSocket](page:websocket), Decoder, [Session](page:session), and [Agent](page:agent). Click any tile to jump straight to that module.

## Payload Arsenal panel

Shows the state of the local payload library — each category and how many payloads it holds, or `not downloaded` if the arsenal has not been pulled yet. The action button opens the [Payloads](page:payloads) module to **Download** (first run) or **Manage** the arsenal.

## Live Activity feed

A real-time stream of every MCP tool call an AI client makes against WonderSuite. Each row shows the timestamp, tool category, tool name, status (`✓` success, `✗` error, `…` running), a short parameter/result summary, and the call duration. This is the fastest way to watch what a connected AI agent is doing.

## Detected Browsers panel

Lists the system browsers WonderSuite found (name, version, engine). These are used as a fallback if [WonderBrowser](page:settings-browser) cannot be launched — see Browser settings for the fallback toggle.
