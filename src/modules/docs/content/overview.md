# Overview

**WonderSuite** is a desktop-native offensive security engine — a full web-application testing platform that pairs Burp Suite-class tooling with an AI agent surface. Everything runs locally: a Rust backend drives a MITM proxy, a vulnerability scanner, recon tooling, and a bundled browser, all wired into a React interface.

## What's in the box

WonderSuite is organized into modules, grouped in the sidebar:

- **Core** — [Dashboard](page:dashboard), [Intercept](page:intercept), [Traffic](page:traffic). Watch and control what flows through the proxy.
- **Testing** — [Repeater](page:repeater), [Intruder](page:intruder), [Scanner](page:scanner), [WebSocket](page:websocket), [OAST](page:oast). Actively probe the target.
- **Recon** — [Sitemap](page:sitemap), [Discovery](page:discovery), [OSINT](page:osint). Map the attack surface.
- **Analysis** — [Sequencer](page:sequencer), [Comparer](page:comparer), [Logger](page:logger), [Templates](page:templates), [Payloads](page:payloads). Analyse tokens, diffs, and run detection checks.
- **Workflow** — [Organizer](page:organizer), [Session](page:session), [Agent](page:agent), [Tools](page:tools), [Findings](page:findings). Stay organized and track results.
- **Settings** — [General](page:settings-general), [MCP Server](page:settings-mcp), [Proxy](page:settings-proxy), [Appearance](page:settings-appearance), [Browser](page:settings-browser), [AI Skill](page:settings-skill).

## The AI angle

WonderSuite exposes its entire toolset over the **Model Context Protocol (MCP)**. A connected AI assistant can drive the proxy, scanner, browser, and recon tools autonomously — using the exact same primitives you use through the UI. The [MCP Server](page:settings-mcp) settings connect an AI client; the [AI Skill](page:settings-skill) teaches it how to use WonderSuite well; the [Agent](page:agent) module shows you what it's doing in real time.

## A typical first session

1. Open or create a [project](page:projects) (or start a Quick Session).
2. From the [Dashboard](page:dashboard), click **Launch Browser** — this starts the proxy and opens [WonderBrowser](page:settings-browser) already wired to it.
3. Browse the target. Requests stream into [Traffic](page:traffic) and the [Sitemap](page:sitemap) builds itself.
4. Set your [scope](page:settings-general) so noise from third-party domains is filtered out.
5. Send interesting requests to [Repeater](page:repeater) or [Intruder](page:intruder) via right-click, or point the [Scanner](page:scanner) at the target.
6. Confirmed issues collect in [Findings](page:findings); export a report when done.

## Responsible use

WonderSuite is for **authorized** security testing, defensive research, and education. Only test systems you own or have explicit written permission to assess.

> New to the layout? Read [The Workspace](page:workspace) next, then [Projects & Launcher](page:projects).
