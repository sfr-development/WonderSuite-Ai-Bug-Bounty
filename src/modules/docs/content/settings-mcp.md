# Settings — MCP Server

The **MCP Server** tab controls WonderSuite's Model Context Protocol server — the bridge that lets an AI assistant drive WonderSuite's tools.

## What MCP is

MCP (Model Context Protocol) is a standard for exposing tools to AI clients. WonderSuite runs an MCP server that publishes its entire toolset — proxy control, scanner, recon, the browser surface, codec utilities — as callable tools. Any MCP-compatible AI (Claude, Cursor, Windsurf, VS Code, Antigravity, Gemini CLI, …) can then operate WonderSuite autonomously, using the exact same primitives a human uses through the UI.

## Server status

The status panel shows whether the server is **Running** or **Stopped** and which port it's listening on. The **Start / Stop** button controls it.

- **Port** — the TCP port the MCP server binds (default `3100`). The server endpoint is `http://127.0.0.1:<port>/mcp`.

## IDE Integration

WonderSuite auto-detects supported AI editors installed on your machine — **Cursor, Windsurf, Antigravity, VS Code, Void, Gemini CLI** — and offers **one-click install**: it writes the correct MCP configuration into that editor's config file for you. Detected editors show whether WonderSuite is already installed in them.

If your editor isn't detected, you can still wire it up manually by pointing its MCP config at `http://127.0.0.1:<port>/mcp`.

## Available Tools

A live, searchable list of every tool the MCP server currently exposes — each with its name, description, and category badge. Use the filter box to find a specific tool. For the full categorized reference, see [MCP Tools Reference](page:mcp-tools).

> Connecting an AI is only half the job — to make it *use* WonderSuite well, also install the [AI Skill](page:settings-skill). Watch what a connected AI does live in the [Agent](page:agent) module.
