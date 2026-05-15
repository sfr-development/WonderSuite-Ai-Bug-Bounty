# Projects & Launcher

When WonderSuite starts, the **Project Launcher** is the first thing you see. A project is the container for everything in an engagement — captured traffic, findings, scope, and configuration.

## The launcher

The launcher lists your existing projects (searchable) and lets you open one, create a new one, or start a throwaway session.

## Creating a project

The **create-project wizard** walks you through:

- **Name**, **description**, and **target URL** — when you enter a target, its hostname is auto-added to the project's scope (both `host` and `*.host`).
- **Project type** — `Pentest`, `Bug Bounty`, `Research`, `CTF`, or `Custom`. The type is metadata that describes the engagement.
- **Proxy & startup** — proxy port, and whether to auto-start the proxy, auto-launch the browser, and enable interception on open.
- **Scope** — the initial in-scope URL patterns.
- **Client name**, **tags**, and **max traffic entries**.

A created project is persistent — its data is saved to disk and you can reopen it later.

## Temporary projects

Two ways to work without a saved project:

- **Quick Session** — an in-memory session. Nothing is written to disk; data is gone when you close it. Good for a fast one-off look at a target.
- **Temporary project** — created through the wizard with the *temporary* flag and a TTL (time-to-live in hours). It behaves like a project but is meant to be short-lived.

Temporary projects are marked with a **TEMP** badge in the [status bar](page:workspace).

## Switching projects

The active project name shows in the status bar at the bottom of the window. Closing the project (the `×` next to its name) returns you to the launcher, where you can open a different one.
