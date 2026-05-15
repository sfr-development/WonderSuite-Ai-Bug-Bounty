# The Workspace

Once a project is open, the WonderSuite window has four persistent regions around whatever module you're using.

## Title bar

The top strip — the WonderSuite logo and name on the left, window controls (minimize / maximize / close) on the right. The whole strip is draggable to move the window.

## Sidebar

The left rail is how you move between modules. It's organized into groups — **Core**, **Testing**, **Recon**, **Analysis**, **Workflow** — with [Documentation](page:overview) and [Settings](page:settings-general) pinned at the bottom.

- Click the **collapse/expand** toggle at the top to switch between icon-only and labelled modes.
- In expanded mode, group headers collapse to hide groups you're not using.
- Hover any icon in collapsed mode for a tooltip with the module name and its shortcut.

Modules stay *mounted* once you've visited them — timers, polling, and in-flight scans keep running when you switch away, so you never lose state by changing tabs.

## Status bar

The bottom strip shows live engagement state:

- **Proxy** status — `Proxy Active` or `Ready`.
- The **active project** name (with a **TEMP** badge for temporary projects, and a `×` to close it).
- **Requests** and **Intercepted** counters.
- Process **memory** usage, CPU **architecture**, and the WonderSuite **version**.

## Context menu

Right-click almost any request — in [Traffic](page:traffic), [Sitemap](page:sitemap), [Logger](page:logger), [Findings](page:findings), [Discovery](page:discovery), and more — for the shared context menu. It's the connective tissue between modules:

- **Send to** [Intruder](page:intruder), [Repeater](page:repeater), [Sequencer](page:sequencer), [Organizer](page:organizer), or [Comparer](page:comparer) (left/right side).
- **Add to scope**.
- **Request in browser** — WonderBrowser or system browser.
- **Engagement tools** — search, find comments/scripts/references, analyze target, discover content, schedule scan, auto-setup attack.
- **Copy URL**, **Copy as cURL**, **Save item**.

## Toasts

Short-lived notifications appear in the corner — operation results, errors, confirmations. They dismiss themselves; click the `×` to close one early.
