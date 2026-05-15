# Sitemap

The Sitemap builds a structured map of the target application from everything WonderSuite has seen. Every host, directory, page, API endpoint, and asset that passes through the proxy is folded into a tree automatically — no manual crawling step.

Open it with <kbd>Ctrl+7</kbd>.

## How it's built

The Sitemap listens to proxy traffic live. As requests flow through, each URL is broken into host → path and slotted into the tree. Repeated hits on the same path are grouped, so one node can hold many traffic entries.

Nodes are typed by extension and MIME, each with its own icon: **host**, **directory**, **file** (page), **JS**, **CSS**, **font**, **image**, **API endpoint**, and **media**.

## View modes

Three ways to look at the same data, switched from the toolbar:

- **Tree View** — the classic collapsible host/path tree.
- **Flow Map** — an interactive node graph showing how the site links together.
- **Mermaid** — the structure rendered as a Mermaid diagram, with the diagram source available to copy.

## Filtering and the blacklist

- The **filter box** narrows the tree to matching paths.
- The **Blacklist** keeps noise out permanently — add URL patterns (wildcards supported) and matching nodes are excluded from the Sitemap. The blacklist persists across sessions. Manage entries from the blacklist panel.

## Delete mode

Toggle **Select & Delete** to get a checkbox on every node. Mark the nodes you don't want and confirm — useful for pruning analytics, CDN, and third-party noise. You can also delete a single node from its right-click menu.

## The detail pane

Select any node to inspect its captured traffic. The detail pane has four tabs:

- **Overview** — method, status, size, timing, content type, TLS.
- **Request** — the raw request, with syntax highlighting.
- **Response** — the raw response body, syntax-highlighted by language (JS, CSS, JSON, HTML, XML); image responses are previewed inline.
- **Headers** — request/response headers, with security headers, sensitive headers, and content-type colour-coded.

A **Format** toggle beautifies minified JS/CSS/JSON/HTML in place, and every view has a **Copy** button.

## Export & context menu

**Export** saves the Sitemap structure to a file. Right-click any node for the shared context menu — send the request to [Repeater](page:repeater), [Intruder](page:intruder), [Scanner](page:scanner), and more.
