# Scanner

The Scanner is WonderSuite's automated vulnerability auditor. Point it at a target, it crawls the app and probes every parameter it finds for a configurable set of vulnerability classes, then streams findings back with full request/response evidence.

Open it with <kbd>Ctrl+6</kbd>.

## Starting a scan

1. Type a target URL in the toolbar.
2. Pick a **scan type**:
   - **Crawl & Audit** — crawl the app, then actively probe everything found.
   - **Passive Audit** — observe only; no active payloads sent.
   - **OWASP Top 10** — focused on the OWASP Top 10 classes.
   - **Lightweight** — a fast, shallow pass.
   - **API Scan** — tuned for JSON/REST API endpoints.
3. Click **Scan**.

Each scan runs as its own task and appears in the **Scan History** list on the left, with a live progress bar, request count, finding count, elapsed time, and detected technologies.

## Configuration

The gear button opens the config panel:

### Checks
Toggle individual checks, grouped by category:

- **Injection** — SQL Injection, Cross-Site Scripting, OS Command Injection, Template Injection (SSTI), XML External Entity.
- **Server** — Server-Side Request Forgery, Path Traversal / LFI.
- **Client** — Open Redirect, CORS Misconfiguration.
- **Config** — Security Headers, Cookie Flags, Information Disclosure.

Quick presets: **All**, **None**, **Critical Only**.

### Options
- **Max Requests** — request budget for the scan.
- **Crawl Depth** — how deep the crawler follows links.
- **Concurrency** — parallel request workers.
- **Follow Redirects** — toggle redirect following.

## Findings

Select a scan to see its findings. The stats bar shows an overall **risk score** (Clean → Critical Risk) and severity pills (Critical / High / Medium / Low / Info) you can filter by, plus a finding search box.

Click a finding for its detail pane with three tabs:

- **Detail** — parameter, payload, full description, collapsible evidence, and remediation guidance.
- **Request** — the exact raw request that triggered the finding.
- **Response** — the response, with status, timing, and size.

Finding actions: send to [Repeater](page:repeater), send to [Intruder](page:intruder), **Copy** (formatted text), and **Retest**. Right-click a finding for the shared context menu.

## Live Requests view

While a scan runs, switch to the **Live Requests** view to watch every request the scanner makes stream in real time — method, status, URL, timing, size. Useful for confirming the crawler is reaching the parts of the app you expect.

## Reports

Generate a full scan report as **HTML** or **JSON** from the stats bar — both download to disk.

> The Scanner shares its findings with the [Findings](page:findings) module, which aggregates results across all scans in the project. For blind vulnerabilities (out-of-band), pair the Scanner with [OAST](page:oast).
