# Findings

Findings is the project's vulnerability register — the single place where every confirmed issue lands, no matter which module discovered it. Where the [Scanner](page:scanner) shows the results of *one* scan, Findings aggregates across *all* of them.

Open it with <kbd>Ctrl+0</kbd>.

## Where findings come from

Findings collects results automatically:

- The [Scanner](page:scanner) streams every finding here as it runs.
- The [Templates](page:templates) module sends confirmed hits here.

You don't add findings by hand — the module pulls them in and keeps them in sync.

## The list

Each finding shows a severity dot, title, confidence level, the affected path and URL, and a status badge. Filter the list with:

- **Search** — matches title and URL.
- **Severity buttons** — `Critical`, `High`, `Medium`, `Low`, `Info`; click to toggle each on/off.

The count of currently-shown findings sits at the end of the toolbar.

## The detail pane

Select a finding to see the full write-up:

- **Severity** and **confidence** badges, plus the affected path.
- **Description** — what the issue is.
- **Evidence** — the captured proof (request/response excerpt).
- **Remediation** — how to fix it.

## Triage status

Each finding has a **status** you set from the detail pane:

| Status | Meaning |
|---|---|
| **New** | Not yet reviewed. |
| **Confirmed** | Verified as a real issue. |
| **False Positive** | Reviewed and dismissed. |
| **Fixed** | Remediated. |

## Export & context menu

**Export** downloads all findings as a JSON file — the basis of a report. Right-click a finding for the shared context menu (send the request to [Repeater](page:repeater) to re-verify, etc., or delete it).
