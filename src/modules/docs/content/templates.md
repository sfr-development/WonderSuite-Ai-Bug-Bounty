# Templates

The Templates module is WonderSuite's library of ready-made detection checks — each one a small, named probe that looks for a specific weakness: an exposed file, a known CVE, a default login, a dangling subdomain. Point them at a target and run them in bulk.

## The library

Every template carries an ID, name, description, severity, category, and tags. Browse and narrow the library with:

- **Category** — `exposures`, `misconfiguration`, `cves`, `vulnerabilities`, `default-logins`, `takeovers`, `technologies`, `fuzzing` (or `all`).
- **Severity** — filter to Critical / High / Medium / Low / Info.
- **Search** — matches ID, name, description, and tags.
- **View** — `grid` (cards) or `table` (dense list).

The header shows how many templates exist at each severity.

## Running templates

1. Enter a **target URL** in the toolbar — it's remembered between sessions.
2. Run a single template from its card/row, or **Run All** to execute every runnable template in the current filter.
3. Bulk runs go 6 at a time; **Cancel** stops the batch, **Clear** resets results.

Each template ends in one of four states:

| State | Meaning |
|---|---|
| **Hit** | The probe matched — the weakness is present. |
| **Miss** | The probe ran but didn't match. |
| **Error** | The request failed (unreachable, timeout). |
| **Pending** | Currently running. |

The run stats bar tallies hits / misses / errors / pending. Toggle **Only show hits** to collapse the list down to confirmed results.

## From hit to finding

Select a template to see its full detail — description, the probe it runs, and remediation guidance. When a template scores a **Hit**, send it straight to the [Findings](page:findings) module, where it's recorded with its severity, evidence (the matched response), and remediation text — the same place [Scanner](page:scanner) results land.

> Some templates are marked **interactive** — they need manual steps and are skipped by Run All. Run those individually.
