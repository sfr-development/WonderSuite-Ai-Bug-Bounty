# Intruder

Intruder is the automated fuzzing engine. You take one request template, mark the spots you want to vary, hand it a list of payloads, and it fires the whole matrix — then you sift the results for the responses that stand out.

Open it with <kbd>Ctrl+5</kbd>.

## Attack types

Pick the attack type in the toolbar — it decides how payloads map to positions:

| Type | Behaviour |
|---|---|
| **Sniper** | One payload set, one position at a time. Best for testing each parameter individually. |
| **Battering Ram** | The same payload goes into every position at once. |
| **Pitchfork** | Multiple payload sets advance in parallel — position N draws from set N. |
| **Cluster Bomb** | Every combination of every set across every position. The matrix grows fast. |

## Positions tab

Edit the **request template** here. Mark an injection position by selecting text and clicking **Add §** — the selection is wrapped in `§…§` markers.

- **Auto** marks likely parameters automatically.
- **Clear** removes all markers.

The toolbar shows the live position count.

## Payloads tab

The left sidebar lists your **payload sets** (add as many as the attack type needs). For each set choose a type:

- **Simple List** — one payload per line in the text area.
- **Numbers** — a numeric range (`from` / `to` / `step`).
- **Brute Force** — every string from a `charset` between a min and max length.
- **Null Payloads** — N empty payloads (re-sends the base request N times).

### Payload processing

Each set can carry a chain of **processors** applied to every payload before it's sent: URL/Base64/Hex/HTML encode & decode, MD5 / SHA-1 / SHA-256 hashing, upper/lowercase, reverse, prefix, suffix, and match & replace.

## Options tab

- **Throttle** — milliseconds to wait between requests.
- **Follow Redirects** — toggle redirect following.
- **Grep — Match / Extract** — add rules that scan each response. A **match** rule flags responses containing a string/regex; an **extract** rule pulls a capture group into its own results column.

## Results tab

A live, sortable table — `#`, payload, status, length, time, grep match, any grep-extract columns, and error. Rows with a grep match are highlighted. Click a row for the full response (headers + body preview) in the detail pane. Export the whole result set as **CSV** or **JSON**.

While an attack runs, the toolbar shows a progress bar with completed/total, elapsed time, and ETA — and you can **Pause**, **Resume**, or **Stop**.

## Turbo Intruder — race conditions

The **Turbo Intruder** tab is a dedicated race-condition tester. It fires N identical requests using barrier synchronization so they all release at the same microsecond — the technique for finding TOCTOU bugs (double-spend, coupon reuse, limit bypass).

Configure method, URL, headers, body, **concurrent request count** (2–50), and timeout, then **Fire**. The summary reports total/fastest/slowest time, timing spread, and the set of status codes seen — a spread of status codes is a strong race-condition signal. The results table shows each request's status, response time, barrier wait, and body preview.
