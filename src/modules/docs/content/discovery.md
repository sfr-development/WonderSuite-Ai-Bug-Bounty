# Discovery

Discovery is the active reconnaissance module — it finds the parts of a target that aren't linked from anywhere: hidden directories and files, forgotten subdomains, and undocumented parameters.

Enter a target URL in the toolbar; the three tabs each run their own kind of scan against it.

## Directories & Files

Content discovery — probes the target for paths that exist but aren't advertised.

Options:
- **Wordlist** — `Common (~300)`, `Medium (~1000)`, or `Large (~5000)`.
- **Extensions** — comma-separated list of extensions to append (`php,html,js,json,txt,bak,env`…).
- **Recursive** — descend into discovered directories.

Click **Start Scan**. The results table lists each found path with its status code, response size, and content type. A progress line tracks how far the scan has got. Copy a full URL with the row's copy button, or right-click a result to send it on to another module.

Watch for the high-value hits: `.env`, `.git/config`, backup files, `swagger` / `api-docs`, admin panels, and `phpinfo`.

## Subdomains

Subdomain enumeration — finds other hosts under the same domain.

Options:
- **Wordlist** — `Small (~60)`, `Medium (~100)`, or `Large (~200)` common prefixes.
- **Use crt.sh** — also pull subdomains from Certificate Transparency logs.

Click **Enumerate**. The table shows each resolvable subdomain, its HTTP status, and state (`alive`, or `alive (http)` if only plain HTTP responded). Right-click a subdomain to push it into another module.

## Hidden Parameters

Parameter discovery — finds query/body parameters the endpoint accepts but doesn't document.

Pick a **method** (`GET` or `POST`) and click **Find Parameters**. WonderSuite captures a baseline response, then injects each candidate parameter name one at a time. Any parameter that shifts the **status code** or the **response size** beyond a threshold is flagged, with the evidence (status and size delta) shown next to it.

Discovered parameters are prime targets — feed them into the [Intruder](page:intruder) or [Scanner](page:scanner) for injection testing.

> Discovery does active probing against the target. Only run it against systems you are authorized to test.
