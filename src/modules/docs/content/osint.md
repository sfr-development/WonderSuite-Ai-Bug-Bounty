# OSINT

OSINT is passive reconnaissance — it gathers intelligence about a target from public, third-party sources without ever touching the target's own infrastructure (with one exception: the live-fetch tabs).

Enter a domain or URL in the toolbar and click **Scan** — the active tab decides which lookup runs.

## WHOIS / RDAP

Registration intelligence via RDAP (the modern WHOIS). Returns the registrar, domain status, creation/update/expiry dates, the registered organisation, nameservers, and contact entities. WonderSuite walks the IANA bootstrap plus ARIN, Verisign, and rdap.org to find a server that answers.

## DNS Records

Resolves **A, AAAA, CNAME, MX, TXT, and NS** records for the domain using Google's DNS-over-HTTPS API — no API key, no local resolver dependency. Each record shows its type, value, and TTL.

## Certificates

Queries **crt.sh** Certificate Transparency logs. Every SSL certificate ever issued for the domain is public, and each one lists the hostnames it covers — so CT logs are one of the richest subdomain sources available. Results list each discovered subdomain, its issuer, and expiry date. **Copy All** grabs the full subdomain list.

## Wayback Machine

Queries the Internet Archive's CDX API for **historical URLs** of the domain — up to 200 archived paths with their capture date, status code, and MIME type. This surfaces deleted endpoints, old API versions, and pages that no longer link from anywhere but may still be live.

## Security Headers

Fetches the target and audits its HTTP response for ten security headers — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and the Cross-Origin-* family. Each is marked **present** or **missing** with a short note on what it protects against, plus an overall score. The raw response headers are available in a collapsible section.

## Tech Detect

Fingerprints the target's technology stack from its response headers and HTML body — web server, language, framework, CMS, JS libraries, CSS frameworks, CDN/WAF, e-commerce platform, and analytics. Each detection shows the category and what evidence triggered it.

> The DNS, Wayback, Security Headers, and Tech Detect tabs do make a request — the first two to third-party APIs, the last two directly to the target. WHOIS and Certificates are fully passive.
