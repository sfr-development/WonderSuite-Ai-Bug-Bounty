# Tools

Tools is WonderSuite's utility belt — a collection of small, self-contained helpers for the encoding, decoding, and conversion work that comes up constantly during testing. Pick a tool from the nav bar at the top.

Open it with <kbd>Ctrl+9</kbd>.

## Decoder

Encode, decode, and hash text through **Base64, URL, HTML, and Hex**, plus **SHA-1 / SHA-256 / SHA-512** hashing. Operations chain — each one applies to the current output and is recorded in the chain history. **Smart** auto-detects and peels back layered encodings (e.g. URL-encoded Base64) in one click.

## JWT

Paste a JSON Web Token to decode its **header** and **payload** without verifying the signature. Shows the algorithm, the claims, the `iat` / `exp` timestamps, and whether the token is **expired**.

## Timestamp

Convert between Unix timestamps (seconds or milliseconds) and human-readable dates. Accepts a numeric timestamp or a date string and returns UTC, ISO 8601, local time, Unix seconds, and milliseconds.

## Regex

A live regex tester — enter a pattern and a body of text, and see every match. Regex errors are reported inline.

## Hash

Hash a string with **SHA-1, SHA-256, and SHA-512** all at once.

## Comparer

A line-level diff — paste two values and see added (green) and removed (red) lines highlighted. For full request/response diffing with word-level granularity, the dedicated [Comparer](page:comparer) module has more.

## IP / CIDR

Enter an IP address or CIDR range (e.g. `192.168.1.0/24`) and get the full breakdown: network and broadcast address, first/last usable host, netmask, host count, wildcard mask, and the address in binary, hex, and decimal.

## PassGen

A cryptographically secure password generator (uses the Web Crypto API). Choose the **length** and how many to **generate at once**, toggle the character sets — `A-Z`, `a-z`, `0-9`, symbols — and copy any result.

## Headers

An HTTP header builder. Add key/value rows by hand, or apply a **preset** — `Auth Bearer`, `JSON POST`, `CORS Bypass`, `WAF Bypass`, `Cache Poison` — then **Build** to get the raw header block ready to paste into [Repeater](page:repeater) or [Intercept](page:intercept).

## Research

A security-research search panel. Enter a query and get jump-off links to Google, Shodan, CVE Details, ExploitDB, and HackerTarget (or live results, if a web-search MCP tool is connected). **Load Hosts** pulls the unique hosts seen in proxy traffic so you can pivot a search straight onto a discovered host.
