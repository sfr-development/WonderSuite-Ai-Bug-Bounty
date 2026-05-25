# Ports

Built-in TCP / UDP / SYN port scanner with in-process service detection. No nmap subprocess — every probe is a Rust async function in the WonderSuite binary, matched against the **real nmap-service-probes file** (187 probes, 12k+ regex match patterns) bundled at build time.

## Quick start

1. Enter a **Target** — hostname, IPv4, IPv6, CIDR (`10.0.0.0/24`), or range (`192.168.1.1-50`). Comma-separate multiple targets.
2. Pick a **Ports** preset (Top 100 is the default) or type a custom spec like `80,443,8080-8090`.
3. Hit **Start**. Results stream in live; sort, filter, or export at any time.

## Scan modes

| Mode | Admin? | Status |
|------|--------|--------|
| **TCP Connect** | No | ✅ Default, fully supported on all platforms |
| **TCP SYN** | Yes | ✅ Real raw-socket engine — Linux pnet, macOS bpf, Windows Npcap |
| **UDP** | No | ✅ Protocol-specific probes (DNS / SNMP / NTP / SSDP / 14 services) |

### TCP SYN — privilege model

The SYN engine sends raw TCP SYN packets and listens for SYN/ACK responses via stateless SipHash sequence-cookie matching (masscan technique). On each OS:

- **Linux**: needs `CAP_NET_RAW`. The ElevationModal shows:
  ```
  sudo setcap cap_net_raw,cap_net_admin=+eip /path/to/wondersuite
  ```
  After running once, the capability sticks until the binary is overwritten.

- **macOS**: requires running as root. Restart WonderSuite via `sudo ./WonderSuite`. Apple does not publish a sandbox entitlement for raw packets — a signed LaunchDaemon helper for non-root operation is on the v0.3.8 roadmap.

- **Windows**: uses the **bundled WinDivert** driver (LGPLv3, EV-signed by Reqrypt LLC, ~140 KB shipped inside WonderSuite). The ElevationModal includes an **"Install network driver"** button that copies the bundled `WinDivert64.sys` to `%ProgramData%\WonderSuite\drivers\` and installs it as a Windows kernel-mode service via the SCM API. Single UAC prompt for life. No external download. **HVCI / Memory Integrity** (Core Isolation in Windows Security) must be disabled for any third-party kernel driver to load — when enabled, the modal flags it clearly and the engine gracefully falls back to TCP connect for that scan.

If admin is missing on any platform, the scan **gracefully falls back to TCP connect** so you still get results.

### UDP

`tokio::net::UdpSocket` sends a protocol-specific probe per port and waits for a response. Responding ports are marked `open`; non-responders are `open|filtered` (we can't distinguish without raw ICMP unreachable capture — same as nmap UDP without root). Probes shipped for: DNS, DHCP, TFTP, NTP, NetBIOS-NS, SNMP, IKE/IPSec, RIP, IPMI, OpenVPN, SSDP, SIP, mDNS, QUIC.

## Timing templates

| Template | Permits | Timeout | Use case |
|----------|---------|---------|----------|
| T0 Paranoid | 1 | 5 min | IDS evasion / glacial pace |
| T1 Sneaky | 4 | 15 s | Subtle |
| T2 Polite | 16 | 10 s | Don't overload anything |
| **T3 Normal** | 256 | 3 s | Sensible default |
| T4 Aggressive | 1024 | 1.25 s | Fast scans of cooperative hosts |
| T5 Insane | 4096 | 300 ms | Lab networks only |
| T6 Ludicrous | 16384 | 150 ms | Friendly LAN, max throughput |

These are the **initial** permit counts. With **Adaptive concurrency** enabled (default), the permit pool floats live based on observed RTT — Little's Law: `in_flight = target_pps × RTT_p50`. The controller recomputes every 2 seconds with a 20% dead-band, floor 64, ceiling 65535.

## Service detection

Powered by the **real nmap-service-probes file** vendored into the binary at build time:

- **187 probes** + **11971 match patterns** + **203 softmatches**.
- Probe selection: NULL banner read first → port-relevant active probes by rarity ≤ intensity → fallback chain.
- Regex match with `$1..$9` capture interpolation into `product`, `version`, `info`, `hostname`, `os`, `device`, `cpe`.
- TLS handshake on 443/8443/9443/465/993/995/636/5671: extracts cert CN + SAN via lightweight DER scan (no x509 parser dependency at runtime).

Intensity slider (0–9) gates which probes are eligible: 0 = banner only, 5 = port-hint + HTTP fallback, 7 = nmap's default, 9 = exhaustive.

## Idle mode

When enabled, caps throughput at ~100 pps regardless of timing template. Useful for long scans running while you do other work on a field laptop.

## Exclude CDN

For range scans, **Exclude CDN** drops IP addresses that resolve into known CDN ranges (Cloudflare, Akamai, Fastly, CloudFront, etc.) before scanning. Saves wasted probes on edge IPs that hit a generic frontend.

## Pop-out safety

Scan state lives in a global zustand store, so popping the Ports module into its own window mid-scan **does not interrupt the scan** — results stream to whichever window currently displays the module. Same applies to the live ticker, sparkline, and donut summary.

## Live UI feedback

- **Live ticker** — pulsing scrolling pills of the last 8 probes, colored by state.
- **PPS sparkline** — 160×32 SVG filling live during the scan, peak labelled.
- **Scan-completion donut** — services-by-count breakdown with relative-bar legend.
- **"?" Unverified pill** — flags open ports without a matching probe/banner so you know which rows to spot-check manually.

## Results table

Each row shows host, port, state pill (open / closed / filtered), service name, product+version, banner first line, RTT. Right-click actions:

- **Send to Scanner** — HTTP/HTTPS ports only. Auto-builds the URL and pops the active scanner.
- **Copy ip:port** — for piping into other tools.

The table is virtualized — handles 50k+ rows without freezing. Use the filter input above the table to narrow by hostname / service / banner substring. Toggle **Show closed/filtered** to display all results, not just open.

## Export formats

| Format | Filename hint | Use case |
|--------|---------------|----------|
| **JSONL** | `<scan_id>.jsonl` | Pipe into `httpx -json`, `nuclei -j`, `jq` |
| **CSV** | `<scan_id>.csv` | Spreadsheets, ad-hoc analysis |
| **Nmap XML** | `<scan_id>.xml` | `msfconsole db_import`, parsing with python-libnmap |
| **gnmap** | `<scan_id>.gnmap` | `grep` / `awk` pipelines |
| **ip:port** | `<scan_id>.txt` | `cat hosts.txt | httpx -ports` |

All export buttons currently copy the rendered output to your clipboard.

## MCP tools

For AI / automation use, 5 tools are exposed via the WonderSuite MCP server:

- **`port_scan`** — single host, all 3 modes, returns summary + scan_id
- **`port_scan_range`** — CIDR / range / list of hosts
- **`service_detect`** — surgical service probe on a known-open port
- **`banner_grab`** — raw bytes only, optional custom payload
- **`port_scan_results`** — paginated drill-down for a scan_id

See [MCP Tools Reference](page:mcp-tools) for full schemas.

## Why this instead of nmap / RustScan?

- **Real raw SYN engine in-process** — no nmap subprocess fork, no XML round-trip. masscan-style stateless SipHash cookies.
- **WinDivert bundled instead of Npcap** — single UAC prompt, no external download. WinDivert is LGPLv3 + EV-signed so we can legally ship the unmodified `.sys` (Npcap's free licence forbids bundling without an $11k/yr OEM contract). Total bundled-driver footprint: 140 KB.
- **Adaptive concurrency** — RustScan's `batch_size` is fixed at startup. Ours floats with observed RTT via Little's Law.
- **Live streaming** — RustScan dumps results at the end. Ours fills the table as ports respond.
- **Real nmap-service-probes** — RustScan pipes to a separate nmap subprocess to detect services. We embed the 2.46 MB probe file at build time and parse it ourselves.
- **Cross-module** — right-click any HTTP port → send to the active scanner; or push a sitemap host → "Scan ports".
- **Windows-friendly** — handles ephemeral port exhaustion (SO_LINGER trick) and detects it via `GetTcpStatistics2`. RustScan dies fast on Windows CONNECT scans without these mitigations.
