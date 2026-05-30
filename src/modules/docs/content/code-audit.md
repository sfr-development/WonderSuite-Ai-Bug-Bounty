# Code Audit

The Code Audit tab lives inside the **Sitemap** module (open with <kbd>Ctrl+7</kbd>, then switch to the **Code Audit** tab). It performs passive source-level analysis on every asset the proxy has captured — no separate scan or crawl step required.

Assets populate automatically as traffic flows through the proxy. The finder engine re-runs in the background whenever new assets arrive.

## Three-column layout

### Left — Asset tree

Assets are grouped as **Domain → Type → File**. Types:

| Type | Colour | Covers |
|---|---|---|
| JS | amber | JavaScript, TypeScript, JSX |
| CSS | blue | Stylesheets, SCSS |
| HTML | red | HTML documents |
| API | yellow | Endpoints matching `/api/`, `/v1/`, `/graphql/` etc. |
| Images | green | PNG, JPEG, SVG, WebP, ICO |
| Fonts | purple | TTF, WOFF, WOFF2 |
| Media | teal | MP4, WebM, MP3, OGG |
| Other | grey | Everything else |

Each node shows:
- A **red badge** with the finding count for that file or group.
- The file size.

Use the **filter input** to narrow by filename or path.

The **type-chip toolbar** at the top toggles which asset types are included in the analysis. The **Settings gear** opens a panel to fine-tune active finders and asset types individually.

Click **Export Tree** at the bottom to save a formatted `.txt` asset manifest.

### Middle — Editor

Click any file node to open it in the editor. The source is:
1. **Auto-beautified** via `js-beautify` (JS, TS, CSS, HTML, JSON) — minified assets become readable.
2. **Syntax-highlighted** with Shiki using the `one-dark-pro` theme.

Click any **finding row** in the right panel to scroll the editor to that line, which flashes amber for 2.5 seconds.

The editor header shows the filename, language tag, finding count badge, and a **Copy** button that copies the beautified source.

### Right — Panel

Two tabs:

**Findings** — findings for the currently selected file, grouped by category and sorted by severity (Critical → Info). Each row shows the severity badge, the matched value, the filename + line number, and the pattern name. Click any row to jump to that line in the editor. Each section header has its own **Export** button.

When no file is selected, the Findings tab shows a prompt; when the selected file has no findings, it confirms the file is clean.

**Summary** — global statistics across all analysed assets:
- Asset counts by type.
- Total captured size.
- Finding counts by severity (Critical, High, Medium, Low, Info).
- **Full export menu** (see [Export](#export)).

A **"This file only" toggle** scopes the summary to the currently selected file — useful for quick per-file reporting.

## Finder engine

The engine runs 60+ regex patterns across five categories:

### Secrets

| Pattern | Severity |
|---|---|
| AWS Access Key ID (`AKIA…`) | Critical |
| AWS Secret / Session Token | Critical |
| OpenAI API key (`sk-…T3BlbkFJ…`, `sk-proj-…`, `sk-o…`) | Critical |
| Anthropic API key (`sk-ant-…`) | Critical |
| GCP Service Account JSON | Critical |
| Supabase service role key | Critical |
| MongoDB / Postgres / MySQL connection string | Critical |
| HashiCorp Vault token | Critical |
| Stripe live key (`sk_live_…`) | Critical |
| GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `gha_`, PAT) | Critical |
| DigitalOcean PAT (`dop_v1_…`) | Critical |
| Azure Storage connection string | Critical |
| Shopify access token (`shpat_…`) | Critical |
| Braintree access token | Critical |
| Private key block (`-----BEGIN … KEY-----`) | Critical |
| Twilio Auth Token | Critical |
| Google API key (`AIza…`) | High |
| HuggingFace token (`hf_…`) | High |
| Replicate API key (`r8_…`) | High |
| GCP OAuth client ID | High |
| Supabase anon key | High |
| Stripe webhook secret (`whsec_…`) | High |
| Slack token (`xox…`) / webhook | High |
| SendGrid key (`SG.…`) | High |
| Mailgun key | High |
| SMTP credentials URL | High |
| Twilio SID (`AC…`) | High |
| Telegram bot token | High |
| Discord bot token / webhook | High |
| NPM token (`npm_…`) | High |
| Azure SAS token | High |
| Redis auth URL | High |
| Firebase server key | High |
| Hardcoded password / secret | High |
| Heroku API key | High |
| Shopify shared / API key | High |
| Stripe test key | Medium |
| Firebase config block | Medium |
| Supabase URL | Medium |
| Sentry DSN | Medium |
| `.env`-style env var (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` + KEY/TOKEN/SECRET) | Medium |
| `process.env.*SECRET` reference | Medium |

### Tokens

JWT, Bearer token, Basic Auth, OAuth access token, id_token, refresh_token, session cookies (PHPSESSID, JSESSIONID, `__session`).

### API Endpoints

`fetch()`, `axios.*()`, XHR `.open()`, API path strings (`/api/`, `/v1/`, `/graphql/`), GraphQL operation names, WebSocket URLs (`new WebSocket(…)`), gRPC endpoints, tRPC router paths.

### Links

Absolute HTTPS/HTTP URLs (localhost excluded), relative paths of 7+ characters.

### Comments

`// TODO`, `// FIXME`, `// HACK`, `// BUG`, `// DEPRECATED`, comments containing words like `password`, `secret`, `private_key`, or `credential`.

---

Findings are deduplicated per pattern+value pair and capped per category to avoid noise floods:

| Category | Cap |
|---|---|
| Links | 150 |
| Comments | 80 |
| API Endpoints | 200 |
| Tokens | 100 |
| Secrets | 500 |

## Export

### From the Summary panel

| Option | Output |
|---|---|
| **Export All (HTML + JSON)** | Opens two save dialogs: full HTML report, then JSON data |
| Full Data (JSON) | Complete result JSON with all assets + findings |
| HTML Report | Self-contained dark-theme HTML security report |
| Asset Tree (TXT) | Formatted folder/file manifest |
| Secrets only (CSV) | Severity, type, value, file, line |
| Tokens only (CSV) | Same format |
| API Endpoints (TXT) | Deduplicated sorted URL list |
| Links (TXT) | Deduplicated sorted URL list |

### From the right-click context menu (per domain / type / file)

Right-click any node in the asset tree to get a context menu scoped to that selection:

| Item | Scope |
|---|---|
| Export Source (formatted) | Single file: beautified source |
| Export All Sources (concat) | All code files in scope, concatenated |
| Export {Type} Only | Type-group: one file type concatenated |
| HTML Report | All findings for this scope as HTML |
| All Findings (CSV) | Every finding for this scope |
| Secrets only / Tokens only (CSV) | Filtered by type |
| API Endpoints / Links (TXT) | Filtered by type |
| Asset List (JSON) | Asset metadata (URL, type, size, status) |
| **Export as ZIP (All Files)** | Full bundle — see below |
| Copy URL | Copies the node URL to clipboard |

### Export as ZIP

The ZIP export bundles all assets for the selected domain or type-group into a structured archive:

```
<domain>_audit.zip
└── <domain>/
    ├── js/          ← JavaScript files (auto-formatted)
    ├── css/         ← Stylesheets (auto-formatted)
    ├── html/        ← HTML documents
    ├── api/         ← API response bodies
    ├── images/
    │   └── _image_urls.txt   ← URLs only (binary not captured)
    ├── fonts/
    │   └── _font_urls.txt
    ├── findings/
    │   ├── secret.csv
    │   ├── token.csv
    │   ├── api-endpoint.txt
    │   ├── link.txt
    │   ├── comment.csv
    │   ├── all-findings.csv
    │   └── report.html
    ├── assets.json  ← full asset metadata
    └── README.txt   ← export summary
```

Clicking **Export as ZIP** opens a native OS save dialog. The archive is written directly to disk via Tauri's `save_file_bytes` command.

## Settings

Click the **gear icon** (top-right of the toolbar) to open the finder settings:

- **Asset Types to Analyse** — toggle each type (HTML, JS, CSS, Images, Fonts, Media, API, Other) individually.
- **Active Finders** — enable or disable each category (Secrets, Tokens, API Endpoints, Links, Comments).

Changes take effect immediately; the finder engine re-runs within ~400 ms.

## Tips

- **Jump to a finding fast** — click the finding row in the right panel; the editor scrolls and flashes that line amber.
- **Scope a report to one file** — select the file, switch to the Summary tab, toggle "This file only", then export.
- **Reduce noise** — disable Links and Comments in the Settings panel when you only care about secrets and tokens.
- **Minified files** — the editor always auto-beautifies before display AND before running the finders, so line numbers in findings match what you see.
- **Coverage** — assets only appear if they passed through the proxy with a response body. Switch to the Sitemap tab and browse the target to capture more assets.
