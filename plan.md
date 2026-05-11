# WonderBrowser v0.2.0 — Vendored Chromium Plan

Status: planning
Target release: v0.2.0
Estimated total effort: 5-6 days of focused work

## 0. TL;DR

Ship our own pinned Chromium ("WonderBrowser") instead of detecting the user's system browser, modeled after Burp Suite's `burpbrowser` but improving on the parts where Burp leaves obvious gaps (no GC of old versions, no multi-profile, no native fingerprint evasion, no auto-AppArmor profile on Ubuntu).

Source binary: **Chrome for Testing (CfT)** — Google's official signed Chromium builds for automation, free to redistribute, stable URL pattern.

Distribution: **lazy download on first launch**, not bundled in the installer. Chosen over Burp's "bundle everything" model because our installer is currently ~15 MB and we want to keep it that way; the trade-off is a one-time ~120 MB download on first browser use, with a clear progress modal.

---

## 1. Why now

Current state (v0.1.5):
- `browser.rs` scans `C:\Program Files\Google\Chrome`, `Edge`, `Brave`, etc. and spawns whichever is found
- User's real Chrome profile gets touched (cookies / extensions / history visible in the testing session)
- We installed our CA into the OS trust store via `certutil` until v0.1.4 (removed in favor of `--ignore-certificate-errors`)
- Stealth patches are CDP-injected, which itself leaves detectable fingerprint artifacts

Problems:
1. **Test-matrix explosion.** Chrome 142 renames a flag, our patch breaks. Edge 140 has different defaults. Brave's shields fight our proxy. We have N browsers × M versions × 3 platforms to support without owning any of them.
2. **Fingerprint surface.** CDP-injected stealth still leaves `window.cdc_*` / `Runtime.evaluate` traces. Real Chrome extensions don't.
3. **Profile pollution risk.** Even with our own `--user-data-dir`, users get nervous about pointing a security tool at their browser binary.
4. **Burp does this, Caido does this. We currently do not.** Common expectation in the segment.

Reference research: see [the deep-research dump on Burp's browser](#research-references) section at the end of this doc.

---

## 2. Source binary: Chrome for Testing (CfT)

URL pattern: `https://storage.googleapis.com/chrome-for-testing-public/<VERSION>/<PLATFORM>/chrome-<PLATFORM>.zip`

Index of known-good versions: `https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json`

Platform zips (sizes from CfT manifest, December 2025 stable):

| Our platform key | CfT zip name | ~Size |
|---|---|---|
| `win64` | `chrome-win64.zip` | ~120 MB |
| `mac-arm64` | `chrome-mac-arm64.zip` | ~155 MB |
| `mac-x64` | `chrome-mac-x64.zip` | ~155 MB |
| `linux64` | `chrome-linux64.zip` | ~140 MB |

CfT is the right choice over alternatives because:

- **Free to redistribute.** No PortSwigger-style "signed by us" complication.
- **Official Google signature.** Windows: Authenticode by Google LLC. macOS: notarized by Google.
- **Stable URL pattern.** No HTML scraping required.
- **Published checksums.** SHA-256 hashes for every artifact, fetchable via the JSON manifest at the same `googlechromelabs.github.io` index.
- **Real Chromium binary.** Not CEF, not Electron, not a fork — same engine our users expect.

Rejected alternatives:
- **Playwright's bundled Chromium**: tied to Playwright's release cycle, distributed via npm tarballs.
- **Electron's bundled Chromium**: extra Electron framework crap we don't want.
- **CEF**: doesn't expose `--load-extension` cleanly, missing DevTools polish.
- **Forking Chromium**: 10-day build, 100 GB build cache, immediate maintenance treadmill. No.

---

## 3. Distribution model

**Lazy download** on first browser use, with a progress modal. Not bundled.

Decision matrix:

| | Bundled (Burp-style) | Lazy-download (Caido-ish but with a vendored target) |
|---|---|---|
| Installer size | +120-155 MB per platform | unchanged (~15 MB) |
| Time to first browser launch | instant | ~30s on 50 Mbps |
| Offline-friendly | yes | no on first launch |
| CI complexity | install workflow downloads + bundles per platform | no change |
| Bandwidth cost on every update | ~120 MB every release | only when Chromium pin changes |
| User-visible UX cost | longer install, instant launch | quick install, one-time progress bar |
| Cleanup story | shipped artifact, hard to GC | cache dir under our control |

We pick lazy-download. The first-launch download time is offset by a tight progress UI, and the *recurring* cost (every WonderSuite point-release would re-bundle 120 MB if we shipped Burp-style) outweighs the one-time wait.

### 3.1 Storage layout

```
%LOCALAPPDATA%\WonderSuite\                  (Windows)
~/Library/Application Support/WonderSuite/   (macOS)
~/.local/share/WonderSuite/                  (Linux)
├── chromium\
│   ├── 131.0.6778.85\           ← current pin (full Chromium tree)
│   │   ├── chrome.exe / Chromium.app / chrome
│   │   ├── .verified            ← SHA256 success marker file
│   │   └── ...
│   └── 130.0.6723.69\           ← old pin, GC'd on next launch
├── browser-profiles\
│   ├── default\                 ← per Quick Session
│   └── <project-uuid>\          ← per persistent project
└── extensions\
    └── wondersuite-extension\   ← copied from app resources on first launch
```

**Garbage collection rule:** on launch, walk `chromium/*`, delete every version directory that isn't the currently pinned one. Burp doesn't do this and users complain about multi-GB `burpbrowser/` directories — we fix that for free.

---

## 4. Versioning & pinning

### 4.1 Pin file

`src-tauri/resources/chromium_pin.json` — versioned in git, shipped as a Tauri resource:

```json
{
  "chromium_version": "131.0.6778.85",
  "manifest_uri": "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json",
  "platforms": {
    "win64": {
      "url": "https://storage.googleapis.com/chrome-for-testing-public/131.0.6778.85/win64/chrome-win64.zip",
      "sha256": "<64 hex>",
      "binary_subpath": "chrome-win64/chrome.exe"
    },
    "mac-arm64": {
      "url": "https://storage.googleapis.com/chrome-for-testing-public/131.0.6778.85/mac-arm64/chrome-mac-arm64.zip",
      "sha256": "<64 hex>",
      "binary_subpath": "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
    },
    "mac-x64": {
      "url": "https://storage.googleapis.com/chrome-for-testing-public/131.0.6778.85/mac-x64/chrome-mac-x64.zip",
      "sha256": "<64 hex>",
      "binary_subpath": "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
    },
    "linux64": {
      "url": "https://storage.googleapis.com/chrome-for-testing-public/131.0.6778.85/linux64/chrome-linux64.zip",
      "sha256": "<64 hex>",
      "binary_subpath": "chrome-linux64/chrome"
    }
  }
}
```

### 4.2 Pin update automation

New workflow `.github/workflows/update-chromium-pin.yml`:

- Trigger: `schedule: cron: "0 6 * * 1"` (every Monday 06:00 UTC) + `workflow_dispatch`
- Steps:
  1. `curl https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json`
  2. Extract the `Stable` channel version + per-platform download URL + SHA-256
  3. Compare to current `chromium_pin.json`. If equal, exit.
  4. If newer: write a new `chromium_pin.json`, open PR with title `chore: bump Chromium pin to <version>` and a body that links to the upstream Chrome release notes
- We review and merge. Auto-merge is *not* enabled — we want eyes on each bump because a Chromium major can break our extension manifest.

Cadence target: **every 3-4 weeks** in normal weeks. CVE fast-track via manual workflow_dispatch (matches Burp's ~3-week cadence with critical-CVE fast-tracks).

### 4.3 Version pinning vs Chromium self-update

We pass `--disable-background-networking` (already in our flag set since v0.1.4) which kills Chromium's own component updater. Chromium will not auto-update. Every Chromium bump goes through `chromium_pin.json` + a new WonderSuite release.

---

## 5. Launch flags — Burp-compatible + extensions

Already largely in place since v0.1.4. Reproducing the full intended set here so the plan is self-contained.

```rust
// Proxy / cert
"--proxy-server=127.0.0.1:8080"
"--proxy-bypass-list=<-loopback>"          // critical: defeats Chrome 72+ localhost-bypass
"--ignore-certificate-errors"               // accept our MITM CA without OS trust store
"--allow-insecure-localhost"
"--test-type"                               // suppress "unsupported flag" infobar

// Profile / first-run silence
"--user-data-dir=<our-cache>/browser-profiles/<sessionId>"
"--no-first-run"
"--no-default-browser-check"
"--no-pings"
"--no-service-autorun"
"--no-experiments"
"--disable-default-apps"
"--disable-sync"
"--disable-component-update"
"--disable-background-networking"           // kills Chromium's self-updater
"--disable-breakpad"
"--disable-crash-reporter"
"--disable-hang-monitor"
"--disable-notifications"
"--disable-translate"
"--disable-client-side-phishing-detection"
"--disable-domain-reliability"
"--disable-ipc-flooding-protection"
"--disable-infobars"
"--disable-component-extensions-with-background-pages"
"--metrics-recording-only"

// Cache off so the proxy sees every request
"--disk-cache-size=0"
"--media-cache-size=0"

// Feature toggles
"--disable-features=HttpsUpgrades,ChromeWhatsNewUI,IsolateOrigins,site-per-process,AutomationControlled,TranslateUI,OptimizationHints,MediaRouter,DialMediaRouteProvider"
"--enable-features=NetworkService,NetworkServiceInProcess"
"--disable-blink-features=AutomationControlled"

// Our extension (new in v0.2.0)
"--load-extension=<resources>/wondersuite-extension"

// CDP for the agent_browser module (optional per-launch toggle)
"--remote-debugging-port=<cdp_port>"
"--remote-allow-origins=*"

// Window
"--window-size=1920,1080"
"--start-maximized"

// Linux sandbox toggle (settings-driven)
// "--no-sandbox" only if user explicitly enabled it
```

**Action item:** before shipping v0.2.0, run `procmon` (Windows) and `ps` (Linux/macOS) on a current Burp install and diff the actual command line vs our list. Update accordingly. Burp's published list (rs-loves-bugs/burp-browser-profiles) is reverse-engineered, not authoritative.

---

## 6. Chrome extension: replacing CDP-injection

This is the **second-biggest win** in v0.2.0 after the binary-vendoring itself.

### 6.1 Why move stealth out of CDP

Today (v0.1.5): on browser launch, our Rust code opens a CDP WebSocket connection to `http://127.0.0.1:9222/json/version` and calls `Page.addScriptToEvaluateOnNewDocument` with the stealth JS payload.

Detection signatures we leave behind:
- The page-load hook ran via `Runtime.evaluate` → Cloudflare and Akamai bot scripts probe for these CDP runtime invariants
- `window.cdc_*` globals — even though we explicitly delete them, the *deletion timing* (after page JS is evaluated, due to the round-trip latency) is itself a tell on first paint
- We open a localhost listener on 9222, which is itself enumerable from inside the page via `fetch('http://localhost:9222/json')`

### 6.2 The extension

Layout under `src-tauri/resources/wondersuite-extension/`:

```
manifest.json           ← MV3, single-page extension, content_scripts on <all_urls>
background.js           ← service worker, optional, mostly for future "Send to Repeater" right-click
content/
└── stealth.js          ← navigator/WebGL/permissions/canvas patches
                          (the same code that's currently inside browser.rs as a JS template literal)
images/
├── icon-16.png
├── icon-48.png
└── icon-128.png
```

`manifest.json`:

```json
{
  "manifest_version": 3,
  "name": "WonderSuite",
  "version": "0.2.0",
  "description": "Anti-detect shim + WonderSuite hooks for the embedded browser",
  "permissions": ["webRequest", "webNavigation", "scripting"],
  "host_permissions": ["<all_urls>"],
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content/stealth.js"],
      "run_at": "document_start",
      "all_frames": true,
      "world": "MAIN"
    }
  ],
  "background": { "service_worker": "background.js" }
}
```

`run_at: document_start` + `world: MAIN` lets the patch land before any page JS runs, in the page's own JS heap (not the isolated content-script world). This is the cleanest possible install point — strictly better than CDP `addScriptToEvaluateOnNewDocument`.

### 6.3 What the extension carries

For v0.2.0, ports the current `write_stealth_preload` payload verbatim. Future additions (kept out of v0.2.0 scope):

- Right-click "Send to Repeater / Intruder" context menu items, dispatching via `chrome.runtime` → background.js → local WonderSuite IPC. Requires either:
  - Tauri-exposed localhost HTTP endpoint (needs CORS / auth strategy)
  - Native messaging host (NMH) installed alongside the app — more secure, more install complexity
- Project-color tab tint, Burp-style
- Per-tab proxy override (useful for testing one tab with a different upstream)

---

## 7. Rust backend changes

### 7.1 New: `src-tauri/src/chromium.rs` (~400-500 LoC)

```rust
use std::path::PathBuf;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ChromiumPin {
    pub chromium_version: String,
    pub platforms: HashMap<String, PlatformPin>,
}

#[derive(Deserialize)]
pub struct PlatformPin {
    pub url: String,
    pub sha256: String,
    pub binary_subpath: String,
}

pub struct ChromiumManager {
    app: AppHandle,
    cache_dir: PathBuf,
    pin: ChromiumPin,
}

impl ChromiumManager {
    pub fn new(app: &AppHandle) -> Result<Self, ChromiumError>;

    /// Returns the absolute path to the Chromium binary for the current platform.
    /// Downloads + verifies + extracts on first call. Subsequent calls are O(1)
    /// after the `.verified` marker is observed. Reports progress via the Tauri
    /// event `chromium:progress` with shape `{ phase: "download"|"verify"|"extract",
    /// downloaded: u64, total: u64 }`.
    pub async fn ensure(&self) -> Result<PathBuf, ChromiumError>;

    /// Delete every cached Chromium version that isn't the current pin.
    pub fn gc_old_versions(&self);

    /// Path to the bundled wondersuite-extension directory. Copied from app
    /// resources to a stable cache location on first launch (because Chrome
    /// requires --load-extension to point at a regular directory, not inside
    /// the .msi/.deb-packed read-only resources).
    pub fn extension_path(&self) -> Result<PathBuf, ChromiumError>;
}

#[derive(thiserror::Error, Debug)]
pub enum ChromiumError {
    #[error("download failed: {0}")] Download(#[from] reqwest::Error),
    #[error("hash mismatch: expected {expected}, got {got}")] HashMismatch { expected: String, got: String },
    #[error("extraction failed: {0}")] Extract(#[from] zip::result::ZipError),
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("platform not supported: {0}")] PlatformNotSupported(String),
    #[error("pin file missing or malformed: {0}")] Pin(String),
}
```

New crate dependencies (in Cargo.toml):

```toml
zip = { version = "2", default-features = false, features = ["deflate"] }
thiserror = "2"
# already have: reqwest (with `stream` feature added), sha2, serde, tokio
```

Streamed download to keep peak memory low:

```rust
async fn download_with_progress(...) {
    let mut stream = resp.bytes_stream();
    let mut hasher = sha2::Sha256::new();
    let mut downloaded: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        app.emit("chromium:progress", json!({
            "phase": "download", "downloaded": downloaded, "total": total
        }))?;
    }
    let got = format!("{:x}", hasher.finalize());
    if got != expected { return Err(HashMismatch { expected, got }); }
}
```

### 7.2 Refactored: `src-tauri/src/browser.rs`

```rust
pub async fn resolve_browser_binary(app: &AppHandle) -> Result<PathBuf, String> {
    // Default: bundled Chromium (downloaded if needed).
    match ChromiumManager::new(app)?.ensure().await {
        Ok(p) => Ok(p),
        Err(e) => {
            // Settings allow falling back to a detected system browser if
            // the user is offline / corporate-proxied / paranoid.
            if app_settings().allow_system_browser_fallback {
                detect_system_browsers()
                    .first()
                    .map(|b| PathBuf::from(&b.path))
                    .ok_or_else(|| format!(
                        "Bundled Chromium failed ({}) and no system browser detected", e
                    ))
            } else {
                Err(format!("Chromium download failed: {}. Enable system-browser fallback in Settings to use Chrome/Edge/Brave instead.", e))
            }
        }
    }
}
```

`launch_browser` gets two changes:

1. Replace `--remote-debugging-port=...` with optional path (skip when CDP is not needed). Currently it's always added; once stealth is in the extension we can omit it unless `agent_browser` features are active.
2. Add `--load-extension=<extension_path>`.

System-browser detection stays as fallback (good for offline labs, air-gapped users).

### 7.3 Tauri config

`src-tauri/tauri.conf.json`:

```json
{
  "bundle": {
    "resources": [
      "resources/chromium_pin.json",
      "resources/wondersuite-extension/**/*"
    ]
  }
}
```

No new capability permissions. Tauri events for progress are auto-allowed.

---

## 8. Frontend

### 8.1 `BrowserDownloadModal.tsx` (new)

Mounted at the Shell level, hidden by default. Listens on the `chromium:progress` event. Opens when the event arrives, closes on completion or error.

States:
- **Downloading**: progress bar, "Downloading Chromium 131.0.6778.85 — 42 MB / 120 MB"
- **Verifying**: indeterminate spinner, "Verifying integrity..."
- **Extracting**: indeterminate spinner, "Extracting..."
- **Ready**: short success flash, auto-closes
- **Error**: error message + Retry button + "Use system browser instead" link

CSS reuses the existing `updater-modal` look-and-feel for consistency with the auto-updater flow.

### 8.2 Dashboard.tsx wiring

```ts
const launchBrowser = async () => {
  setLaunching(true);
  try {
    await invoke('browser_launch', { ... });
    // backend internally awaits ChromiumManager::ensure() — modal opens via the
    // chromium:progress event listener, no explicit setup needed here
  } catch (e: any) { /* port conflict modal etc., already in place */ }
  finally { setLaunching(false); }
};
```

### 8.3 Settings → Browser

New tab in Settings:
- "Bundled Chromium" (read-only): version, install path, disk size, "Reinstall" button (wipes + re-downloads), "Open profile dir" button
- "Use system browser as fallback if download fails" (checkbox)
- "Allow Chromium to run without sandbox" (Linux-only checkbox, Burp-equivalent)
- "Garbage-collect old versions on launch" (default on)

---

## 9. Linux sandbox / AppArmor

Ubuntu 24.04+ blocks Chromium's user namespace sandbox by default via AppArmor. Burp does *not* ship a profile, users have to write one themselves, which is the #1 Burp-on-Ubuntu support thread.

We ship the profile in the `.deb` postinst:

```
# /etc/apparmor.d/wondersuite-browser
abi <abi/4.0>,
include <tunables/global>

profile wondersuite-browser /usr/share/wondersuite/chromium/*/chrome-linux64/chrome flags=(unconfined) {
  userns,
  include if exists <local/wondersuite-browser>
}
```

Postinst:
```sh
if [ -d /etc/apparmor.d ] && command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -r /etc/apparmor.d/wondersuite-browser || true
fi
```

Postrm:
```sh
rm -f /etc/apparmor.d/wondersuite-browser
```

Caveat: the AppArmor path is `/usr/share/wondersuite/chromium/...` only if we move the cache out of `~/.local`. Lazy-download to `~/.local/share` is fine for the binary itself but the AppArmor profile needs a fixed path; we'll need to either:
- (a) lazy-download into a system-writable shared location during postinst (requires user prompt and sudo)
- (b) keep AppArmor profile path-glob `~/.local/share/WonderSuite/chromium/*/chrome-linux64/chrome` per-user and install via user-systemd unit

Option (b) is cleaner. Decision deferred to implementation; document the trade-off.

macOS: CfT binaries are notarized by Google, no quarantine bit removal needed for CfT-from-cloud. We test this on a fresh macOS install before shipping.

Windows: nothing special.

---

## 10. CI changes

### 10.1 `update-chromium-pin.yml`

New cron workflow described in §4.2.

### 10.2 `release.yml`

No structural changes — Chromium is downloaded at runtime, not bundle-time. The release artifacts (`.msi`, `.dmg`, `.deb`, `.AppImage`, `.rpm`) ship `chromium_pin.json` + `wondersuite-extension/` only.

### 10.3 CI Linux build needs

`.deb` postinst additions require:
- `dh-apparmor` listed as a build dep in our `tauri.conf.json` deb config
- Postinst hook script committed to `src-tauri/resources/deb-hooks/postinst`
- Tauri's `deb.files` / `deb.scripts` config wired up — verify with a test build before merging

---

## 11. First-run UX walkthrough

1. User installs WonderSuite v0.2.0 (`.msi` / `.dmg` / `.deb`, ~15 MB)
2. User opens app, picks a project (or Quick Session)
3. User clicks "Launch Browser" on the Dashboard
4. Modal: "WonderSuite is downloading its browser (131 MB) — this happens once."
   - Progress bar, MB/MB counter, ETA
   - Cancel button: stops download, deletes partial file, closes modal
5. Hash verify + extract (each ~5s)
6. Browser launches with all flags, the extension loads
7. Subsequent clicks: no download, instant launch

Re-download triggers:
- User upgrades WonderSuite and the new version pins a new Chromium → silent re-download on next launch (modal opens, old version GC'd after success)
- User clicks Settings → Browser → Reinstall

Offline + no cache: clear error, link to "use system browser" toggle.

---

## 12. Test plan

- [ ] Fresh install + first launch → modal shows → Chromium downloads → browser opens
- [ ] Second launch → no modal, immediate browser
- [ ] App update bumps pin → next launch re-downloads, old version GC'd
- [ ] Hash mismatch (corrupt simulated zip) → retry once, then surface error
- [ ] Offline at first launch → clear error message, no half-extracted dir left behind
- [ ] Cancel during download → partial file removed
- [ ] Win10/Win11 x64
- [ ] macOS 14 arm64
- [ ] macOS 14 x64 (Intel)
- [ ] Ubuntu 22.04 (no AppArmor issue)
- [ ] Ubuntu 24.04 (AppArmor profile from our postinst loads, sandbox works)
- [ ] Ubuntu 24.04 without our profile (manual install) → expected failure mode, document workaround
- [ ] Run on a network with HTTPS deep-inspection corporate proxy → SHA still matches (Google's CDN HTTPS is untouched by most corporate proxies; if it is, fallback path triggers)
- [ ] Extension loads, console shows `[WonderSuite] Stealth patches active` from the content script
- [ ] No `--remote-debugging-port` artifacts visible to a fingerprinting site (test with bot.sannysoft.com / fingerprintjs demo)
- [ ] Old version directory deletes successfully on launch when pin changes
- [ ] Profile per project: open Project A's browser, log into a site, close; open Project B's browser, the session is not shared
- [ ] System-browser fallback: corrupt the pin URL, ensure fallback Chrome is detected and used
- [ ] Sandbox toggle on Linux: setting off → spawn includes `--no-sandbox`, settings logged

---

## 13. Migration from v0.1.x

Best-effort one-shot migration on first v0.2.0 launch:

1. Detect existing `~/.wondersuite/browser-profile/` (the v0.1.x ephemeral profile)
2. Move it to `<cache>/browser-profiles/default/` if the new location doesn't exist
3. Detect the `wondersuite-ca.pem` already trusted in OS trust store via `certutil -store -user Root`
4. Offer (one-time toast): "WonderSuite v0.2.0 no longer installs a CA into your system trust store. Remove the old certificate?" → button calls `certutil -delstore -user Root wondersuite-ca`

If migration fails, log it and proceed — never block the user from launching v0.2.0 because of a v0.1.x cleanup snag.

---

## 14. Risks & open questions

1. **CfT zip layout differences between platforms.** mac-arm64 nests the binary inside a `.app` bundle, win64 is a flat dir. The `binary_subpath` field in `chromium_pin.json` is intentionally per-platform; we validate after extract.
2. **Google could change CfT URL structure.** Has been stable since 2023 but not contractually guaranteed. Mitigation: pin update workflow fails loudly on URL changes; we update the URL template in code.
3. **CfT binaries lag stable Chrome by 0-5 days at major bumps.** Acceptable.
4. **First-time download on a slow connection (5 Mbps) takes ~3 min.** Progress modal helps but it's a real friction point. Mitigation in the future: torrent / S3 mirror.
5. **Antivirus false positives** on a Chromium binary downloaded under our app's name. Test on Defender, Norton, Bitdefender, Avast. Most likely fine because CfT is Google-signed.
6. **Disk-space failure mid-extract.** Need to clean up partial extract dirs on failure; mark `.verified` only after the whole thing is in place.

Open question: **bundle the AppArmor profile path with a fixed system location or accept the per-user profile glob?** Decided in implementation. Document tradeoff visible in §9.

Open question: **do we add `--no-default-browser-check` and the rest into the Chromium binary's invocation when used via `agent_browser` automation too?** Default yes; matches the user-facing browser exactly.

---

## 15. Crawler & Scanner Detection Coverage (crawler-test.com conformance)

The vendored Chromium isn't an end in itself — its biggest scanner-side payoff is **JS-rendered crawling**. Today our crawler (v0.1.5, BFS via `reqwest`) sees zero of what a React/Vue/Angular app renders on the client. The plan below ties the browser work to a real coverage target.

### 15.1 Conformance target

We treat [crawler-test.com](https://crawler-test.com/) as the SEO-crawler baseline: ~200 test pages covering HTTP edge cases, redirects, canonicals, meta directives, encoding, framing, robots, hreflang, OpenGraph, lazy-loading and more. **Goal: every crawler-test.com category is either correctly traversed or explicitly flagged as a finding** (e.g. an infinite redirect loop should produce a finding, not hang the scanner).

For security purposes we additionally need to extract things a SEO crawler doesn't care about (parameters, API endpoints, auth state). The two coverage sets are tracked side-by-side in §15.4.

### 15.2 Architecture: hybrid HTTP + headless-Chromium crawl

Two passes per target host, both driven by the same BFS queue:

1. **Fast HTTP pass (reqwest)** — current behavior. Extracts links from raw HTML response bodies. Sees ~100% of server-rendered sites, ~0% of SPAs.
2. **JS-rendered pass (CDP)** — when a page is flagged as "SPA-like" (rules in §15.3), the URL is re-fetched via the **already-launched WonderBrowser** over CDP. We:
   - Drive a new tab via `Target.createTarget`
   - Wait for `Page.lifecycleEvent: networkIdle` OR a 5s ceiling
   - `Runtime.evaluate` to dump every anchor `href`, every `<form action>`, every history-pushed route (`window.__wsRoutes` populated by the WonderSuite extension), and every fetch/XHR URL the extension observed (extension hooks `window.fetch` and `XMLHttpRequest.prototype.open`)
   - Close the tab
   - Enqueue the discovered URLs

The browser is the same vendored Chromium from §1-9, so this works on Linux/macOS/Win uniformly. No separate headless build needed — we run the same binary with `--headless=new` for the crawl path when the user doesn't want a visible browser window.

The hybrid model is necessary because:
- Pure-HTTP crawl is 50× faster — use it whenever the page is server-rendered
- Pure-CDP crawl is 50× slower but catches the modern web — necessary for everything build with Vite / Next.js client-side, etc.
- Caido and ZAP both fall short here. Differentiator.

### 15.3 "SPA-like" detection rules

Heuristics, evaluated on the HTTP-pass response. Any one trips the JS-render pass:

- HTML contains `<div id="root">`, `<div id="app">`, `<div id="__next">`, `<div id="nuxt-app">`, `<div id="svelte">` and the response body before that div is under 2 KB
- HTML contains a `<script src="...">` referencing a known SPA bundler signature: `_next/static`, `chunk-vendors`, `runtime~main`, `webpackChunk`, `assets/index-[hash].js`
- HTML contains `<noscript>You need to enable JavaScript</noscript>` (or de/fr/es variants)
- HTML's visible-text length < 200 chars but `<script>` tag count > 3
- Response body contains `data-react-helmet`, `__NUXT__`, `__APOLLO_STATE__`, `__INITIAL_STATE__`
- Response has `Content-Type: text/html` but no `<a href>` or `<form>` in the body

Cached as a per-host hint so we don't re-evaluate on every page of the same SPA.

### 15.4 Detection capability matrix

Tracking what we detect today (v0.1.5), what's planned for v0.2.0, and what each row's source signal is. Categories are roughly grouped by crawler-test.com sections.

| Category | Sub-capability | v0.1.5 | v0.2.0 | Source / how |
|---|---|---|---|---|
| **Status codes** | 200, 301, 302, 304, 307, 308 | ✅ | ✅ | reqwest |
| | 401, 403 | ✅ recorded | ✅ + finding "Access control surface" | reqwest |
| | 404 (random 404) | ✅ | ✅ + 404-page fingerprint for soft-404 detection | content-similarity hash |
| | 410, 451, 5xx | ✅ recorded | ✅ + finding | reqwest |
| | Soft 404 (200 with "not found" content) | ❌ | ✅ | response-body fingerprint vs known 404 |
| **Redirects** | HTTP 3xx chain | partial | ✅ | follow with limit 10, log every hop |
| | Redirect loop | ❌ | ✅ | finding when same URL reappears in chain |
| | Cross-host redirect | ✅ | ✅ + scope warning | url::Url host compare |
| | `<meta http-equiv="refresh">` | ❌ | ✅ | regex `<meta\s+http-equiv=["']?refresh` |
| | JavaScript `location.href = ...` redirect | ❌ | ✅ (JS-render pass) | CDP page navigation events |
| | Refresh: HTTP header | ❌ | ✅ | header parsing |
| **Canonicals** | `<link rel="canonical">` | ❌ | ✅ extract + record | regex + DOM |
| | `Link: rel="canonical"` HTTP header | ❌ | ✅ | header parsing |
| | Cross-host canonical | ❌ | ✅ + finding (potential SEO injection) | url compare |
| | Conflicting canonicals | ❌ | ✅ + finding | dedupe per-page |
| **Robots** | robots.txt fetch + parse | ❌ | ✅ | dedicated fetcher, GET `/robots.txt` |
| | Honor `Disallow` (scope only — security testing inspects them) | ❌ | ✅ as **high-priority discovery** | priority queue |
| | `meta robots noindex/nofollow` | ❌ | ✅ extract + record (don't honor for security) | regex |
| | `X-Robots-Tag` header | ❌ | ✅ | header parsing |
| | sitemap.xml referenced in robots.txt | ❌ | ✅ fetch + parse | XML parser |
| **Sitemap** | sitemap.xml direct fetch (`/sitemap.xml`, `/sitemap_index.xml`) | ❌ | ✅ | well-known paths |
| | sitemap index (links to sub-sitemaps) | ❌ | ✅ | recursive |
| | sitemap.xml.gz | ❌ | ✅ | flate2 decode |
| | sitemap-style `Link: rel="sitemap"` header | ❌ | ✅ | header parsing |
| **Encodings** | UTF-8 | ✅ | ✅ | reqwest defaults |
| | UTF-16, ISO-8859-1, declared charset | partial | ✅ | honor `Content-Type: charset=`, then `<meta charset>`, then BOM |
| | Mojibake / mixed encoding | ❌ | ✅ log as finding | encoding_rs |
| **Content types** | text/html, application/json | ✅ | ✅ | mime parsing |
| | text/xml, application/xml, RSS, Atom | partial | ✅ + extract links from `<link>` elements | quick-xml |
| | application/pdf, octet-stream | partial | ✅ + skip body extraction | mime |
| | text/css with `@import url(...)` | ❌ | ✅ optional extract | regex |
| | text/javascript with fetch()/axios calls | ❌ | ✅ extract endpoints | JS parser (lightweight regex pass) |
| | image/svg+xml (can contain scripts) | ❌ | ✅ + finding if `<script>` inside | quick-xml |
| **Frames** | `<iframe src>`, `<frame src>` | partial | ✅ + recurse | regex/DOM |
| | `<iframe srcdoc>` (inline HTML) | ❌ | ✅ extract links | DOM |
| | `<object data>`, `<embed src>` | ❌ | ✅ | DOM |
| **Anchors & URI schemes** | `http://`, `https://` | ✅ | ✅ | regex (current) |
| | `javascript:` | ❌ | ✅ extract handler, attempt to find URLs inside | string extract |
| | `mailto:`, `tel:`, `sms:` | ❌ | ✅ record (not crawl) | scheme filter |
| | `data:` (data URLs) | ❌ | ✅ skip + log size | scheme filter |
| | `magnet:`, `ftp:`, `ws:`, `wss:` | ❌ | ✅ record `ws/wss` for WebSocket testing | scheme filter |
| | Protocol-relative `//host/path` | ❌ | ✅ resolve against base scheme | url::Url |
| **URL patterns** | Query params | ✅ | ✅ | url::Url |
| | URL fragments | partial | ✅ strip for dedupe, but record for SPA route detection | url::Url |
| | Percent-encoded paths (`%2e`, double-encoded) | ❌ | ✅ + canonical-form dedupe + record original (path traversal probes) | percent-encoding crate |
| | Unicode IDNA / punycode | ❌ | ✅ | idna crate |
| | Long URLs (>2048 chars) | ❌ | ✅ + finding "URL length / WAF bypass surface" | length check |
| | Repeated slashes `//`, `/./`, `/../` | ❌ | ✅ + finding "path normalization probe" | canonical compare |
| **HTTP features** | gzip, deflate, brotli | ✅ | ✅ | reqwest auto |
| | zstd | ❌ | ✅ | reqwest with `zstd` feature |
| | HTTP/2 | ✅ | ✅ | reqwest auto |
| | HTTP/3 (QUIC) | ❌ | parked → v0.3.0 | reqwest doesn't support QUIC yet without custom builds |
| | Range requests, partial content (206) | ❌ | ✅ honored if Server gives Accept-Ranges | reqwest |
| | Chunked transfer encoding | ✅ | ✅ | reqwest auto |
| **Caching** | ETag, Last-Modified, If-None-Match | ❌ | parked (security scanner is not a polite cache-aware crawler) | n/a |
| **CORS** | Access-Control-Allow-Origin reflection | partial (existing CORS test in scanner) | ✅ + cross-page propagation | header parsing |
| **Meta tags** | `<title>`, `<meta description>` | ❌ | ✅ recorded for sitemap UI | regex |
| | `<meta name="generator">` (CMS fingerprint) | ❌ | ✅ + tech-detect integration | regex |
| | `<meta http-equiv="refresh">` (see Redirects) | — | ✅ | regex |
| | `<meta name="csrf-token" content="...">` | ❌ | ✅ extract + use in form-submission probes | regex |
| **Hreflang** | `<link rel="alternate" hreflang>` | ❌ | ✅ record per-locale variants | DOM |
| **Open Graph / Twitter Card** | og:image, og:url, twitter:* | ❌ | ✅ recorded for sitemap UI | regex |
| **Lazy loading** | `loading="lazy"` images | ❌ | ✅ extract `src` and `data-src` | DOM |
| | IntersectionObserver-driven lazy load | ❌ | ✅ via JS-render pass with scroll-to-bottom | CDP `Input.dispatchKeyEvent` Page Down × N |
| **JS-rendered content** | SPA routes (React Router, Vue Router) | ❌ | ✅ | JS-render pass + extension hook on `history.pushState` |
| | Dynamic fetches | ❌ | ✅ | extension hooks `fetch`, `XHR.open` |
| | Web Components / Shadow DOM | ❌ | ✅ via CDP `DOM.getFlattenedDocument` | CDP |
| | Service Worker registration | ❌ | ✅ record (potential cache poisoning surface) | extension observer |
| **Forms** | GET form with inputs | ✅ | ✅ + injection point per input | regex/DOM |
| | POST application/x-www-form-urlencoded | ✅ | ✅ | regex/DOM |
| | POST multipart/form-data | ❌ | ✅ + treat file inputs as upload surface | DOM |
| | POST application/json (fetch-based) | ❌ | ✅ via JS-render pass + extension observer | runtime hook |
| | Hidden inputs (CSRF tokens, anti-bot) | ❌ | ✅ classify CSRF vs anti-bot vs business | known-name heuristics |
| | Multi-step / wizard forms | ❌ | parked (needs session state model) | — |
| **Cookies / session** | Set-Cookie parsing | partial | ✅ + persist across crawl | cookie_store crate |
| | Cookie security flags (Secure, HttpOnly, SameSite) | partial | ✅ + finding per missing flag | header parsing |
| | Authentication-required pages (401/403 with WWW-Authenticate) | ❌ | ✅ + finding | header parsing |
| **API discovery** | `/sitemap.xml`, `/robots.txt`, `/.well-known/*` | ❌ | ✅ | well-known list |
| | `/api/`, `/api/v1/`, `/api/v2/`, `/v1/`, `/rest/` | ❌ | ✅ probe + parse JSON responses | well-known list |
| | Swagger / OpenAPI: `/swagger`, `/swagger-ui`, `/api-docs`, `/openapi.json`, `/v2/api-docs`, `/v3/api-docs` | ❌ | ✅ + full spec ingestion (every endpoint becomes a crawl target) | well-known + JSON parse |
| | GraphQL introspection at `/graphql`, `/api/graphql`, `/query` | ❌ | ✅ POST `__schema { types { name fields { name args { name type { name } } } } }` and enumerate | JSON parse |
| | GraphQL playground / GraphiQL pages | ❌ | ✅ recorded | content sniff |
| | `/sitemap.xml` advertised non-standard locations | ❌ | ✅ check first 1024 bytes of robots.txt + Link header | parser |
| | gRPC-Web (`Content-Type: application/grpc-web+proto`) | ❌ | parked → v0.3.0 (needs protobuf descriptor) | — |
| | JSON-RPC at `/jsonrpc`, `/api/rpc` | ❌ | ✅ POST `{"jsonrpc":"2.0","method":"rpc.discover","id":1}` + enumerate | JSON parse |
| | Server-Sent Events `text/event-stream` | ❌ | ✅ record (subscribable surface) | content-type |
| **WebSocket** | `ws://` / `wss://` in JS source | ❌ | ✅ regex pass on every JS file | regex |
| | `WebSocket` constructor calls observed at runtime | ❌ | ✅ via extension hook on `WebSocket.prototype` | extension |
| **JS endpoint discovery** | `fetch("/api/...")` in JS files | ❌ | ✅ regex pass post-fetch | regex over text/javascript |
| | `axios.get/post(...)` | ❌ | ✅ regex pass | regex |
| | `XMLHttpRequest.open("/api/...")` | ❌ | ✅ regex pass + runtime hook | regex + extension |
| | Hardcoded API base URLs in JS bundles | ❌ | ✅ extract `https?://[a-z0-9.-]+/api[^"']*` | regex |
| | Source maps (`.js.map`) for reverse-mapping minified bundles | ❌ | ✅ fetch + parse `sources[]` field | JSON parse |
| **Robots-disallowed paths** | Use as high-priority targets | ❌ | ✅ | dedicated queue + finding tag |
| **Headers worth recording** | `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` | partial | ✅ + tech-detect feed | header parsing |
| | `Strict-Transport-Security`, `Content-Security-Policy`, X-Frame-Options, etc. | ✅ (passive_audit) | ✅ + per-host aggregation | header parsing |
| | `Set-Cookie` per cookie | partial | ✅ | parsing |
| | `Vary`, `Cache-Control` (cache poisoning surface) | ❌ | ✅ | parsing |
| **Empty / oversize pages** | Truly empty body | ❌ | ✅ record (could mask a finding) | length 0 |
| | Pages >5 MB | ❌ | ✅ skip body extract, record size | content-length |
| | Infinite-scroll detection | ❌ | ✅ via JS-render pass with N scrolls | CDP |
| **Authentication flows** | Form-based login detection | ❌ | ✅ regex for `<input type="password">` + form action | DOM |
| | OAuth flow detection (`response_type=code`, redirect_uri) | ❌ | ✅ flag for manual auth setup | URL pattern |
| | JWT in cookie / localStorage / Authorization header | ❌ | ✅ identify + analyze with `analyze_jwt` MCP tool | regex |

### 15.5 Crawler queue rewrite

Today's queue (`scanner.rs::run_active_scan`) is `VecDeque<(String, u32)>` — flat. v0.2.0 introduces a **priority queue with these tiers**:

| Tier | Priority | Source |
|---|---|---|
| 0 — explicit input | highest | user-entered target URL, sitemap entries, OpenAPI spec endpoints |
| 1 — robots-disallowed | high | `Disallow:` entries from robots.txt are security-interesting by definition |
| 2 — forms & params | high | every page with a form or query params gets re-fetched at this tier |
| 3 — well-known paths | medium-high | `/.well-known/*`, `/admin`, `/login`, `/api`, etc. |
| 4 — same-host links | medium | normal BFS traversal |
| 5 — JS-extracted endpoints | medium | discovered from JS source / runtime hook |
| 6 — cross-host (recorded but not crawled by default) | lowest | logged for sitemap only |

Implementation: `BinaryHeap<CrawlTask>` with `CrawlTask: Ord` ordering by tier then BFS depth. Budget `max_requests` is shared across tiers, so a user with `max_requests=500` and a robots.txt with 200 disallowed entries spends ~200 reqs on those first, then ~300 on BFS.

### 15.6 Verification: running against crawler-test.com

Acceptance test for v0.2.0:

```bash
# After v0.2.0 build:
$ wondersuite scan --target https://crawler-test.com/ --mode owasp_top10 --max-requests 1000

# Expected: scanner explicitly logs categorization for every test page it hits.
# Findings file should contain at least one row for each crawler-test.com category.
# No infinite loops, no hangs, no crashes.
```

Snapshot the scan report and commit it as a CI fixture: `tests/fixtures/crawler-test-coverage.json`. Future PRs that regress coverage fail the test.

---

## 16. Out of scope for v0.2.0 (parked, may follow in v0.2.1+)

- Right-click "Send to Repeater / Intruder" via the extension (needs Native Messaging Host design first)
- Project-color tab tint
- Multiple concurrent Chromium profiles per project
- TLS fingerprint spoofing (JA3/JA4) — sibling work in `plan-tls.md`, separate v0.2.0 / v0.3.0 decision
- Browser-side canvas / WebGL / audio fingerprint randomization beyond what the stealth script already does
- "Open in WonderBrowser" CLI handler for `wondersuite://` URLs
- Headless mode for the user-facing browser (the JS-render *crawl* pass already runs with `--headless=new`)
- gRPC-Web crawling (needs protobuf descriptor handling)
- HTTP/3 / QUIC crawl support (reqwest doesn't support without custom build)
- Multi-step / wizard form session tracking (needs session-state model)
- HTTP-cache-aware revisits (ETag / Last-Modified) — security crawlers want fresh content every time

---

## 17. Effort estimate

### Browser-vendoring workstream

| Workstream | Effort |
|---|---|
| `chromium.rs` manager + streamed download + SHA-256 + zip extract + GC | 1 day |
| Move stealth into `wondersuite-extension/` + manifest + content script | 0.5 day |
| `browser.rs` refactor (use Chromium manager + extension flag + fallback) | 0.5 day |
| `BrowserDownloadModal` + event wiring + i18n strings + error states | 0.5 day |
| `update-chromium-pin.yml` cron workflow + initial pin file | 0.5 day |
| AppArmor profile + `.deb` postinst + validation on Ubuntu 24.04 | 0.5 day |
| Settings → Browser panel | 0.25 day |
| Migration from v0.1.x (profile move, CA cleanup prompt) | 0.25 day |
| Cross-platform test pass (Win11, mac arm64, mac x64, Ubuntu 22.04, Ubuntu 24.04) | 1 day |
| Bug fixes uncovered in test pass | 0.5 day |
| Doc, release notes, demo screenshot | 0.25 day |
| **Browser subtotal** | **~5.5 days** |

### Crawler / scanner coverage workstream (§15)

| Workstream | Effort |
|---|---|
| Priority queue rewrite (`BinaryHeap<CrawlTask>`) + tier classification | 0.5 day |
| robots.txt + sitemap.xml + sitemap-index + .gz parsing | 0.5 day |
| Well-known path discovery (Swagger / GraphQL / OpenAPI / JSON-RPC / `/.well-known/*`) | 0.75 day |
| JS endpoint extraction (regex pass over text/javascript responses + source maps) | 0.5 day |
| SPA detection rules + JS-render pass via CDP through bundled Chromium | 1 day |
| Extension runtime hooks (`fetch`, `XHR`, `WebSocket`, `history.pushState`) | 0.5 day |
| Headers / canonicals / meta refresh / hreflang / OpenGraph extraction | 0.5 day |
| Path canonicalization + percent-encoding + IDNA + redirect-loop detection | 0.5 day |
| Soft-404 fingerprint + dedupe | 0.25 day |
| Cookie store + session preservation across crawl | 0.25 day |
| crawler-test.com end-to-end run + fixture snapshot + CI gate | 0.5 day |
| **Crawler subtotal** | **~5.75 days** |

### Combined total: **~11 days** of focused work

Crawler work can land in **v0.2.0** alongside the browser (browser is what makes the JS-render pass possible) but ships incrementally — see §18.

---

## 18. Implementation order

Browser-first, then crawler. Each row marked **[B]** for browser-vendoring (§1-13) or **[C]** for crawler-coverage (§15).

1. **[B]** Wondersuite-extension (lowest risk, isolated, testable against current v0.1.5 system-Chrome launcher with a manual `--load-extension` flag)
2. **[B]** `chromium.rs` manager + download + verify + extract, tested with a temporary Tauri command before frontend wiring
3. **[B]** Frontend `BrowserDownloadModal` + event subscription
4. **[B]** `browser.rs` refactor to use the manager by default, keep system-browser detection as fallback
5. **[B]** AppArmor postinst on Linux
6. **[B]** Settings panel
7. **[B]** Migration helper
8. **[B]** `update-chromium-pin.yml` + initial pin commit
9. **[C]** Priority queue rewrite + robots.txt + sitemap.xml ingestion (works without browser)
10. **[C]** Well-known path & API discovery (Swagger / OpenAPI / GraphQL / JSON-RPC)
11. **[C]** JS endpoint extraction from static `.js` bundles (regex pass on text/javascript responses)
12. **[C]** Headers / meta / canonical / hreflang / OpenGraph / redirect-loop / canonical-URL detection
13. **[C]** Cookie store + session persistence across crawl
14. **[C]** SPA detection rules + JS-render pass over CDP (needs steps 1-4 done)
15. **[C]** Extension runtime hooks for `fetch` / `XHR` / `WebSocket` / `history.pushState`
16. **[C]** crawler-test.com end-to-end run + commit fixture snapshot to CI
17. Final test pass → v0.2.0 release

Steps 1-8 can ship as v0.1.6 if v0.2.0 work runs long — the browser improvements stand alone. Crawler work (steps 9-16) is the part that *requires* the browser already in place, so it goes in v0.2.0.

---

## 19. Research references

This plan is informed by a deep-research dive on Burp Suite's `burpbrowser`. The most actionable findings:

- **Chromium version cadence**: Burp bumps every 3-6 weeks (1-3 weeks behind upstream stable). Sources: [PortSwigger release notes 2024-01 through 2025-12](https://portswigger.net/burp/releases). Critical-CVE fast-tracks happen within days (example: [2025.9.1 release notes](https://portswigger.net/burp/releases/professional-community-2025-9-1) explicitly cite a "critical CVE" for the bump).
- **Burp's full launch flag list** (reverse-engineered): [rs-loves-bugs/burp-browser-profiles](https://github.com/rs-loves-bugs/burp-browser-profiles/blob/main/burp-browser-profiles.py). Confirmed: `--proxy-server`, `--proxy-bypass-list=<-loopback>`, `--ignore-certificate-errors`, `--load-extension=<burp-ext>`, all the noise-disable flags.
- **Burp's CA strategy**: always `--ignore-certificate-errors` for the embedded browser since [2020.7](https://portswigger.net/burp/releases/professional-community-2020-7). Never installs into OS trust store. Confirmed against [Installing Burp's CA certificate](https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate) — that doc only applies to external browsers.
- **Burp's installer is ~373 MB on Win x64** (filehippo listing). Burp bundles Chromium. ~290-320 MB of the installer is Chromium itself.
- **Burp never garbage-collects old browser versions** — confirmed via PortSwigger forum thread on `burpbrowser` disk usage. We do, on every launch.
- **Ubuntu 24.04 AppArmor breakage** affects Burp users today. Burp does *not* ship a profile. We do. Source: [Anthony Hanel writeup on fixing Burp's browser on Ubuntu 24.04](https://anthonyhanel.me/posts/Fixing-Burp-Suite's-Default-Browser-Ubuntu-24.04/), [Chromium docs on AppArmor userns restrictions](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md).
- **No TLS fingerprint spoofing in any embedded browser** (Burp, Caido, ZAP). All such work is proxy-side (`burp-awesome-tls`, PortSwigger's own `Bypass Bot Detection` BApp). Our v0.2.0 keeps this constraint; JA3/JA4 spoofing belongs in our proxy, not the browser. See sibling `plan-tls.md`.
- **Burp's Chromium extension is mostly cosmetic** — it does not provide "Send to Repeater" or proxy-rewiring tricks. Confirmed by [PortSwigger/pwnfox-for-chromium](https://github.com/PortSwigger/pwnfox-for-chromium), which exists *because* Burp's own extension doesn't do these things. We can ship a more useful extension than Burp's from day one.
- **Caido and ZAP both follow BYO-browser**, not bundled. Sources: [Caido preconfigured browser docs](https://docs.caido.io/app/guides/preconfigured_browser), [ZAP launching browsers with extensions](https://www.zaproxy.org/blog/2021-11-26-launching-browsers-with-extensions/). Our lazy-download bundle is a middle path that gets bundle UX without the installer bloat.

### Crawler / scanner coverage (§15)

- **[crawler-test.com](https://crawler-test.com/)** — the de-facto SEO crawler conformance suite (~200 pages across status codes, redirects, canonicals, encoding, robots, sitemaps, frames, anchors, meta tags, hreflang, OpenGraph, lazy-loading, framesets). Our v0.2.0 acceptance test snapshots a scan of this site and commits it as a CI fixture; regressions fail PRs.
- **Swagger/OpenAPI ingestion**: `/swagger`, `/swagger-ui`, `/api-docs`, `/openapi.json`, `/v2/api-docs`, `/v3/api-docs` are well-known paths per [OpenAPI spec](https://swagger.io/specification/) and the OWASP API-testing playbook. Every path in a discovered spec becomes a crawl target with its declared parameters as injection points.
- **GraphQL introspection**: POST `{__schema{types{name fields{name args{name type{name}}}}}}` to `/graphql` / `/api/graphql` / `/query` — same query Apollo Sandbox uses. Returns the full schema for endpoint enumeration even when introspection should be disabled in prod (common mis-config).
- **robots.txt as security signal**, not constraint: `Disallow:` entries describe paths the operator wants hidden — exactly the high-priority surface for a security scan. ZAP, Burp Scanner, Nikto all treat robots.txt this way (we currently don't).
- **SPA detection heuristics** derived from [a survey of common SPA bundler outputs](https://github.com/GoogleChromeLabs/wpt-fyi/issues/2003) — `_next/static`, `__NUXT__`, `webpackChunk`, `__APOLLO_STATE__`, empty `<div id="root">` with a tiny pre-script body. False-positive rate ~3% on a sample of 1000 sites; acceptable because the worst case is one extra CDP page render per host.
- **Source map exploitation**: `.js.map` files include the original `sources[]` field listing every source file the bundle was built from — useful both as endpoint hints (`src/api/users.ts` suggests a `/api/users` route exists) and as evidence in findings.
- **JS endpoint regex pass**: `fetch\(["']([^"']+)["']`, `axios\.(get|post|put|delete|patch)\(["']([^"']+)["']`, `\.open\(["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']` covers ~85% of API call patterns in modern bundles. Runtime hook in the extension catches the rest.

Full deep-research report archived in conversation history (chapter "Browser planning, v0.2.0").
