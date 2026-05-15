# Settings — Browser

The **Browser** tab configures **WonderBrowser** — WonderSuite's own bundled Chromium — and the browser-automation behaviour the AI agent uses.

## WonderBrowser

WonderSuite ships its own pinned Chromium build (Chrome for Testing), so testing is isolated from your system Chrome and the version stays reproducible. The binary is verified against a pinned SHA-256.

The **Bundled Chromium** panel shows:

- Install state (**Installed** / **Not yet downloaded**), version, and on-disk size.
- **Download now** — fetch the Chromium build (it's downloaded on first browser launch otherwise).
- **Open cache dir** — reveal the cache folder in your file manager.
- **Reinstall** — delete the cached Chromium so it re-downloads fresh on next launch.

## Browser options

### Prefer system browser
Use a detected Chrome / Edge / Brave instead of the bundled WonderBrowser. WonderSuite also falls back to a system browser automatically if the bundled download fails.

### Allow browser without sandbox
Passes `--no-sandbox` to Chromium. Only needed if you run WonderSuite as root on Linux, or on a hardened kernel without user namespaces. Off by default.

### Impersonate Chrome TLS (JA3/JA4 + HTTP/2)
When on, the proxy's upstream requests use a Chrome 137 JA3/JA4 + HTTP/2 fingerprint — this defeats bot-detection from Cloudflare, Akamai, DataDome, and PerimeterX. On by default; turning it off falls back to native TLS, which those services will likely block.

### Run MCP browser headless
Hides the browser window the AI agent drives. Off by default — keeping it visible lets you step in on captchas and 2FA prompts.

## Stealth profile

Controls how human-like the AI's clicks and keystrokes are when it drives the browser:

| Profile | Behaviour |
|---|---|
| **Fast** | Programmatic clicks/typing — fastest, but easy to detect. For your own lab targets only. |
| **Human** *(default)* | Humanised mouse trajectories (Bezier + jitter), per-character typing cadence, dwell time before actions. Passes fraud SDKs like FriendlyCaptcha, Cloudflare Bot Management, and Imperva. |
| **Paranoid** | Slowest, with occasional overshoot and maximum detection-evasion. Use on heavily-instrumented targets (e.g. Akamai Bot Manager). |

## Legacy CA cleanup

If an older WonderSuite version installed a root CA into your OS trust store, this tab detects it and offers a **Remove** button — the current bundled browser doesn't need it (it uses an isolated profile with `--ignore-certificate-errors`).
