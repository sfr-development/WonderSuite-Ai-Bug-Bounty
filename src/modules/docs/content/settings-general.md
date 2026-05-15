# Settings — General

Open Settings with <kbd>Ctrl+,</kbd>. The **General** tab covers system information, core application settings, and global scope.

## System Information

A read-only panel describing the environment WonderSuite is running in:

- **Architecture** — the CPU instruction set (x64 / arm64), badge-coded.
- **Operating System** — OS version.
- **CPU Cores** — available parallelism.
- **Data Directory** — where WonderSuite stores its configuration and project data on disk.
- **Detected Browsers** — every system browser found, with version and engine. These are the fallback browsers if [WonderBrowser](page:settings-browser) can't launch.

## General application settings

- **Max traffic entries** — the cap on stored HTTP messages before old ones are evicted.
- **Response size limit** — the largest response body (in MB) WonderSuite will store.
- **Follow redirects** — whether HTTP redirects are followed automatically.

## Global Target Scope

Scope defines what is *in bounds* for the assessment. Add URL patterns or hostnames — for example `*.example.com` — and they're recorded as your scope.

Once scope is set, modules like [Traffic](page:traffic) (and others with an in-scope filter) can hide everything outside it, keeping noise from third-party domains, CDNs, and analytics out of view. With no scope defined, everything is treated as in-scope.

Add a pattern with the input and **Add Scope**; remove one with its `×`.

> Setting scope early is the single best way to keep a busy engagement readable — define it before you start browsing the target.
