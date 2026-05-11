#!/usr/bin/env node
// Refresh src-tauri/resources/chromium_pin.json from the current
// Chrome-for-Testing Stable manifest. Downloads each platform zip,
// computes SHA-256, and writes the new pin file.
//
// Usage:
//   node scripts/refresh-chromium-pin.mjs           # only updates if newer
//   node scripts/refresh-chromium-pin.mjs --force   # always re-fetch hashes
//
// Total bandwidth: ~600 MB across all four platforms. Run from a fast network.
// Used both interactively and by .github/workflows/update-chromium-pin.yml.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PIN_PATH = path.join(__dirname, '..', 'src-tauri', 'resources', 'chromium_pin.json');
const MANIFEST_URI =
  'https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json';

const PLATFORMS = {
  win64: 'chrome-win64/chrome.exe',
  'mac-arm64': 'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
  'mac-x64': 'chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
  linux64: 'chrome-linux64/chrome',
};

const force = process.argv.includes('--force');

async function fetchManifest() {
  const r = await fetch(MANIFEST_URI);
  if (!r.ok) throw new Error(`manifest GET ${r.status}`);
  return await r.json();
}

async function sha256OfUrl(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`zip GET ${r.status} for ${url}`);
  const hasher = createHash('sha256');
  const total = Number(r.headers.get('content-length') || 0);
  let seen = 0;
  let lastPct = -1;
  for await (const chunk of Readable.fromWeb(r.body)) {
    hasher.update(chunk);
    seen += chunk.length;
    if (total > 0) {
      const pct = Math.floor((seen / total) * 100);
      if (pct !== lastPct && pct % 10 === 0) {
        process.stderr.write(`  ${pct}%`);
        lastPct = pct;
      }
    }
  }
  process.stderr.write('\n');
  return hasher.digest('hex');
}

async function main() {
  const existing = fs.existsSync(PIN_PATH) ? JSON.parse(fs.readFileSync(PIN_PATH, 'utf8')) : null;
  const manifest = await fetchManifest();
  const stable = manifest.channels.Stable;
  const newVersion = stable.version;

  if (!force && existing && existing.chromium_version === newVersion) {
    console.log(`Already pinned to ${newVersion}. Use --force to recompute hashes.`);
    process.exit(0);
  }

  const downloads = Object.fromEntries(stable.downloads.chrome.map((d) => [d.platform, d.url]));
  const out = {
    chromium_version: newVersion,
    manifest_uri: MANIFEST_URI,
    platforms: {},
  };

  for (const [key, binarySubpath] of Object.entries(PLATFORMS)) {
    const url = downloads[key];
    if (!url) {
      throw new Error(`platform ${key} not in manifest`);
    }
    console.log(`Hashing ${key} ...`);
    const sha = await sha256OfUrl(url);
    console.log(`  ${key}: ${sha}`);
    out.platforms[key] = { url, sha256: sha, binary_subpath: binarySubpath };
  }

  fs.writeFileSync(PIN_PATH, JSON.stringify(out, null, 2) + '\n');
  console.log(`\nWrote ${PIN_PATH} for Chromium ${newVersion}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
