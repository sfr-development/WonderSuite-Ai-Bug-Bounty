// WonderSuite minimal stealth — MAIN world, document_start.
//
// Design principle: vanilla Chromium 148 is NOT detected as a bot. Every
// spoof we add is itself a detection vector — wrong plugins, mismatched
// languages, patched permissions API, all of these show up as "this Chrome
// is doing something weird" in modern bot detectors.
//
// So we do as little as possible:
//
//   1. Delete navigator.webdriver if it's set (only happens when CDP is on,
//      which is off by default in user-launched sessions).
//   2. Purge legacy automation marker globals (webdriver-evaluate, cdc_*,
//      phantom, nightmare, selenium markers) — these are written by various
//      automation frameworks, never by real Chrome.
//
// That's it. Anything else (plugins, languages, WebGL, screen size,
// permissions API, Worker constructors) we leave NATIVE. The OS / browser
// values are coherent by construction — spoofing them introduces mismatch.
//
// Tested green against: bot.sannysoft.com (when CDP off), arh.antoinevastel
// .com/bots/areyouheadless, intoli.com headless test, fp-collect.

(() => {
  if (window.__wsStealthApplied) return;
  Object.defineProperty(window, '__wsStealthApplied', { value: true, configurable: false });

  // 1. Delete webdriver from Navigator.prototype so `'webdriver' in navigator`
  //    returns false, not just navigator.webdriver === undefined.
  try {
    const proto = Object.getPrototypeOf(navigator);
    if (proto && Object.getOwnPropertyDescriptor(proto, 'webdriver')) {
      delete proto.webdriver;
    }
  } catch (_) {}

  // 2. Purge automation-framework marker globals if any survived.
  try {
    const exact = [
      '__nightmare', '_phantom', '__phantomas',
      'callPhantom', 'callSelenium',
      '_selenium', '__selenium_evaluate', '__webdriver_evaluate',
      '__driver_evaluate', '__webdriver_unwrapped',
      '__fxdriver_evaluate', '__fxdriver_unwrapped',
      '__selenium_unwrapped', '__webdriver_script_fn',
      '__webdriver_script_func', '__webdriver_script_function',
    ];
    for (const k of exact) {
      try { delete window[k]; } catch (_) {}
    }
    for (const k of Object.keys(window)) {
      if (k.startsWith('cdc_') || k.startsWith('$cdc_') || k.startsWith('__webdriver')) {
        try { delete window[k]; } catch (_) {}
      }
    }
  } catch (_) {}

  // 3. Mark page so the crawler can verify our extension actually loaded.
  try {
    document.documentElement.setAttribute('data-wondersuite-stealth', '1');
  } catch (_) {}
})();
