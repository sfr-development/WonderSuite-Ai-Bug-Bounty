// WonderSuite relay — runs in the ISOLATED content-script world, listens for
// `wondersuite:endpoint` CustomEvents dispatched by hooks.js in the MAIN world,
// and forwards them to the extension service worker via chrome.runtime.sendMessage.
//
// Two worlds because: MAIN can patch page globals (needed for fetch/XHR hooks)
// but cannot access chrome.runtime; ISOLATED can access chrome.runtime but
// cannot patch page globals. The bridge between them is window CustomEvents.

(() => {
  if (window.__wsRelayApplied) return;
  Object.defineProperty(window, '__wsRelayApplied', { value: true, configurable: false });

  function send(detail) {
    try {
      chrome.runtime.sendMessage({
        type: 'endpoint',
        href: location.href,
        endpoint: detail,
      });
    } catch (_) {
      // service worker not ready or extension disabled — swallow
    }
  }

  window.addEventListener('wondersuite:endpoint', (e) => {
    if (e && e.detail) send(e.detail);
  });

  // On first paint, send a "page loaded" beacon so the background SW knows the
  // tab is alive and the crawler can probe it via tabs.executeScript later.
  function announce() {
    try {
      chrome.runtime.sendMessage({
        type: 'page',
        href: location.href,
        title: document.title || '',
        ts: Date.now(),
      });
    } catch (_) {}
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', announce, { once: true });
  } else {
    announce();
  }
})();
