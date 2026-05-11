// WonderSuite runtime endpoint discovery — runs in the MAIN world at
// document_start, wraps fetch / XMLHttpRequest / WebSocket / history.pushState
// so we can collect every URL the page actually talks to (including ones the
// HTML never references because they are constructed in JS at runtime).
//
// Observed URLs are stashed on `window.__wsRoutes` AND dispatched as
// CustomEvent("wondersuite:endpoint", { detail }) for the ISOLATED-world
// relay.js content script to forward to the background service worker.

(() => {
  if (window.__wsHooksApplied) return;
  Object.defineProperty(window, '__wsHooksApplied', { value: true, configurable: false });

  const routes = (window.__wsRoutes = window.__wsRoutes || []);
  const seen = new Set();
  const MAX = 500;

  function record(detail) {
    try {
      const key = `${detail.kind}|${detail.method || ''}|${detail.url}`;
      if (seen.has(key)) return;
      seen.add(key);
      if (routes.length >= MAX) routes.shift();
      routes.push(detail);
      window.dispatchEvent(new CustomEvent('wondersuite:endpoint', { detail }));
    } catch (_) {}
  }

  function abs(url) {
    try {
      return new URL(url, document.baseURI).toString();
    } catch (_) {
      return String(url);
    }
  }

  // ── fetch ──────────────────────────────────────────────────────────────
  try {
    const origFetch = window.fetch;
    if (typeof origFetch === 'function') {
      window.fetch = function (input, init) {
        try {
          let url, method;
          if (typeof input === 'string') {
            url = abs(input);
            method = (init && init.method) || 'GET';
          } else if (input instanceof Request) {
            url = abs(input.url);
            method = input.method || 'GET';
          } else if (input && input.url) {
            url = abs(input.url);
            method = (init && init.method) || 'GET';
          }
          if (url) {
            record({ kind: 'fetch', method: method.toUpperCase(), url, ts: Date.now() });
          }
        } catch (_) {}
        return origFetch.apply(this, arguments);
      };
    }
  } catch (_) {}

  // ── XMLHttpRequest ─────────────────────────────────────────────────────
  try {
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      try {
        record({ kind: 'xhr', method: String(method || 'GET').toUpperCase(), url: abs(url), ts: Date.now() });
      } catch (_) {}
      return origOpen.apply(this, arguments);
    };
  } catch (_) {}

  // ── WebSocket constructor ──────────────────────────────────────────────
  try {
    const OrigWS = window.WebSocket;
    if (OrigWS) {
      function WSProxy(url, protocols) {
        try {
          record({ kind: 'websocket', method: 'CONNECT', url: abs(url), protocols, ts: Date.now() });
        } catch (_) {}
        return protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);
      }
      WSProxy.prototype = OrigWS.prototype;
      WSProxy.CONNECTING = OrigWS.CONNECTING;
      WSProxy.OPEN = OrigWS.OPEN;
      WSProxy.CLOSING = OrigWS.CLOSING;
      WSProxy.CLOSED = OrigWS.CLOSED;
      window.WebSocket = WSProxy;
    }
  } catch (_) {}

  // ── EventSource (SSE) ──────────────────────────────────────────────────
  try {
    const OrigES = window.EventSource;
    if (OrigES) {
      function ESProxy(url, init) {
        try {
          record({ kind: 'eventsource', method: 'GET', url: abs(url), ts: Date.now() });
        } catch (_) {}
        return new OrigES(url, init);
      }
      ESProxy.prototype = OrigES.prototype;
      window.EventSource = ESProxy;
    }
  } catch (_) {}

  // ── history.pushState / replaceState (SPA routing) ─────────────────────
  try {
    const origPush = history.pushState;
    const origReplace = history.replaceState;
    history.pushState = function (state, title, url) {
      try {
        if (url) record({ kind: 'pushstate', method: 'GET', url: abs(url), ts: Date.now() });
      } catch (_) {}
      return origPush.apply(this, arguments);
    };
    history.replaceState = function (state, title, url) {
      try {
        if (url) record({ kind: 'replacestate', method: 'GET', url: abs(url), ts: Date.now() });
      } catch (_) {}
      return origReplace.apply(this, arguments);
    };
  } catch (_) {}

  // ── popstate (back/forward) ────────────────────────────────────────────
  try {
    window.addEventListener('popstate', () => {
      record({ kind: 'popstate', method: 'GET', url: location.href, ts: Date.now() });
    });
  } catch (_) {}

  // Expose a small helper the crawler can call via Runtime.evaluate to drain
  // the in-memory list when it visits the tab.
  Object.defineProperty(window, '__wsDrainRoutes', {
    value: function () {
      const out = routes.slice();
      routes.length = 0;
      seen.clear();
      return out;
    },
    configurable: false,
  });

  document.documentElement.setAttribute('data-wondersuite-hooks', '1');
})();
