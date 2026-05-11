// WonderSuite background service worker.
//
// Receives:
//   { type: 'endpoint', href, endpoint } from relay.js
//   { type: 'page',     href, title, ts } from relay.js
// Stores in an in-memory ring buffer accessible from chrome.runtime for the
// crawler / scanner to drain via a future Native Messaging Host channel.
//
// For v0.2.0 the buffer is service-worker-local; the crawler can fetch it by
// asking Chromium via CDP to evaluate `chrome.runtime.sendMessage({type:'drain'})`
// from any of our content scripts and forwarding the response.

const MAX_BUFFER = 2000;
let buffer = [];

function push(entry) {
  buffer.push(entry);
  if (buffer.length > MAX_BUFFER) buffer.splice(0, buffer.length - MAX_BUFFER);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== 'object') return;

  switch (msg.type) {
    case 'endpoint':
      push({
        type: 'endpoint',
        href: msg.href || '',
        tabId: sender.tab && sender.tab.id,
        frameId: sender.frameId,
        endpoint: msg.endpoint,
        ts: Date.now(),
      });
      break;
    case 'page':
      push({
        type: 'page',
        href: msg.href || '',
        title: msg.title || '',
        tabId: sender.tab && sender.tab.id,
        ts: msg.ts || Date.now(),
      });
      break;
    case 'drain':
      const out = buffer.slice();
      buffer = [];
      sendResponse({ entries: out });
      return true;
    case 'peek':
      sendResponse({ entries: buffer.slice(), size: buffer.length });
      return true;
    case 'clear':
      buffer = [];
      sendResponse({ ok: true });
      return true;
  }
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('[WonderSuite] background service worker installed');
});
