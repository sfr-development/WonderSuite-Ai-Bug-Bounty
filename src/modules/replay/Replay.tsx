import { useState, useCallback, useEffect } from 'react';
import { Send, Plus, X, ArrowRight, Loader2, Copy, Clock, Code, Settings2, ClipboardPaste } from 'lucide-react';
import { useReplayStore, useAppStore } from '../../stores';
import { invoke } from '@tauri-apps/api/core';
import './Replay.css';

/** Best-effort parser for pasted requests. Accepts:
 *   - Raw HTTP/1.1 (`POST /api HTTP/1.1\nHost: ex.com\n...`)
 *   - Absolute-URL request line (`GET https://ex.com/api HTTP/1.1\n...`)
 *   - cURL command (`curl 'https://...' -X POST -H ... -d '...'`)
 *   - JS fetch() snippet (`fetch('https://...', { method, headers, body })`)
 * Returns null if it can't figure the format out.
 */
function parsePastedRequest(text: string): null | {
  method: string;
  url: string;
  requestRaw: string;
  format: string;
} {
  const t = text.trim();
  if (!t) return null;

  // cURL ────────────────────────────────────────────────────────────────────
  if (/^curl\b/i.test(t)) {
    const flat = t.replace(/\\\s*\n/g, ' ').replace(/\s+/g, ' ');
    let method = 'GET';
    const m = flat.match(/-X\s+([A-Z]+)/i);
    if (m) method = m[1].toUpperCase();
    const urlMatch = flat.match(/curl\s+(?:-[A-Za-z]\s+\S+\s+)*['"]?(https?:\/\/[^\s'"]+)['"]?/);
    let url = urlMatch?.[1] || '';
    if (!url) {
      // fallback: first http(s) URL anywhere
      const any = flat.match(/https?:\/\/[^\s'"]+/);
      url = any?.[0] || '';
    }
    const headers: Record<string, string> = {};
    const hdrRe = /-H\s+['"]([^:'"]+):\s*([^'"]*)['"]/g;
    let mm;
    while ((mm = hdrRe.exec(flat)) !== null) headers[mm[1].trim()] = mm[2].trim();
    let body = '';
    const dataMatch = flat.match(/(?:--data(?:-raw|-binary|-urlencode)?|-d)\s+['"]([\s\S]+?)['"](?=\s|$)/);
    if (dataMatch) {
      body = dataMatch[1];
      if (!method || method === 'GET') method = 'POST';
    }
    if (!url) return null;
    try {
      const u = new URL(url);
      if (!headers['Host'] && !headers['host']) headers['Host'] = u.host;
    } catch { return null; }
    const path = (() => { try { return new URL(url).pathname + new URL(url).search; } catch { return '/'; } })();
    const raw =
      `${method} ${path} HTTP/1.1\r\n` +
      Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') +
      (body ? `\r\n\r\n${body}` : '\r\n\r\n');
    return { method, url, requestRaw: raw, format: 'curl' };
  }

  // fetch() JS ──────────────────────────────────────────────────────────────
  if (/^fetch\s*\(/i.test(t)) {
    const urlMatch = t.match(/fetch\s*\(\s*['"]([^'"]+)['"]/);
    const url = urlMatch?.[1] || '';
    if (!url) return null;
    let method = 'GET';
    const mm = t.match(/method\s*:\s*['"]([A-Z]+)['"]/i);
    if (mm) method = mm[1].toUpperCase();
    const headers: Record<string, string> = {};
    const headersBlock = t.match(/headers\s*:\s*\{([\s\S]*?)\}/);
    if (headersBlock) {
      const re = /['"]([^'"]+)['"]\s*:\s*['"]([^'"]*)['"]/g;
      let h;
      while ((h = re.exec(headersBlock[1])) !== null) headers[h[1]] = h[2];
    }
    let body = '';
    const bodyMatch = t.match(/body\s*:\s*['"]([^'"]*)['"]/) ||
                      t.match(/body\s*:\s*JSON\.stringify\s*\(\s*([\s\S]+?)\s*\)/);
    if (bodyMatch) {
      body = bodyMatch[1];
      if (method === 'GET') method = 'POST';
    }
    try {
      const u = new URL(url);
      if (!headers['Host'] && !headers['host']) headers['Host'] = u.host;
      const path = u.pathname + u.search;
      const raw =
        `${method} ${path} HTTP/1.1\r\n` +
        Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') +
        (body ? `\r\n\r\n${body}` : '\r\n\r\n');
      return { method, url, requestRaw: raw, format: 'fetch' };
    } catch { return null; }
  }

  // Raw HTTP ────────────────────────────────────────────────────────────────
  const lines = t.split(/\r?\n/);
  const reqLine = lines[0] || '';
  const reqLineMatch = reqLine.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/\d/i);
  if (!reqLineMatch) return null;
  const method = reqLineMatch[1].toUpperCase();
  const target = reqLineMatch[2];
  const headers: Record<string, string> = {};
  let bodyStart = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === '') { bodyStart = i + 1; break; }
    const c = lines[i].indexOf(':');
    if (c > 0) headers[lines[i].slice(0, c).trim()] = lines[i].slice(c + 1).trim();
  }
  // body is preserved inside requestRaw — we don't need to surface it separately
  void bodyStart;

  // Reconstruct absolute URL: either target is absolute, or Host header + path
  let url = '';
  if (/^https?:\/\//i.test(target)) {
    url = target;
  } else {
    const host = headers['Host'] || headers['host'];
    if (!host) return null;
    // Best guess on scheme: HTTPS if explicit `:443`/known, else https for any
    // host without port (most public services), http only if explicit `:80`.
    const scheme = /(:80)$/.test(host) ? 'http' : 'https';
    url = `${scheme}://${host}${target.startsWith('/') ? target : '/' + target}`;
  }
  return { method, url, requestRaw: t.replace(/\r?\n/g, '\r\n'), format: 'raw_http' };
}

function statusClass(code: number | null) {
  if (!code) return '';
  if (code < 300) return 's2xx';
  if (code < 400) return 's3xx';
  if (code < 500) return 's4xx';
  return 's5xx';
}

function toHex(text: string): string {
  const lines: string[] = [];
  const bytes = new TextEncoder().encode(text);
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(chunk).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
    lines.push(`${i.toString(16).padStart(8, '0')}  ${hex.padEnd(48)}  ${ascii}`);
  }
  return lines.join('\n');
}

interface HistoryEntry {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  status: number;
  time_ms: number;
  size: number;
  requestRaw: string;
  responseRaw: string;
}

export function Replay() {
  const { tabs, activeTabId, addTab, removeTab, setActiveTab, updateTab } = useReplayStore();
  const tab = tabs.find((t) => t.id === activeTabId);
  const [reqView, setReqView] = useState<'raw' | 'headers' | 'hex'>('raw');
  const [respView, setRespView] = useState<'raw' | 'pretty' | 'headers' | 'hex' | 'rendered'>('raw');
  const [history, setHistory] = useState<Record<string, HistoryEntry[]>>({});
  const [showHistory, setShowHistory] = useState(false);
  const [followRedirects, setFollowRedirects] = useState(true);
  const [autoContentLength, setAutoContentLength] = useState(true);
  const [showSettings, setShowSettings] = useState(false);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [showImport, setShowImport] = useState(false);
  const [importText, setImportText] = useState('');
  const [importError, setImportError] = useState<string | null>(null);

  const handleImport = () => {
    setImportError(null);
    const parsed = parsePastedRequest(importText);
    if (!parsed) {
      setImportError("Couldn't recognise format. Paste a raw HTTP request, cURL command, or fetch() snippet.");
      return;
    }
    // Reuse the active tab if it's blank, else open a new one.
    let host = 'imported';
    try { host = new URL(parsed.url).hostname; } catch {}
    const target = tab && !tab.url && !tab.requestRaw.trim() ? tab.id : `tab-${Date.now()}`;
    if (target === tab?.id) {
      updateTab(target, {
        method: parsed.method, url: parsed.url,
        requestRaw: parsed.requestRaw, responseRaw: '',
        statusCode: null, responseTimeMs: null, responseSize: null,
        name: host,
      });
    } else {
      addTab({
        id: target, name: host,
        method: parsed.method, url: parsed.url,
        requestRaw: parsed.requestRaw, responseRaw: '',
        statusCode: null, responseTimeMs: null, responseSize: null,
        isLoading: false,
      });
    }
    addToast({ title: `Imported (${parsed.format})`, message: `${parsed.method} ${parsed.url}`, type: 'success' });
    setShowImport(false);
    setImportText('');
  };


  const { pendingSendTo, clearSendTo, addToast } = useAppStore();
  useEffect(() => {
    if (pendingSendTo && pendingSendTo.tool === 'repeater') {
      const id = `tab-${Date.now()}`;
      let name = 'Sent';
      try { name = new URL(pendingSendTo.url).hostname; } catch {}
      addTab({
        id,
        name,
        method: pendingSendTo.method,
        url: pendingSendTo.url,
        requestRaw: pendingSendTo.requestRaw,
        responseRaw: '',
        statusCode: null,
        responseTimeMs: null,
        responseSize: null,
        isLoading: false,
      });
      clearSendTo();
    }
  }, [pendingSendTo]);

  const send = useCallback(async () => {
    if (!tab || tab.isLoading) return;
    updateTab(tab.id, { isLoading: true, responseRaw: '', statusCode: null });

    try {
      const parsedHeaders: Record<string, string> = {};
      let parsedBody: string | null = null;

      if (tab.requestRaw) {
        const lines = tab.requestRaw.split('\n');
        let bodyStartIdx = -1;
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].replace(/\r/g, '');
          if (line === '') { bodyStartIdx = i + 1; break; }
          const colonIdx = line.indexOf(':');
          if (colonIdx > 0) {
            parsedHeaders[line.slice(0, colonIdx).trim()] = line.slice(colonIdx + 1).trim();
          }
        }
        if (bodyStartIdx > 0 && bodyStartIdx < lines.length) {
          parsedBody = lines.slice(bodyStartIdx).join('\n').trim() || null;
        }
      }

      const r: { status: number; headers: string; body: string; time_ms: number; size: number } =
        await invoke('send_http_request', {
          method: tab.method,
          url: tab.url,
          headers: Object.keys(parsedHeaders).length > 0 ? parsedHeaders : null,
          body: parsedBody,
        });

      const responseRaw = `HTTP/1.1 ${r.status}\n${r.headers}\n\n${r.body}`;
      updateTab(tab.id, {
        isLoading: false,
        responseRaw,
        statusCode: r.status,
        responseTimeMs: r.time_ms,
        responseSize: r.size,
      });


      const entry: HistoryEntry = {
        id: `h-${Date.now()}`,
        timestamp: new Date().toISOString(),
        method: tab.method,
        url: tab.url,
        status: r.status,
        time_ms: r.time_ms,
        size: r.size,
        requestRaw: tab.requestRaw,
        responseRaw,
      };
      setHistory(prev => ({
        ...prev,
        [tab.id]: [...(prev[tab.id] || []), entry],
      }));


      if (tab.name === 'New Request' || tab.name === 'New') {
        try {
          const host = new URL(tab.url).hostname;
          updateTab(tab.id, { name: host });
        } catch {}
      }
    } catch (err: unknown) {
      updateTab(tab.id, {
        isLoading: false,
        responseRaw: `Error: ${err instanceof Error ? err.message : String(err)}`,
        statusCode: 0,
      });
    }
  }, [tab, updateTab]);

  const addNew = () => {
    const id = `tab-${Date.now()}`;
    addTab({ id, name: 'New Request', method: 'GET', url: '', requestRaw: '', responseRaw: '', statusCode: null, responseTimeMs: null, responseSize: null, isLoading: false });
  };

  const duplicateTab = () => {
    if (!tab) return;
    const id = `tab-${Date.now()}`;
    addTab({ ...tab, id, name: `${tab.name} (copy)` });
  };

  const copyResponse = () => {
    if (tab?.responseRaw) navigator.clipboard.writeText(tab.responseRaw);
  };

  const copyRequest = () => {
    if (tab?.requestRaw) navigator.clipboard.writeText(tab.requestRaw);
  };

  const copyCurl = () => {
    if (!tab) return;
    const curl = `curl -X ${tab.method} '${tab.url}'`;
    navigator.clipboard.writeText(curl);
  };

  const startRename = (id: string, name: string) => {
    setRenaming(id);
    setRenameValue(name);
  };

  const finishRename = () => {
    if (renaming && renameValue.trim()) {
      updateTab(renaming, { name: renameValue.trim() });
    }
    setRenaming(null);
  };

  const loadHistoryEntry = (entry: HistoryEntry) => {
    if (!tab) return;
    updateTab(tab.id, {
      method: entry.method,
      url: entry.url,
      requestRaw: entry.requestRaw,
      responseRaw: entry.responseRaw,
      statusCode: entry.status,
      responseTimeMs: entry.time_ms,
      responseSize: entry.size,
    });
    setShowHistory(false);
  };

  const tabHistory = tab ? (history[tab.id] || []) : [];

  const formatBody = (raw: string, mode: string) => {
    if (mode === 'pretty') {
      try {
        const parts = raw.split('\n\n');
        if (parts.length > 1) {
          const body = parts.slice(1).join('\n\n');
          return parts[0] + '\n\n' + JSON.stringify(JSON.parse(body), null, 2);
        }
      } catch {}
      return raw;
    }
    if (mode === 'headers') {
      return raw.split('\n\n')[0] || raw;
    }
    if (mode === 'hex') {
      return toHex(raw);
    }
    return raw;
  };

  return (
    <div className="replay">

      <div className="replay-tabbar">
        {tabs.map((t) => (
          <button key={t.id}
            className={`replay-tab ${t.id === activeTabId ? 'active' : ''}`}
            onClick={() => setActiveTab(t.id)}
            onDoubleClick={() => startRename(t.id, t.name)}
          >
            <span className={`replay-tab-method`} style={{ color: t.method === 'GET' ? 'var(--green)' : t.method === 'POST' ? '#f0c040' : t.method === 'DELETE' ? 'var(--red)' : 'var(--accent)' }}>{t.method}</span>
            {renaming === t.id ? (
              <input className="replay-tab-rename" value={renameValue} onChange={e => setRenameValue(e.target.value)}
                onBlur={finishRename} onKeyDown={e => e.key === 'Enter' && finishRename()} autoFocus />
            ) : (
              <span className="replay-tab-name">{t.name}</span>
            )}
            {t.statusCode != null && t.statusCode > 0 && <span className={`replay-tab-status ${statusClass(t.statusCode)}`}>{t.statusCode}</span>}
            {tabs.length > 1 && (
              <span className="replay-tab-close" onClick={(e) => { e.stopPropagation(); removeTab(t.id); }}>
                <X size={10} />
              </span>
            )}
          </button>
        ))}
        <button className="replay-tab-add" onClick={addNew} title="New tab"><Plus size={13} /></button>
      </div>

      {tab && (
        <>
          <div className="replay-toolbar">
            <div className="replay-url-bar">
              <select className="replay-method-select" value={tab.method} onChange={(e) => updateTab(tab.id, { method: e.target.value })}>
                {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
              <input className="replay-url-input" placeholder="https://example.com/api/endpoint" value={tab.url}
                onChange={(e) => updateTab(tab.id, { url: e.target.value })} onKeyDown={(e) => e.key === 'Enter' && send()} />
            </div>
            <button className={`replay-send-btn ${tab.isLoading ? 'loading' : ''}`} onClick={send} title="Send request (Enter)">
              {tab.isLoading ? <Loader2 size={12} className="spin" /> : <Send size={12} />}
              Send
            </button>

            <div className="replay-toolbar-divider" />

            <button className="replay-action-btn" onClick={duplicateTab} title="Duplicate tab"><Copy size={12} /></button>
            <button className="replay-action-btn" onClick={copyCurl} title="Copy as cURL"><Code size={12} /></button>
            <button className={`replay-action-btn ${showImport ? 'active' : ''}`} onClick={() => setShowImport(s => !s)} title="Import raw HTTP / cURL / fetch">
              <ClipboardPaste size={12} />
            </button>
            <button className={`replay-action-btn ${showHistory ? 'active' : ''}`} onClick={() => setShowHistory(!showHistory)} title="Show history">
              <Clock size={12} />
              {tabHistory.length > 0 && <span className="replay-history-badge">{tabHistory.length}</span>}
            </button>
            <button className={`replay-action-btn ${showSettings ? 'active' : ''}`} onClick={() => setShowSettings(!showSettings)} title="Request settings">
              <Settings2 size={12} />
            </button>
          </div>

          {showSettings && (
            <div className="replay-settings-bar">
              <label className="replay-setting">
                <input type="checkbox" checked={followRedirects} onChange={e => setFollowRedirects(e.target.checked)} />
                Follow redirects
              </label>
              <label className="replay-setting">
                <input type="checkbox" checked={autoContentLength} onChange={e => setAutoContentLength(e.target.checked)} />
                Auto Content-Length
              </label>
            </div>
          )}

          {showImport && (
            <div className="replay-import-panel">
              <div className="replay-import-header">
                <ClipboardPaste size={12} />
                <span>Paste a request — raw HTTP, cURL, or fetch()</span>
                <button className="replay-import-close" onClick={() => { setShowImport(false); setImportError(null); setImportText(''); }} title="Close"><X size={12} /></button>
              </div>
              <textarea
                className="replay-import-textarea"
                value={importText}
                onChange={e => { setImportText(e.target.value); setImportError(null); }}
                onPaste={e => {
                  // Auto-import on paste if textarea is empty
                  if (!importText.trim()) {
                    const pasted = e.clipboardData.getData('text');
                    setImportText(pasted);
                    setTimeout(() => {
                      const ok = parsePastedRequest(pasted);
                      if (ok) handleImport();
                    }, 0);
                    e.preventDefault();
                  }
                }}
                placeholder={`Paste here. Examples:\n\nPOST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{"u":"a","p":"b"}\n\n— or —\n\ncurl 'https://example.com/api/login' -X POST -H 'Content-Type: application/json' -d '{"u":"a","p":"b"}'\n\n— or —\n\nfetch('https://example.com/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{"u":"a","p":"b"}' })`}
                spellCheck={false}
                autoFocus
              />
              <div className="replay-import-footer">
                {importError && <span className="replay-import-error">{importError}</span>}
                <button className="replay-import-btn" onClick={handleImport} disabled={!importText.trim()}>
                  Detect &amp; import
                </button>
              </div>
            </div>
          )}

          {showHistory && tabHistory.length > 0 && (
            <div className="replay-history-panel">
              {[...tabHistory].reverse().map(h => (
                <div key={h.id} className="replay-history-item" onClick={() => loadHistoryEntry(h)}>
                  <span className="replay-history-method" style={{ color: h.method === 'GET' ? 'var(--green)' : '#f0c040' }}>{h.method}</span>
                  <span className={`replay-history-status ${statusClass(h.status)}`}>{h.status}</span>
                  <span className="replay-history-time">{h.time_ms}ms</span>
                  <span className="replay-history-ts">{new Date(h.timestamp).toLocaleTimeString()}</span>
                </div>
              ))}
            </div>
          )}

          <div className="replay-panels">
            <div className="replay-panel">
              <div className="replay-panel-header">
                <span className="replay-panel-title">Request</span>
                <div className="replay-panel-tabs">
                  {(['raw', 'headers', 'hex'] as const).map(v => (
                    <button key={v} className={`replay-view-tab ${reqView === v ? 'active' : ''}`} onClick={() => setReqView(v)}>{v}</button>
                  ))}
                </div>
                <button className="replay-copy-btn" onClick={copyRequest} title="Copy request"><Copy size={10} /></button>
              </div>
              <div className="replay-editor">
                {reqView === 'raw' && (
                  <textarea value={tab.requestRaw} onChange={(e) => updateTab(tab.id, { requestRaw: e.target.value })}
                    placeholder={`${tab.method} / HTTP/1.1\nHost: example.com\nAccept: */*`} spellCheck={false} />
                )}
                {reqView === 'headers' && (
                  <div className="replay-editor-readonly">{(tab.requestRaw || '').split('\n\n')[0]}</div>
                )}
                {reqView === 'hex' && (
                  <pre className="replay-hex">{toHex(tab.requestRaw || '')}</pre>
                )}
              </div>
            </div>

            <div className="replay-panel">
              <div className="replay-panel-header">
                <span className="replay-panel-title">Response</span>
                <div className="replay-panel-meta">
                  {tab.statusCode != null && tab.statusCode > 0 && (
                    <>
                      <span className={`replay-status ${statusClass(tab.statusCode)}`}>{tab.statusCode}</span>
                      <span className="replay-timing">{tab.responseTimeMs}ms</span>
                      {tab.responseSize != null && (
                        <span className="replay-timing">{tab.responseSize > 1024 ? `${(tab.responseSize / 1024).toFixed(1)}KB` : `${tab.responseSize}B`}</span>
                      )}
                    </>
                  )}
                </div>
                <div className="replay-panel-tabs">
                  {(['raw', 'pretty', 'headers', 'hex'] as const).map((v) => (
                    <button key={v} className={`replay-view-tab ${respView === v ? 'active' : ''}`} onClick={() => setRespView(v)}>{v}</button>
                  ))}
                </div>
                <button className="replay-copy-btn" onClick={copyResponse} title="Copy response"><Copy size={10} /></button>
              </div>
              <div className="replay-editor">
                {tab.responseRaw ? (
                  respView === 'hex' ? (
                    <pre className="replay-hex">{toHex(tab.responseRaw)}</pre>
                  ) : (
                    <div className="replay-editor-readonly">{formatBody(tab.responseRaw, respView)}</div>
                  )
                ) : (
                  <div className="replay-empty-response">
                    <ArrowRight size={18} />
                    <p>Send a request to see response</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
