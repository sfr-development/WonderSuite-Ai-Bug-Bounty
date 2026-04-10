import { useState, useEffect, useCallback, useRef } from 'react';
import { Pause, Play, ArrowRight, X, Shield, Zap, Globe, Copy, Send, Eye, Code, FileText, Hash, ToggleLeft, ToggleRight } from 'lucide-react';
import { useAppStore } from '../../stores';
import './Intercept.css';

interface QueuedRequest {
  id: string;
  method: string;
  url: string;
  host: string;
  raw: string;
  timestamp: string;
  isResponse: boolean;
  status?: number;
  rawResponse?: string;
}

interface ParsedHeader {
  key: string;
  value: string;
}

interface ParsedParam {
  key: string;
  value: string;
  source: string; // 'query', 'body', 'cookie'
}

function parseHeaders(raw: string): ParsedHeader[] {
  const headers: ParsedHeader[] = [];
  const lines = raw.split('\n');
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) break;
    const idx = line.indexOf(':');
    if (idx > 0) {
      headers.push({ key: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
    }
  }
  return headers;
}

function parseParams(raw: string, url: string): ParsedParam[] {
  const params: ParsedParam[] = [];

  // Query params from URL
  try {
    const u = new URL(url.startsWith('http') ? url : 'http://x' + url);
    u.searchParams.forEach((v, k) => params.push({ key: k, value: v, source: 'query' }));
  } catch {}

  // Body params (form-urlencoded)
  const bodyStart = raw.indexOf('\r\n\r\n') || raw.indexOf('\n\n');
  if (bodyStart > 0) {
    const body = raw.slice(bodyStart).trim();
    if (body && !body.startsWith('{') && !body.startsWith('<')) {
      body.split('&').forEach(pair => {
        const [k, v] = pair.split('=').map(s => {
          try { return decodeURIComponent(s); } catch { return s; }
        });
        if (k) params.push({ key: k, value: v || '', source: 'body' });
      });
    }
  }

  // Cookie params
  const lines = raw.split('\n');
  for (const line of lines) {
    if (line.toLowerCase().startsWith('cookie:')) {
      const cookies = line.slice(7).trim();
      cookies.split(';').forEach(c => {
        const [k, v] = c.trim().split('=');
        if (k) params.push({ key: k.trim(), value: (v || '').trim(), source: 'cookie' });
      });
    }
  }

  return params;
}

function toHex(text: string): string {
  const lines: string[] = [];
  const bytes = new TextEncoder().encode(text);
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(chunk).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
    const offset = i.toString(16).padStart(8, '0');
    lines.push(`${offset}  ${hex.padEnd(48)}  ${ascii}`);
  }
  return lines.join('\n');
}

export function Intercept() {
  const [interceptOn, setInterceptOn] = useState(false);
  const [responseInterceptOn, setResponseInterceptOn] = useState(false);
  const [proxyRunning, setProxyRunning] = useState(false);
  const [editorTab, setEditorTab] = useState<'raw' | 'headers' | 'params' | 'hex'>('raw');
  const [queue, setQueue] = useState<QueuedRequest[]>([]);
  const [current, setCurrent] = useState<QueuedRequest | null>(null);
  const [editedRaw, setEditedRaw] = useState('');
  const [editedHeaders, setEditedHeaders] = useState<ParsedHeader[]>([]);
  const [editedParams, setEditedParams] = useState<ParsedParam[]>([]);
  const [totalRequests, setTotalRequests] = useState(0);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; item: QueuedRequest } | null>(null);
  const contextRef = useRef<HTMLDivElement>(null);


  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen<any>('proxy-event', (event) => {
          const data = event.payload;
          if (data.type === 'intercept') {
            const item = data.item;
            const req: QueuedRequest = {
              id: item.id, method: item.method, url: item.url, host: item.host,
              raw: item.is_response ? (item.raw_response || '') : item.raw_request,
              timestamp: item.timestamp,
              isResponse: item.is_response || false,
              status: item.status,
              rawResponse: item.raw_response,
            };
            setQueue((q) => [...q, req]);
          } else if (data.type === 'intercept_resolved') {
            setQueue((q) => q.filter((r) => r.id !== data.id));
          } else if (data.type === 'traffic') {
            setTotalRequests((n) => n + 1);
          }
        });
      } catch {}
    })();
    return () => { unlisten?.(); };
  }, []);


  useEffect(() => {
    if (!current && queue.length > 0) {
      selectItem(queue[0]);
    }
  }, [queue, current]);

  const selectItem = (item: QueuedRequest) => {
    setCurrent(item);
    setEditedRaw(item.raw);
    setEditedHeaders(parseHeaders(item.raw));
    setEditedParams(parseParams(item.raw, item.url));
  };


  const rebuildRawFromHeaders = (headers: ParsedHeader[]) => {
    const lines = editedRaw.split('\n');
    const firstLine = lines[0] || '';
    const bodyIdx = editedRaw.indexOf('\r\n\r\n');
    const body = bodyIdx > 0 ? editedRaw.slice(bodyIdx) : '';
    const newRaw = firstLine + '\r\n' + headers.map(h => `${h.key}: ${h.value}`).join('\r\n') + '\r\n' + body;
    setEditedRaw(newRaw);
  };


  useEffect(() => {
    const check = async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const status = await invoke<any>('proxy_status');
        setProxyRunning(status.running);
        setInterceptOn(status.intercept_enabled);
        setResponseInterceptOn(status.response_intercept_enabled || false);
        setTotalRequests(status.total_requests);
      } catch {}
    };
    check();
    const interval = setInterval(check, 3000);
    return () => clearInterval(interval);
  }, []);


  useEffect(() => {
    const handler = () => setContextMenu(null);
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, []);

  const startProxy = useCallback(async () => {
    try { const { invoke } = await import('@tauri-apps/api/core'); await invoke('proxy_start', { port: 8080 }); setProxyRunning(true); } catch (e) { console.error(e); }
  }, []);

  const stopProxy = useCallback(async () => {
    try { const { invoke } = await import('@tauri-apps/api/core'); await invoke('proxy_stop'); setProxyRunning(false); setInterceptOn(false); } catch (e) { console.error(e); }
  }, []);

  const toggleIntercept = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      if (!proxyRunning) await startProxy();
      const next = !interceptOn;
      await invoke('proxy_toggle_intercept', { enabled: next });
      setInterceptOn(next);
    } catch (e) { console.error(e); }
  }, [interceptOn, proxyRunning, startProxy]);

  const toggleResponseIntercept = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const next = !responseInterceptOn;
      await invoke('proxy_toggle_response_intercept', { enabled: next });
      setResponseInterceptOn(next);
    } catch (e) { console.error(e); }
  }, [responseInterceptOn]);

  const forward = useCallback(async () => {
    if (!current) return;
    try { const { invoke } = await import('@tauri-apps/api/core'); await invoke('proxy_intercept_forward', { id: current.id, modifiedRequest: editedRaw }); setCurrent(null); } catch (e) { console.error(e); }
  }, [current, editedRaw]);

  const drop = useCallback(async () => {
    if (!current) return;
    try { const { invoke } = await import('@tauri-apps/api/core'); await invoke('proxy_intercept_drop', { id: current.id }); setCurrent(null); } catch (e) { console.error(e); }
  }, [current]);

  const forwardAll = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      for (const req of queue) { await invoke('proxy_intercept_forward', { id: req.id, modifiedRequest: null }); }
      setQueue([]); setCurrent(null);
    } catch {}
  }, [queue]);

  const dropAll = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      for (const req of queue) { await invoke('proxy_intercept_drop', { id: req.id }); }
      setQueue([]); setCurrent(null);
    } catch {}
  }, [queue]);

  const copyUrl = () => { if (current) navigator.clipboard.writeText(current.url); };
  const copyRaw = () => { navigator.clipboard.writeText(editedRaw); };

  const handleContextMenu = (e: React.MouseEvent, item: QueuedRequest) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, item });
  };

  const { sendTo } = useAppStore();

  const contextAction = async (action: string) => {
    if (!contextMenu) return;
    const item = contextMenu.item;
    setContextMenu(null);
    const { invoke } = await import('@tauri-apps/api/core');
    switch (action) {
      case 'forward': await invoke('proxy_intercept_forward', { id: item.id, modifiedRequest: null }); break;
      case 'drop': await invoke('proxy_intercept_drop', { id: item.id }); break;
      case 'copy_url': navigator.clipboard.writeText(item.url); break;
      case 'copy_raw': navigator.clipboard.writeText(item.raw); break;
      case 'copy_host': navigator.clipboard.writeText(item.host); break;
      case 'send_to_repeater': sendTo('repeater', item.method, item.url, item.raw); break;
      case 'send_to_intruder': sendTo('intruder', item.method, item.url, item.raw); break;
    }
  };

  const updateHeader = (idx: number, field: 'key' | 'value', val: string) => {
    const copy = [...editedHeaders];
    copy[idx] = { ...copy[idx], [field]: val };
    setEditedHeaders(copy);
    rebuildRawFromHeaders(copy);
  };

  const removeHeader = (idx: number) => {
    const copy = editedHeaders.filter((_, i) => i !== idx);
    setEditedHeaders(copy);
    rebuildRawFromHeaders(copy);
  };

  const addHeader = () => {
    const copy = [...editedHeaders, { key: '', value: '' }];
    setEditedHeaders(copy);
  };

  const mc = (m: string) => {
    const c: Record<string, string> = { GET: 'var(--method-get)', POST: 'var(--method-post)', PUT: 'var(--method-put)', DELETE: 'var(--method-delete)', PATCH: 'var(--accent)' };
    return c[m] || 'var(--text-1)';
  };

  return (
    <div className="intercept">

      <div className="intercept-toolbar">
        <button className={`intercept-toggle ${interceptOn ? 'on' : 'off'}`} onClick={toggleIntercept}>
          {interceptOn ? <Pause size={12} /> : <Play size={12} />}
          {interceptOn ? 'Intercept On' : 'Intercept Off'}
        </button>

        <div className="intercept-toolbar-divider" />

        <button className="intercept-action forward" disabled={!current} onClick={forward} title="Forward request (possibly modified)">
          <ArrowRight size={12} /> Forward
        </button>
        <button className="intercept-action drop" disabled={!current} onClick={drop} title="Drop this request">
          <X size={12} /> Drop
        </button>

        {queue.length > 1 && <>
          <div className="intercept-toolbar-divider" />
          <button className="intercept-action forward" onClick={forwardAll} title="Forward all queued requests">
            <ArrowRight size={12} /> Forward All ({queue.length})
          </button>
          <button className="intercept-action drop" onClick={dropAll} title="Drop all queued requests">
            <X size={12} /> Drop All
          </button>
        </>}

        <div className="intercept-spacer" />


        <button className={`intercept-resp-toggle ${responseInterceptOn ? 'on' : ''}`} onClick={toggleResponseIntercept} title="Toggle response interception">
          {responseInterceptOn ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
          <span>Resp</span>
        </button>

        <div className="intercept-toolbar-divider" />


        {current && <>
          <button className="intercept-action-mini" onClick={copyUrl} title="Copy URL"><Copy size={11} /></button>
          <button className="intercept-action-mini" onClick={copyRaw} title="Copy raw request"><FileText size={11} /></button>
        </>}

        <div className="intercept-toolbar-divider" />

        {!proxyRunning ? (
          <button className="intercept-proxy-btn" onClick={startProxy}><Zap size={12} /> Start Proxy</button>
        ) : (
          <button className="intercept-proxy-btn stop" onClick={stopProxy}><Zap size={12} /> Stop Proxy</button>
        )}

        <button className="intercept-proxy-btn browser" onClick={async () => {
          try { const { invoke } = await import('@tauri-apps/api/core'); if (!proxyRunning) await invoke('proxy_start', { port: 8080 }); await invoke('browser_launch', { browserName: null, proxyPort: 8080 }); } catch (e) { console.error(e); }
        }}>
          <Globe size={12} /> WonderBrowser
        </button>

        <div className="intercept-status">
          <div className={`intercept-status-dot ${proxyRunning ? (interceptOn ? 'active' : 'running') : 'idle'}`} />
          {proxyRunning ? interceptOn ? `${queue.length} queued · ${totalRequests} total` : `Running · ${totalRequests} req` : 'Proxy off'}
        </div>
      </div>


      <div className="intercept-body">
        <div className="intercept-editor">
          {current ? (
            <>

              <div className="intercept-info-bar">
                <span className="intercept-info-method" style={{ color: mc(current.method) }}>{current.method}</span>
                <span className="intercept-info-url">{current.url}</span>
                {current.isResponse && <span className="intercept-info-badge resp">RESPONSE {current.status}</span>}
                {!current.isResponse && <span className="intercept-info-badge req">REQUEST</span>}
              </div>


              <div className="intercept-editor-tabs">
                {([
                  { id: 'raw', label: 'Raw', icon: <Code size={11} /> },
                  { id: 'headers', label: 'Headers', icon: <FileText size={11} /> },
                  { id: 'params', label: 'Params', icon: <Hash size={11} /> },
                  { id: 'hex', label: 'Hex', icon: <Eye size={11} /> },
                ] as const).map((t) => (
                  <button key={t.id} className={`intercept-editor-tab ${editorTab === t.id ? 'active' : ''}`} onClick={() => setEditorTab(t.id)}>
                    {t.icon} {t.label}
                    {t.id === 'headers' && <span className="intercept-tab-count">{editedHeaders.length}</span>}
                    {t.id === 'params' && <span className="intercept-tab-count">{editedParams.length}</span>}
                  </button>
                ))}
              </div>


              {editorTab === 'raw' && (
                <textarea className="intercept-textarea" value={editedRaw} onChange={(e) => { setEditedRaw(e.target.value); setEditedHeaders(parseHeaders(e.target.value)); }} spellCheck={false} />
              )}

              {editorTab === 'headers' && (
                <div className="intercept-table-wrap">
                  <table className="intercept-table">
                    <thead><tr><th>Header</th><th>Value</th><th></th></tr></thead>
                    <tbody>
                      {editedHeaders.map((h, i) => (
                        <tr key={i}>
                          <td><input className="intercept-table-input" value={h.key} onChange={e => updateHeader(i, 'key', e.target.value)} /></td>
                          <td><input className="intercept-table-input" value={h.value} onChange={e => updateHeader(i, 'value', e.target.value)} /></td>
                          <td><button className="intercept-table-del" onClick={() => removeHeader(i)}>×</button></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <button className="intercept-table-add" onClick={addHeader}>+ Add Header</button>
                </div>
              )}

              {editorTab === 'params' && (
                <div className="intercept-table-wrap">
                  {editedParams.length === 0 ? (
                    <div className="intercept-empty-tab">No parameters found in this request</div>
                  ) : (
                    <table className="intercept-table">
                      <thead><tr><th>Source</th><th>Name</th><th>Value</th></tr></thead>
                      <tbody>
                        {editedParams.map((p, i) => (
                          <tr key={i}>
                            <td><span className={`intercept-param-source ${p.source}`}>{p.source}</span></td>
                            <td><span className="intercept-param-name">{p.key}</span></td>
                            <td><input className="intercept-table-input" defaultValue={p.value} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {editorTab === 'hex' && (
                <pre className="intercept-hex">{toHex(editedRaw)}</pre>
              )}
            </>
          ) : (
            <div className="intercept-empty">
              <Shield size={32} />
              <span>{interceptOn ? 'Waiting for request...' : 'Intercept is off'}</span>
              {!proxyRunning && <span className="intercept-empty-sub">Configure your browser to use proxy 127.0.0.1:8080</span>}
            </div>
          )}
        </div>


        <div className="intercept-queue">
          <div className="intercept-queue-header">Queue ({queue.length})</div>
          <div className="intercept-queue-list">
            {queue.map((req) => (
              <div key={req.id}
                className={`intercept-queue-item ${current?.id === req.id ? 'active' : ''}`}
                onClick={() => selectItem(req)}
                onContextMenu={(e) => handleContextMenu(e, req)}
              >
                <div className="intercept-queue-method" style={{ color: mc(req.method) }}>{req.method}</div>
                <div className="intercept-queue-url">{req.host}{new URL(req.url.startsWith('http') ? req.url : 'http://x' + req.url).pathname}</div>
                {req.isResponse && <span className="intercept-queue-badge">RESP</span>}
              </div>
            ))}
          </div>
        </div>
      </div>


      {contextMenu && (
        <div ref={contextRef} className="intercept-context-menu" style={{ left: contextMenu.x, top: contextMenu.y }}>
          <div className="intercept-ctx-item" onClick={() => contextAction('forward')}><ArrowRight size={12} /> Forward</div>
          <div className="intercept-ctx-item" onClick={() => contextAction('drop')}><X size={12} /> Drop</div>
          <div className="intercept-ctx-divider" />
          <div className="intercept-ctx-item" onClick={() => contextAction('copy_url')}><Copy size={12} /> Copy URL</div>
          <div className="intercept-ctx-item" onClick={() => contextAction('copy_raw')}><FileText size={12} /> Copy Raw Request</div>
          <div className="intercept-ctx-item" onClick={() => contextAction('copy_host')}><Globe size={12} /> Copy Host</div>
          <div className="intercept-ctx-divider" />
          <div className="intercept-ctx-item" onClick={() => contextAction('send_to_repeater')}><Send size={12} /> Send to Repeater</div>
          <div className="intercept-ctx-item" onClick={() => contextAction('send_to_intruder')}><Zap size={12} /> Send to Intruder</div>
        </div>
      )}
    </div>
  );
}
