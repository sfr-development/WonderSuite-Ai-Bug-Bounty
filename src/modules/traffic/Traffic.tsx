import { useState, useEffect, useCallback } from 'react';
import { Search, Activity, Trash2, Download, Lock, Filter, ArrowUpDown } from 'lucide-react';
import { useAppStore } from '../../stores';
import { useVisibilityAwareInterval } from '../../hooks/useVisibilityAwareInterval';
import './Traffic.css';

interface TrafficEntry {
  id: number;
  method: string;
  host: string;
  path: string;
  url: string;
  status: number;
  response_length: number;
  response_time_ms: number;
  source: string;
  tls: boolean;
  mime_type: string;
  timestamp: string;
  request_headers: string;
  request_body: string;
  response_headers: string;
  response_body: string;
  notes?: string;
  color?: string;
}

type SortField = 'id' | 'method' | 'host' | 'status' | 'response_length' | 'response_time_ms';
type SortDir = 'asc' | 'desc';
type DetailTab = 'request' | 'response' | 'headers' | 'params' | 'hex';

function statusClass(code: number) {
  if (code < 200) return 's1xx';
  if (code < 300) return 's2xx';
  if (code < 400) return 's3xx';
  if (code < 500) return 's4xx';
  return 's5xx';
}

function formatTime(ts: string) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return '';
  }
}

function formatSize(bytes: number): string {
  if (bytes > 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
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

function parseHeaders(raw: string): { key: string; value: string }[] {
  return raw.split('\n')
    .filter(l => l.includes(':'))
    .map(l => {
      const idx = l.indexOf(':');
      return { key: l.slice(0, idx).trim(), value: l.slice(idx + 1).trim() };
    });
}

function parseParams(url: string, body: string): { source: string; key: string; value: string }[] {
  const params: { source: string; key: string; value: string }[] = [];
  try {
    const u = new URL(url);
    u.searchParams.forEach((v, k) => params.push({ source: 'query', key: k, value: v }));
  } catch {}
  if (body && !body.startsWith('{') && !body.startsWith('<') && body.includes('=')) {
    body.split('&').forEach(pair => {
      const [k, v] = pair.split('=').map(s => { try { return decodeURIComponent(s); } catch { return s; } });
      if (k) params.push({ source: 'body', key: k, value: v || '' });
    });
  }
  return params;
}

export function Traffic() {
  const [entries, setEntries] = useState<TrafficEntry[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [search, setSearch] = useState('');
  const [detailTab, setDetailTab] = useState<DetailTab>('request');
  const [sortField, setSortField] = useState<SortField>('id');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [methodFilter, setMethodFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [showFilters, setShowFilters] = useState(false);
  const [inScopeOnly, setInScopeOnly] = useState(false);
  const { openContextMenu, isInScope } = useAppStore();


  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen<any>('proxy-event', (event) => {
          const data = event.payload;
          if (data.type === 'traffic') {
            setEntries((prev) => [...prev, data.entry]);
          }
        });
      } catch {}
    })();

    (async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const traffic = await invoke<TrafficEntry[]>('proxy_get_traffic');
        if (traffic.length > 0) setEntries(traffic);
      } catch {}
    })();

    return () => { unlisten?.(); };
  }, []);


  const pollMcpTraffic = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const mcpTraffic = await invoke<TrafficEntry[]>('get_mcp_traffic', { sinceId: 0 });
      if (mcpTraffic.length > 0) {
        setEntries(prev => {
          const existingIds = new Set(prev.map(e => e.id));
          const fresh = mcpTraffic.filter(e => !existingIds.has(e.id));
          return fresh.length > 0 ? [...prev, ...fresh] : prev;
        });
      }
    } catch {}
  }, []);

  useVisibilityAwareInterval(pollMcpTraffic, 1000);


  const clearTraffic = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('proxy_clear_traffic');
      setEntries([]);
      setSelected(null);
    } catch {}
  }, []);

  const exportTraffic = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const json = await invoke<string>('proxy_export_traffic');
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `wondersuite-traffic-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {}
  }, []);

  const handleSort = (field: SortField) => {
    if (sortField === field) { setSortDir(d => d === 'asc' ? 'desc' : 'asc'); }
    else { setSortField(field); setSortDir('asc'); }
  };

  const handleContextMenu = (e: React.MouseEvent, entry: TrafficEntry) => {
    e.preventDefault();
    openContextMenu(e.clientX, e.clientY, {
      method: entry.method,
      url: entry.url,
      requestRaw: `${entry.request_headers}\n\n${entry.request_body}`,
      responseRaw: `${entry.response_headers}\n\n${entry.response_body}`,
    });
  };


  const filtered = entries.filter((e) => {
    if (inScopeOnly && !isInScope(e.url)) return false;
    if (methodFilter && e.method !== methodFilter) return false;
    if (statusFilter) {
      const group = statusFilter;
      if (group === '2xx' && (e.status < 200 || e.status >= 300)) return false;
      if (group === '3xx' && (e.status < 300 || e.status >= 400)) return false;
      if (group === '4xx' && (e.status < 400 || e.status >= 500)) return false;
      if (group === '5xx' && e.status < 500) return false;
    }
    if (!search) return true;
    const s = search.toLowerCase();
    return e.host.toLowerCase().includes(s) || e.path.toLowerCase().includes(s) ||
      e.method.toLowerCase().includes(s) || e.url.toLowerCase().includes(s) ||
      e.mime_type.toLowerCase().includes(s) ||
      e.request_headers.toLowerCase().includes(s) ||
      e.response_headers.toLowerCase().includes(s) ||
      e.request_body.toLowerCase().includes(s) ||
      e.response_body.toLowerCase().includes(s);
  });

  const sorted = [...filtered].sort((a, b) => {
    const aVal = a[sortField];
    const bVal = b[sortField];
    const cmp = typeof aVal === 'string' ? aVal.localeCompare(bVal as string) : (aVal as number) - (bVal as number);
    return sortDir === 'asc' ? cmp : -cmp;
  });

  const selectedEntry = entries.find((e) => e.id === selected);

  const mc = (m: string) => {
    const c: Record<string, string> = { GET: 'var(--method-get)', POST: 'var(--method-post)', PUT: 'var(--method-put)', DELETE: 'var(--method-delete)', PATCH: 'var(--accent)', OPTIONS: 'var(--text-3)', HEAD: 'var(--text-2)' };
    return c[m] || 'var(--text-1)';
  };

  const SortHeader = ({ field, label, style }: { field: SortField; label: string; style?: React.CSSProperties }) => (
    <th style={{ ...style, cursor: 'pointer', userSelect: 'none' }} onClick={() => handleSort(field)}>
      <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
        {label}
        {sortField === field && <ArrowUpDown size={9} style={{ opacity: 0.5 }} />}
      </span>
    </th>
  );

  return (
    <div className="traffic">
      <div className="traffic-toolbar">
        <span className="traffic-toolbar-title">HTTP History</span>
        <span className="traffic-count">{filtered.length} / {entries.length}</span>
        <div className="traffic-toolbar-spacer" />


        <button className={`traffic-toolbar-btn ${inScopeOnly ? 'active' : ''}`} onClick={() => setInScopeOnly(!inScopeOnly)} title="Show only in-scope items">
          <Lock size={13} />
        </button>
        <button className={`traffic-toolbar-btn ${showFilters ? 'active' : ''}`} onClick={() => setShowFilters(!showFilters)} title="Toggle filters">
          <Filter size={13} />
        </button>
        <button className="traffic-toolbar-btn" onClick={clearTraffic} title="Clear traffic">
          <Trash2 size={13} />
        </button>
        <button className="traffic-toolbar-btn" onClick={exportTraffic} title="Export as JSON">
          <Download size={13} />
        </button>
        <div className="traffic-search">
          <Search size={14} className="traffic-search-icon" />
          <input placeholder="Search URL, headers, body..." value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </div>


      {showFilters && (
        <div className="traffic-filter-bar">
          <span className="traffic-filter-label">Method:</span>
          {['', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].map(m => (
            <button key={m} className={`traffic-filter-chip ${methodFilter === m ? 'active' : ''}`}
              onClick={() => setMethodFilter(m)}>{m || 'All'}</button>
          ))}
          <span className="traffic-filter-sep" />
          <span className="traffic-filter-label">Status:</span>
          {['', '2xx', '3xx', '4xx', '5xx'].map(s => (
            <button key={s} className={`traffic-filter-chip ${statusFilter === s ? 'active' : ''}`}
              onClick={() => setStatusFilter(s)}>{s || 'All'}</button>
          ))}
        </div>
      )}

      {sorted.length > 0 ? (
        <>
          <div className="traffic-table-wrap">
            <table className="traffic-table">
              <thead>
                <tr>
                  <SortHeader field="id" label="#" style={{ width: 40 }} />
                  <th style={{ width: 24 }}>TLS</th>
                  <SortHeader field="method" label="Method" style={{ width: 70 }} />
                  <SortHeader field="host" label="Host" />
                  <th>Path</th>
                  <SortHeader field="status" label="Status" style={{ width: 60 }} />
                  <SortHeader field="response_length" label="Size" style={{ width: 70 }} />
                  <SortHeader field="response_time_ms" label="Time" style={{ width: 60 }} />
                  <th style={{ width: 50 }}>MIME</th>
                  <th style={{ width: 55 }}>Clock</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((entry) => (
                  <tr key={entry.id}
                    className={selected === entry.id ? 'selected' : ''}
                    onClick={() => setSelected(entry.id)}
                    onContextMenu={(e) => handleContextMenu(e, entry)}
                    style={entry.color ? { borderLeft: `3px solid ${entry.color}` } : undefined}
                  >
                    <td style={{ color: 'var(--text-3)' }}>{entry.id}</td>
                    <td style={{ textAlign: 'center' }}>
                      {entry.tls && <Lock size={10} style={{ color: 'var(--green)', opacity: 0.7 }} />}
                    </td>
                    <td><span className="traffic-method" style={{ color: mc(entry.method) }}>{entry.method}</span></td>
                    <td className="traffic-cell-host">{entry.host}</td>
                    <td className="traffic-cell-path">{entry.path}</td>
                    <td><span className={`traffic-status ${statusClass(entry.status)}`}>{entry.status}</span></td>
                    <td style={{ color: 'var(--text-3)' }}>{formatSize(entry.response_length)}</td>
                    <td style={{ color: entry.response_time_ms > 500 ? 'var(--red)' : 'var(--text-3)' }}>{entry.response_time_ms}ms</td>
                    <td className="traffic-cell-mime">{entry.mime_type.split(';')[0].split('/').pop()}</td>
                    <td className="traffic-cell-time">{formatTime(entry.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {selectedEntry && (
            <div className="traffic-detail">
              <div className="traffic-detail-tabs">
                {([
                  { id: 'request', label: 'Request' },
                  { id: 'response', label: 'Response' },
                  { id: 'headers', label: 'Headers' },
                  { id: 'params', label: 'Params' },
                  { id: 'hex', label: 'Hex' },
                ] as const).map(t => (
                  <button key={t.id} className={`traffic-detail-tab ${detailTab === t.id ? 'active' : ''}`}
                    onClick={() => setDetailTab(t.id)}>{t.label}</button>
                ))}
                <div className="traffic-detail-meta">
                  <span className="traffic-method" style={{ color: mc(selectedEntry.method) }}>{selectedEntry.method}</span>
                  <span style={{ color: 'var(--text-2)', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{selectedEntry.url}</span>
                  <span className={`traffic-status ${statusClass(selectedEntry.status)}`}>{selectedEntry.status}</span>
                  <span style={{ color: 'var(--text-3)', fontSize: 10 }}>{selectedEntry.response_time_ms}ms · {formatSize(selectedEntry.response_length)}</span>
                  {selectedEntry.tls && <Lock size={10} style={{ color: 'var(--green)' }} />}
                </div>
              </div>

              <div className="traffic-detail-body">
                {detailTab === 'request' && (
                  <pre>{selectedEntry.request_headers}{selectedEntry.request_body ? `\n\n${selectedEntry.request_body}` : ''}</pre>
                )}
                {detailTab === 'response' && (
                  <pre>{selectedEntry.response_headers}{selectedEntry.response_body ? `\n\n${selectedEntry.response_body}` : ''}</pre>
                )}
                {detailTab === 'headers' && (
                  <div className="traffic-parsed-headers">
                    <div className="traffic-parsed-section">
                      <div className="traffic-parsed-title">Request Headers</div>
                      <table className="traffic-parsed-table">
                        <tbody>
                          {parseHeaders(selectedEntry.request_headers).map((h, i) => (
                            <tr key={i}><td className="traffic-hdr-key">{h.key}</td><td>{h.value}</td></tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="traffic-parsed-section">
                      <div className="traffic-parsed-title">Response Headers</div>
                      <table className="traffic-parsed-table">
                        <tbody>
                          {parseHeaders(selectedEntry.response_headers).map((h, i) => (
                            <tr key={i}><td className="traffic-hdr-key">{h.key}</td><td>{h.value}</td></tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
                {detailTab === 'params' && (() => {
                  const params = parseParams(selectedEntry.url, selectedEntry.request_body);
                  return params.length > 0 ? (
                    <table className="traffic-parsed-table">
                      <thead><tr><th>Source</th><th>Name</th><th>Value</th></tr></thead>
                      <tbody>
                        {params.map((p, i) => (
                          <tr key={i}>
                            <td><span className={`traffic-param-src ${p.source}`}>{p.source}</span></td>
                            <td className="traffic-hdr-key">{p.key}</td>
                            <td>{p.value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : <div className="traffic-empty-tab">No parameters</div>;
                })()}
                {detailTab === 'hex' && (
                  <pre className="traffic-hex">{toHex(detailTab === 'hex'
                    ? `${selectedEntry.request_headers}\n\n${selectedEntry.request_body}`
                    : ''
                  )}</pre>
                )}
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="traffic-empty">
          <Activity size={40} strokeWidth={1} />
          <p>No traffic captured</p>
          <span className="traffic-empty-sub">
            Start the proxy (127.0.0.1:8080) and configure your browser to use it
          </span>
        </div>
      )}


    </div>
  );
}
