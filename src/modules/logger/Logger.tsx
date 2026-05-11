import { useState, useEffect, useCallback } from 'react';
import { FileText, Search, Trash2, Download } from 'lucide-react';
import './Logger.css';

interface LogEntry {
  id: number;
  timestamp: string;
  tool: string;
  method: string;
  url: string;
  host: string;
  status: number;
  length: number;
  time_ms: number;
  tls: boolean;
  mime: string;
  notes: string;
}

export function Logger() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [search, setSearch] = useState('');
  const [toolFilter, setToolFilter] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen<any>('proxy-event', (event) => {
          const data = event.payload;
          if (data.type === 'traffic') {
            const e = data.entry;
            setEntries(prev => [...prev, {
              id: e.id,
              timestamp: e.timestamp,
              tool: 'Proxy',
              method: e.method,
              url: e.url,
              host: e.host,
              status: e.status,
              length: e.response_length,
              time_ms: e.response_time_ms,
              tls: e.tls,
              mime: e.mime_type,
              notes: '',
            }]);
          }
        });
      } catch {}
    })();
    (async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const traffic = await invoke<any[]>('proxy_get_traffic');
        setEntries(traffic.map(e => ({
          id: e.id, timestamp: e.timestamp, tool: e.source === 'proxy' ? 'Proxy' : e.source === 'repeater' ? 'Repeater' : e.source,
          method: e.method, url: e.url, host: e.host, status: e.status,
          length: e.response_length, time_ms: e.response_time_ms, tls: e.tls,
          mime: e.mime_type, notes: e.notes || '',
        })));
      } catch {}
    })();
    return () => { unlisten?.(); };
  }, []);

  const filtered = entries.filter(e => {
    if (toolFilter && e.tool !== toolFilter) return false;
    if (!search) return true;
    const s = search.toLowerCase();
    return e.url.toLowerCase().includes(s) || e.host.toLowerCase().includes(s) || e.method.toLowerCase().includes(s);
  });

  const tools = [...new Set(entries.map(e => e.tool))];

  const exportLog = useCallback(() => {
    const csv = ['ID,Timestamp,Tool,Method,URL,Status,Length,Time'].concat(
      filtered.map(e => `${e.id},"${e.timestamp}","${e.tool}","${e.method}","${e.url}",${e.status},${e.length},${e.time_ms}`)
    ).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `wondersuite-log-${Date.now()}.csv`; a.click();
  }, [filtered]);

  const sc = (code: number) => code < 300 ? 's2xx' : code < 400 ? 's3xx' : code < 500 ? 's4xx' : 's5xx';

  return (
    <div className="logger">
      <div className="logger-toolbar">
        <FileText size={14} />
        <span className="logger-title">Logger</span>
        <span className="logger-count">{filtered.length} entries</span>
        <div style={{ flex: 1 }} />

        <div className="logger-tool-filter">
          <button className={`logger-chip ${!toolFilter ? 'active' : ''}`} onClick={() => setToolFilter('')}>All</button>
          {tools.map(t => (
            <button key={t} className={`logger-chip ${toolFilter === t ? 'active' : ''}`} onClick={() => setToolFilter(t)}>{t}</button>
          ))}
        </div>

        <label className="logger-auto-scroll">
          <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} />
          Auto-scroll
        </label>

        <button className="logger-btn" onClick={() => { setEntries([]); setSelected(null); }} title="Clear"><Trash2 size={12} /></button>
        <button className="logger-btn" onClick={exportLog} title="Export CSV"><Download size={12} /></button>

        <div className="logger-search">
          <Search size={12} />
          <input placeholder="Filter..." value={search} onChange={e => setSearch(e.target.value)} />
        </div>
      </div>

      <div className="logger-table-wrap">
        <table className="logger-table">
          <thead>
            <tr>
              <th style={{ width: 40 }}>#</th>
              <th style={{ width: 60 }}>Tool</th>
              <th style={{ width: 55 }}>Method</th>
              <th>URL</th>
              <th style={{ width: 50 }}>Status</th>
              <th style={{ width: 60 }}>Size</th>
              <th style={{ width: 50 }}>Time</th>
              <th style={{ width: 60 }}>Clock</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(e => (
              <tr key={e.id} className={selected === e.id ? 'selected' : ''} onClick={() => setSelected(e.id)}>
                <td className="logger-dim">{e.id}</td>
                <td><span className={`logger-tool-badge ${e.tool.toLowerCase()}`}>{e.tool}</span></td>
                <td><span className="logger-method" style={{ color: e.method === 'GET' ? 'var(--green)' : e.method === 'POST' ? '#f0c040' : e.method === 'DELETE' ? 'var(--red)' : 'var(--text-1)' }}>{e.method}</span></td>
                <td className="logger-url">{e.url}</td>
                <td><span className={`logger-status ${sc(e.status)}`}>{e.status}</span></td>
                <td className="logger-dim">{e.length > 1024 ? `${(e.length / 1024).toFixed(1)}K` : `${e.length}B`}</td>
                <td className="logger-dim">{e.time_ms}ms</td>
                <td className="logger-dim logger-ts">{new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filtered.length === 0 && (
        <div className="logger-empty">
          <FileText size={32} strokeWidth={1} />
          <p>No log entries</p>
          <span>HTTP traffic from all tools will appear here</span>
        </div>
      )}
    </div>
  );
}
