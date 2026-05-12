import { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Bot, Search, Trash2, Filter, Loader2, Check, X } from 'lucide-react';
import './Agent.css';

interface ActivityEntry {
  id: number;
  timestamp: string;
  tool_name: string;
  category: string;
  params_summary: string;
  status: string;
  result_summary: string;
  duration_ms: number;
  target_url: string;
}

interface ActivityStats {
  total: number;
  running: number;
  success: number;
  errors: number;
}

type DetailTab = 'params' | 'result' | 'raw';

function ActivityPanel() {
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [stats, setStats] = useState<ActivityStats>({ total: 0, running: 0, success: 0, errors: 0 });
  const [selected, setSelected] = useState<number | null>(null);
  const [search, setSearch] = useState('');
  const [catFilter, setCatFilter] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [detailTab, setDetailTab] = useState<DetailTab>('params');
  const feedRef = useRef<HTMLDivElement>(null);
  const autoScroll = useRef(true);
  const lastSeenId = useRef<number>(0);

  useEffect(() => {
    const MAX_ENTRIES = 200;
    const poll = async () => {
      try {
        const newEntries = await invoke<ActivityEntry[]>('get_mcp_activity', { sinceId: lastSeenId.current });
        if (newEntries.length > 0) {
          const maxId = Math.max(...newEntries.map(e => e.id));
          if (maxId > lastSeenId.current) lastSeenId.current = maxId;

          setEntries(prev => {
            const map = new Map(prev.map(e => [e.id, e]));
            for (const entry of newEntries) {
              map.set(entry.id, entry);
            }
            const merged = Array.from(map.values()).sort((a, b) => a.id - b.id);
            return merged.length > MAX_ENTRIES ? merged.slice(-MAX_ENTRIES) : merged;
          });
        }
        const s = await invoke<ActivityStats>('get_mcp_activity_stats');
        setStats(s);
      } catch { /* MCP not running */ }
    };
    poll();
    const interval = setInterval(poll, 1500);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (autoScroll.current && feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [entries]);

  const handleScroll = () => {
    if (!feedRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = feedRef.current;
    autoScroll.current = scrollHeight - scrollTop - clientHeight < 50;
  };

  const clearLog = useCallback(() => { setEntries([]); setSelected(null); }, []);

  const categories = Array.from(new Set(entries.map(e => e.category)));
  const filtered = entries.filter(e => {
    if (catFilter && e.category !== catFilter) return false;
    if (!search) return true;
    const s = search.toLowerCase();
    return e.tool_name.toLowerCase().includes(s) ||
      e.params_summary.toLowerCase().includes(s) ||
      e.result_summary.toLowerCase().includes(s) ||
      e.target_url.toLowerCase().includes(s) ||
      e.category.toLowerCase().includes(s);
  });

  const selectedEntry = entries.find(e => e.id === selected);
  const durClass = (ms: number) => ms === 0 ? '' : ms < 500 ? 'fast' : ms < 3000 ? 'medium' : 'slow';
  const fmtDur = (ms: number) => ms === 0 ? '—' : ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;

  return (
    <div className="activity-panel">
      <div className="agent-toolbar">
        <span className="agent-toolbar-title">
          <div className={`live-dot ${stats.running > 0 ? '' : 'idle'}`} />
          MCP Activity
        </span>
        <span className="agent-pill" style={{ marginLeft: 4 }}>{filtered.length} / {entries.length}</span>
        <div className="agent-toolbar-spacer" />
        <div className="agent-stat-pills">
          <span className="agent-pill running"><span className="pill-num">{stats.running}</span> active</span>
          <span className="agent-pill success"><span className="pill-num">{stats.success}</span> done</span>
          <span className="agent-pill error"><span className="pill-num">{stats.errors}</span> err</span>
        </div>
        <button className={`agent-toolbar-btn ${showFilters ? 'active' : ''}`} onClick={() => setShowFilters(!showFilters)} title="Filters">
          <Filter size={13} />
        </button>
        <button className="agent-toolbar-btn" onClick={clearLog} title="Clear log">
          <Trash2 size={13} />
        </button>
        <div className="agent-search">
          <Search size={14} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
          <input placeholder="Search tools, URLs…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
      </div>

      {showFilters && (
        <div className="agent-toolbar" style={{ height: 28, gap: 3 }}>
          <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-3)', textTransform: 'uppercase' as const, letterSpacing: '0.04em', marginRight: 2 }}>Category:</span>
          {['', ...categories].map(c => (
            <button key={c}
              style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 3,
                border: `1px solid ${catFilter === c ? 'var(--accent)' : 'var(--border-0)'}`,
                background: catFilter === c ? 'var(--accent)' : 'var(--bg-2)',
                color: catFilter === c ? 'white' : 'var(--text-2)',
                cursor: 'pointer', transition: 'all 0.15s',
              }}
              onClick={() => setCatFilter(c)}
            >
              {c || 'All'}
            </button>
          ))}
        </div>
      )}

      {filtered.length > 0 ? (
        <>
          <div className="agent-table-wrap" ref={feedRef} onScroll={handleScroll}>
            <table className="agent-table">
              <thead>
                <tr>
                  <th style={{ width: 35 }}>#</th>
                  <th style={{ width: 60 }}>Time</th>
                  <th style={{ width: 65 }}>Category</th>
                  <th style={{ width: 140 }}>Tool</th>
                  <th>Details</th>
                  <th style={{ width: 180 }}>Result</th>
                  <th style={{ width: 55, textAlign: 'right' }}>Duration</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(entry => (
                  <tr key={entry.id}
                    className={`${selected === entry.id ? 'selected' : ''} status-${entry.status}`}
                    onClick={() => setSelected(entry.id)}
                  >
                    <td style={{ color: 'var(--text-3)' }}>{entry.id}</td>
                    <td className="agent-time">{entry.timestamp}</td>
                    <td><span className={`agent-cat ${entry.category}`}>{entry.category}</span></td>
                    <td className="agent-tool-name">{entry.tool_name}</td>
                    <td className="agent-detail-cell" title={entry.params_summary}>{entry.params_summary}</td>
                    <td>
                      {entry.status === 'running' ? (
                        <span className="agent-status-indicator running">
                          <span className="running-dot" /> Processing…
                        </span>
                      ) : entry.status === 'error' ? (
                        <span className="agent-status-indicator error" title={entry.result_summary}>
                          ✗ {entry.result_summary.slice(0, 40)}
                        </span>
                      ) : (
                        <span className="agent-status-indicator success" title={entry.result_summary}>
                          {entry.result_summary.slice(0, 40) || '✓'}
                        </span>
                      )}
                    </td>
                    <td className={`agent-dur ${durClass(entry.duration_ms)}`} style={{ textAlign: 'right' }}>
                      {entry.status === 'running'
                        ? <Loader2 size={12} className="agent-spin" />
                        : fmtDur(entry.duration_ms)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {selectedEntry && (
            <div className="agent-detail">
              <div className="agent-detail-tabs">
                {([
                  { id: 'params' as const, label: 'Parameters' },
                  { id: 'result' as const, label: 'Result' },
                  { id: 'raw' as const, label: 'Raw' },
                ]).map(t => (
                  <button key={t.id} className={`agent-detail-tab ${detailTab === t.id ? 'active' : ''}`}
                    onClick={() => setDetailTab(t.id)}>{t.label}</button>
                ))}
                <div className="agent-detail-meta">
                  <span className={`agent-cat ${selectedEntry.category}`}>{selectedEntry.category}</span>
                  <span className="agent-tool-name">{selectedEntry.tool_name}</span>
                  <span className={`agent-status-indicator ${selectedEntry.status}`}>
                    {selectedEntry.status === 'success'
                      ? <Check size={12} />
                      : selectedEntry.status === 'error'
                      ? <X size={12} />
                      : <Loader2 size={12} className="agent-spin" />}
                  </span>
                  <span style={{ color: 'var(--text-3)', fontSize: 10 }}>{fmtDur(selectedEntry.duration_ms)}</span>
                </div>
              </div>
              <div className="agent-detail-body">
                {detailTab === 'params' && (
                  <pre>{selectedEntry.params_summary}{selectedEntry.target_url ? `\n\nTarget: ${selectedEntry.target_url}` : ''}</pre>
                )}
                {detailTab === 'result' && (
                  <pre>{selectedEntry.result_summary || '(no result yet)'}</pre>
                )}
                {detailTab === 'raw' && (
                  <pre>{JSON.stringify(selectedEntry, null, 2)}</pre>
                )}
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="agent-empty">
          <Bot size={40} strokeWidth={1} />
          <p>No agent activity</p>
          <span className="agent-empty-sub">
            When an MCP-connected AI uses WonderSuite tools, every action appears here in real-time
          </span>
        </div>
      )}
    </div>
  );
}

export function Agent() {
  return (
    <div className="agent-module">
      <ActivityPanel />
    </div>
  );
}
