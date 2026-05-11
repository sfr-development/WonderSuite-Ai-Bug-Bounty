import { useState, useEffect, useRef, useCallback } from 'react';
import { Play, Radar, ShieldAlert, Trash2, Settings2, Download, FileText, RefreshCcw, ExternalLink, ChevronDown, ChevronRight, Pause, Copy, Zap, Globe, BarChart3, AlertTriangle, CheckCircle, XCircle, Clock, Search } from 'lucide-react';
import { useAppStore } from '../../stores';
import './Scan.css';

interface ScanTask {
  id: string; target: string; type: string; status: string; progress: number;
  requests: number; findingCount: number; elapsedMs: number; startedAt: string; technologies: string[];
}
interface ScanFinding {
  id: string; finding_type: string; name: string; severity: string; confidence: string;
  url: string; parameter?: string; payload?: string; evidence?: string; detail: string; remediation: string;
  request_info?: { method: string; url: string; request_headers: string[]; request_body?: string; response_status: number; response_headers: string[]; response_body_preview: string; response_time_ms: number; response_size: number; };
}
type ScanCheck = { key: string; label: string; enabled: boolean; category: string };

const DEFAULT_CHECKS: ScanCheck[] = [
  { key: 'check_sqli', label: 'SQL Injection', enabled: true, category: 'injection' },
  { key: 'check_xss', label: 'Cross-Site Scripting', enabled: true, category: 'injection' },
  { key: 'check_command_injection', label: 'OS Command Injection', enabled: true, category: 'injection' },
  { key: 'check_ssti', label: 'Template Injection (SSTI)', enabled: true, category: 'injection' },
  { key: 'check_xxe', label: 'XML External Entity', enabled: true, category: 'injection' },
  { key: 'check_ssrf', label: 'Server-Side Request Forgery', enabled: true, category: 'server' },
  { key: 'check_path_traversal', label: 'Path Traversal / LFI', enabled: true, category: 'server' },
  { key: 'check_open_redirect', label: 'Open Redirect', enabled: true, category: 'client' },
  { key: 'check_cors', label: 'CORS Misconfiguration', enabled: true, category: 'client' },
  { key: 'check_headers', label: 'Security Headers', enabled: true, category: 'config' },
  { key: 'check_cookies', label: 'Cookie Flags', enabled: true, category: 'config' },
  { key: 'check_info_disclosure', label: 'Information Disclosure', enabled: true, category: 'config' },
];

const SEV_COLORS: Record<string, string> = { critical: '#dc2626', high: '#ef4444', medium: '#f59e0b', low: '#3b82f6', info: '#6b7280' };
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_ICONS: Record<string, any> = { critical: XCircle, high: AlertTriangle, medium: AlertTriangle, low: CheckCircle, info: CheckCircle };

export function Scan() {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('crawl_and_audit');
  const [showConfig, setShowConfig] = useState(false);
  const [checks, setChecks] = useState<ScanCheck[]>(DEFAULT_CHECKS);
  const [maxRequests, setMaxRequests] = useState(500);
  const [maxDepth, setMaxDepth] = useState(3);
  const [concurrency, setConcurrency] = useState(5);
  const [followRedirects, setFollowRedirects] = useState(true);
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [selectedTask, setSelectedTask] = useState<string | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<ScanFinding | null>(null);
  const [viewMode, setViewMode] = useState<'findings' | 'live'>('findings');
  const [liveLog, setLiveLog] = useState<Array<{ method: string; url: string; response_status: number; response_time_ms: number; response_size: number }>>([]);
  const liveLogRef = useRef<HTMLDivElement | null>(null);
  const autoScrollRef = useRef(true);
  const [showEvidence, setShowEvidence] = useState(false);
  const [sevFilter, setSevFilter] = useState<string>('all');
  const [detailTab, setDetailTab] = useState<'detail'|'request'|'response'>('detail');
  const [findingSearch, setFindingSearch] = useState('');
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const { sendTo, openContextMenu, addToast } = useAppStore();

  const startScan = useCallback(async () => {
    if (!target || target.length < 8) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const config: Record<string, unknown> = {
        max_depth: maxDepth, max_requests: maxRequests, follow_redirects: followRedirects,
        auto_crawl: true, crawl_depth: 2, timeout_ms: 10000, concurrency,
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WonderSuite/1.0',
      };
      for (const c of checks) config[c.key] = c.enabled;
      const scanId: string = await invoke('scanner_start_active', { target, config });
      const task: ScanTask = { id: scanId, target, type: scanType, status: 'running', progress: 0, requests: 0, findingCount: 0, elapsedMs: 0, startedAt: new Date().toISOString(), technologies: [] };
      setTasks(t => [task, ...t]);
      setSelectedTask(scanId);
      startPolling(scanId);
      addToast({ title: 'Scan Started', message: `Scanning ${target}...`, type: 'info' });
    } catch (err: any) { addToast({ title: 'Scan Failed', message: String(err), type: 'error' }); }
  }, [target, scanType, checks, maxRequests, maxDepth, followRedirects, concurrency]);

  const startPolling = (scanId: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const s: any = await invoke('scanner_status', { scanId });
        setTasks(prev => prev.map(t => t.id === scanId ? { ...t, status: s.status, progress: s.progress, requests: s.total_requests, findingCount: s.finding_count, elapsedMs: s.elapsed_ms } : t));
        // Always pull live data for the running scan - the selectedTask check
        // was stale-captured in the interval closure, leaving live log empty.
        loadFindings(scanId);
        try {
          const r: any = await invoke('scanner_get_result', { scanId });
          if (r?.request_log) setLiveLog(r.request_log);
        } catch { /* not ready */ }
        const done = s.status === 'completed' || s.status === 'cancelled' || (typeof s.status === 'string' && s.status.startsWith('error'));
        if (done) {
          clearInterval(pollRef.current!); pollRef.current = null;
          loadFindings(scanId);
          const tone = s.status === 'completed' ? (s.finding_count > 0 ? 'warning' : 'success') : (s.status === 'cancelled' ? 'info' : 'error');
          const title = s.status === 'completed' ? 'Scan Complete' : s.status === 'cancelled' ? 'Scan Cancelled' : 'Scan Failed';
          const msg = s.status === 'completed' ? `${s.finding_count} findings.` : s.status === 'cancelled' ? `${s.finding_count} findings recorded before cancel.` : s.status;
          addToast({ title, message: msg, type: tone });
        }
      } catch { /* not ready */ }
    }, 700);
  };

  useEffect(() => {
    if (viewMode !== 'live' || !autoScrollRef.current) return;
    const el = liveLogRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [liveLog, viewMode]);

  const onLiveScroll = () => {
    const el = liveLogRef.current;
    if (!el) return;
    autoScrollRef.current = (el.scrollHeight - el.scrollTop - el.clientHeight) < 30;
  };

  const loadFindings = async (scanId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const r: any = await invoke('scanner_get_findings', { scanId, severityFilter: null });
      setFindings(r.findings || []);
      setTasks(prev => prev.map(t => t.id === scanId ? { ...t, findingCount: (r.findings || []).length, technologies: r.technologies || [] } : t));
    } catch { /* */ }
  };

  const stopScan = async (id: string) => { try { const { invoke } = await import('@tauri-apps/api/core'); await invoke('scanner_stop', { scanId: id }); } catch { /* */ } };
  const deleteScan = async (id: string) => { try { const { invoke } = await import('@tauri-apps/api/core'); await invoke('scanner_delete_scan', { scanId: id }); } catch { /* */ } setTasks(p => p.filter(t => t.id !== id)); if (selectedTask === id) { setSelectedTask(null); setFindings([]); setSelectedFinding(null); } };

  const generateReport = async (fmt: string) => {
    if (!selectedTask) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const report: string = await invoke('scanner_generate_report', { scanId: selectedTask, format: fmt });
      const blob = new Blob([report], { type: fmt === 'json' ? 'application/json' : 'text/html' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
      a.download = `scan-report-${Date.now()}.${fmt === 'json' ? 'json' : 'html'}`; a.click();
      addToast({ title: 'Report Downloaded', message: `${fmt.toUpperCase()} report saved.`, type: 'success' });
    } catch { addToast({ title: 'Error', message: 'Report generation failed.', type: 'error' }); }
  };

  const sendToRepeater = (f: ScanFinding) => {
    const u = f.request_info?.url || f.url; const m = f.request_info?.method || 'GET';
    const raw = f.request_info ? `${m} ${u} HTTP/1.1\n${f.request_info.request_headers.join('\n')}${f.request_info.request_body ? '\n\n' + f.request_info.request_body : ''}` : `GET ${u} HTTP/1.1\nHost: ${new URL(u).hostname}`;
    sendTo('repeater', m, u, raw);
  };

  const handleCtx = (e: React.MouseEvent, f: ScanFinding) => {
    e.preventDefault();
    const u = f.request_info?.url || f.url; const m = f.request_info?.method || 'GET';
    const req = f.request_info ? `${m} ${u} HTTP/1.1\n${f.request_info.request_headers.join('\n')}${f.request_info.request_body ? '\n\n' + f.request_info.request_body : ''}` : `GET ${u} HTTP/1.1\nHost: ${new URL(u).hostname}`;
    const res = f.request_info ? `HTTP/1.1 ${f.request_info.response_status}\n${f.request_info.response_headers.join('\n')}\n\n${f.request_info.response_body_preview || ''}` : undefined;
    openContextMenu(e.clientX, e.clientY, { method: m, url: u, requestRaw: req, responseRaw: res });
  };

  const copyFinding = (f: ScanFinding) => {
    const txt = `[${f.severity.toUpperCase()}] ${f.name}\nURL: ${f.url}\n${f.parameter ? `Parameter: ${f.parameter}\n` : ''}${f.payload ? `Payload: ${f.payload}\n` : ''}Detail: ${f.detail}\n${f.remediation ? `Remediation: ${f.remediation}` : ''}`;
    navigator.clipboard.writeText(txt);
    addToast({ title: 'Copied', message: 'Finding details copied.', type: 'success' });
  };

  useEffect(() => { if (selectedTask) loadFindings(selectedTask); }, [selectedTask]);
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const activeTask = tasks.find(t => t.id === selectedTask);
  const filteredFindings = findings
    .filter(f => sevFilter === 'all' || f.severity === sevFilter)
    .filter(f => !findingSearch || f.name.toLowerCase().includes(findingSearch.toLowerCase()) || f.url.toLowerCase().includes(findingSearch.toLowerCase()))
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4));

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { if (f.severity in sevCounts) (sevCounts as any)[f.severity]++; });
  const totalSev = sevCounts.critical * 10 + sevCounts.high * 5 + sevCounts.medium * 2 + sevCounts.low;
  const riskLabel = totalSev === 0 ? 'Clean' : totalSev <= 5 ? 'Low Risk' : totalSev <= 20 ? 'Medium Risk' : totalSev <= 50 ? 'High Risk' : 'Critical Risk';
  const riskColor = totalSev === 0 ? '#22c55e' : totalSev <= 5 ? '#3b82f6' : totalSev <= 20 ? '#f59e0b' : totalSev <= 50 ? '#ef4444' : '#dc2626';

  const categories = [...new Set(DEFAULT_CHECKS.map(c => c.category))];

  return (
    <div className="scan">
      {/* Toolbar */}
      <div className="scan-toolbar">
        <Radar size={14} className="scan-toolbar-icon" />
        <span className="scan-toolbar-title">Active Scanner</span>
        <div style={{ flex: 1 }} />
        <div className="scan-target-wrap">
          <Globe size={11} className="scan-target-icon" />
          <input className="scan-target-input" value={target} onChange={e => setTarget(e.target.value)} placeholder="https://target.example.com" onKeyDown={e => e.key === 'Enter' && startScan()} />
        </div>
        <select className="scan-type-select" value={scanType} onChange={e => setScanType(e.target.value)}>
          <option value="crawl_and_audit">Crawl & Audit</option>
          <option value="passive_audit">Passive Audit</option>
          <option value="owasp_top10">OWASP Top 10</option>
          <option value="lightweight">Lightweight</option>
          <option value="api_scan">API Scan</option>
        </select>
        <button className={`scan-config-btn ${showConfig ? 'active' : ''}`} onClick={() => setShowConfig(!showConfig)} title="Configuration"><Settings2 size={11} /></button>
        <button className="scan-start-btn" onClick={startScan} disabled={!target || target.length < 8}><Play size={10} /> Scan</button>
      </div>

      {/* Config panel */}
      {showConfig && (
        <div className="scan-config-panel">
          <div className="scan-config-left">
            <span className="scan-config-title">Scan Checks</span>
            {categories.map(cat => (
              <div key={cat} className="scan-config-cat">
                <span className="scan-config-cat-label">{cat}</span>
                {checks.filter(c => c.category === cat).map(c => (
                  <label key={c.key} className="scan-config-check"><input type="checkbox" checked={c.enabled} onChange={() => setChecks(p => p.map(x => x.key === c.key ? { ...x, enabled: !x.enabled } : x))} />{c.label}</label>
                ))}
              </div>
            ))}
            <div className="scan-config-quick">
              <button onClick={() => setChecks(p => p.map(c => ({ ...c, enabled: true })))}>All</button>
              <button onClick={() => setChecks(p => p.map(c => ({ ...c, enabled: false })))}>None</button>
              <button onClick={() => setChecks(p => p.map(c => ({ ...c, enabled: ['check_sqli','check_xss','check_command_injection'].includes(c.key) })))}>Critical Only</button>
            </div>
          </div>
          <div className="scan-config-right">
            <span className="scan-config-title">Options</span>
            <div className="scan-config-grid">
              <label>Max Requests</label><input type="number" value={maxRequests} onChange={e => setMaxRequests(Number(e.target.value))} />
              <label>Crawl Depth</label><input type="number" value={maxDepth} onChange={e => setMaxDepth(Number(e.target.value))} />
              <label>Concurrency</label><input type="number" value={concurrency} onChange={e => setConcurrency(Number(e.target.value))} />
            </div>
            <label className="scan-config-check"><input type="checkbox" checked={followRedirects} onChange={e => setFollowRedirects(e.target.checked)} /> Follow Redirects</label>
          </div>
        </div>
      )}

      <div className="scan-body">
        {/* Task list */}
        <div className="scan-task-list">
          <div className="scan-task-list-header">
            <span>Scan History</span>
            <span className="scan-task-count">{tasks.length}</span>
          </div>
          {tasks.length === 0 ? (
            <div className="scan-empty">
              <Radar size={28} strokeWidth={1} />
              <span>No scans yet</span>
              <span className="scan-empty-sub">Enter a URL and press Scan</span>
            </div>
          ) : tasks.map(task => (
            <div key={task.id} className={`scan-task ${selectedTask === task.id ? 'selected' : ''}`} onClick={() => setSelectedTask(task.id)}>
              <div className="scan-task-top">
                <div className={`scan-task-dot ${task.status === 'running' ? 'running' : task.status.startsWith('error') ? 'failed' : 'completed'}`} />
                <span className="scan-task-target" title={task.target}>{task.target.replace(/^https?:\/\//, '')}</span>
                <div className="scan-task-actions">
                  {task.status === 'running' && <button title="Stop" onClick={e => { e.stopPropagation(); stopScan(task.id); }}><Pause size={9} /></button>}
                  <button title="Delete" onClick={e => { e.stopPropagation(); deleteScan(task.id); }}><Trash2 size={9} /></button>
                </div>
              </div>
              <div className="scan-task-progress-bar"><div className="scan-task-progress-fill" style={{ width: `${task.progress}%` }} /></div>
              <div className="scan-task-meta">
                <span>{Math.round(task.progress)}%</span>
                <span>{task.requests} req</span>
                <span className={task.findingCount > 0 ? 'scan-has-findings' : ''}>{task.findingCount} findings</span>
                {task.elapsedMs > 0 && <span><Clock size={8} /> {(task.elapsedMs / 1000).toFixed(1)}s</span>}
              </div>
              {task.technologies.length > 0 && (
                <div className="scan-task-techs">{task.technologies.slice(0, 5).map(t => <span key={t} className="scan-tech-badge">{t}</span>)}</div>
              )}
            </div>
          ))}
        </div>

        {/* Findings */}
        {activeTask ? (
          <div className="scan-findings-panel">
            {/* Stats bar */}
            <div className="scan-stats-bar">
              <div className="scan-risk-badge" style={{ '--risk-color': riskColor } as React.CSSProperties}>
                <BarChart3 size={11} />
                <span>{riskLabel}</span>
              </div>
              <div className="scan-view-toggle">
                <button
                  className={`scan-view-tab ${viewMode === 'findings' ? 'active' : ''}`}
                  onClick={() => setViewMode('findings')}>Findings ({findings.length})</button>
                <button
                  className={`scan-view-tab ${viewMode === 'live' ? 'active' : ''}`}
                  onClick={() => setViewMode('live')}>
                  Live Requests
                  {activeTask?.status !== 'completed' && activeTask?.status !== 'cancelled' && !activeTask?.status?.startsWith('error') && (
                    <span className="scan-view-live-dot" />
                  )}
                  <span className="scan-view-count">{liveLog.length}</span>
                </button>
              </div>
              {viewMode === 'findings' && (
              <div className="scan-sev-pills">
                <button className={`scan-sev-pill ${sevFilter === 'all' ? 'active' : ''}`} onClick={() => setSevFilter('all')}>All ({findings.length})</button>
                {Object.entries(sevCounts).filter(([, v]) => v > 0).map(([sev, count]) => {
                  const Icon = SEV_ICONS[sev] || CheckCircle;
                  return <button key={sev} className={`scan-sev-pill ${sevFilter === sev ? 'active' : ''}`} style={{ '--pill-color': SEV_COLORS[sev] } as React.CSSProperties} onClick={() => setSevFilter(sev)}><Icon size={8} /> {sev[0].toUpperCase()} ({count})</button>;
                })}
              </div>
              )}
              <div style={{ flex: 1 }} />
              <div className="scan-search-wrap">
                <Search size={10} />
                <input placeholder="Filter findings..." value={findingSearch} onChange={e => setFindingSearch(e.target.value)} />
              </div>
              <button className="scan-action-btn" onClick={() => generateReport('html')}><FileText size={10} /> HTML</button>
              <button className="scan-action-btn" onClick={() => generateReport('json')}><Download size={10} /> JSON</button>
            </div>

            <div className="scan-findings-body">
              {viewMode === 'live' && (
                <div className="scan-live-log" ref={liveLogRef} onScroll={onLiveScroll}>
                  {liveLog.length === 0 ? (
                    <div className="scan-empty" style={{ padding: 30 }}>
                      <span style={{ fontSize: 11, color: 'var(--text-3)' }}>No requests yet. Start a scan to see traffic stream here.</span>
                    </div>
                  ) : (
                    liveLog.map((r, i) => (
                      <div key={i} className={`scan-live-row status-${Math.floor(r.response_status / 100)}xx`}>
                        <span className="scan-live-num">{i + 1}</span>
                        <span className={`scan-live-status s${Math.floor(r.response_status / 100)}`}>{r.response_status || '—'}</span>
                        <span className="scan-live-method">{r.method}</span>
                        <span className="scan-live-url" title={r.url}>{r.url.length > 110 ? r.url.slice(0, 110) + '…' : r.url}</span>
                        <span className="scan-live-time">{r.response_time_ms}ms</span>
                        <span className="scan-live-size">{r.response_size > 1024 ? `${(r.response_size / 1024).toFixed(1)}KB` : `${r.response_size}B`}</span>
                      </div>
                    ))
                  )}
                </div>
              )}
              {viewMode === 'findings' && (<>
              {/* List */}
              <div className="scan-findings-list">
                {filteredFindings.map(f => (
                  <div key={f.id} className={`scan-finding ${selectedFinding?.id === f.id ? 'selected' : ''}`} onClick={() => { setSelectedFinding(f); setShowEvidence(false); setDetailTab('detail'); }} onContextMenu={e => handleCtx(e, f)}>
                    <span className="scan-finding-sev" style={{ background: SEV_COLORS[f.severity] }}>{f.severity[0].toUpperCase()}</span>
                    <div className="scan-finding-info">
                      <span className="scan-finding-name">{f.name}</span>
                      <span className="scan-finding-url">{f.url.replace(/^https?:\/\//, '').substring(0, 50)}</span>
                    </div>
                    {f.parameter && <span className="scan-finding-param">{f.parameter}</span>}
                    <span className="scan-finding-conf">{f.confidence}</span>
                  </div>
                ))}
                {filteredFindings.length === 0 && (
                  <div className="scan-empty" style={{ padding: 20 }}>
                    <span style={{ fontSize: 11, color: 'var(--text-3)' }}>{findings.length === 0 ? (activeTask.status === 'running' ? 'Scanning...' : 'No findings') : 'No match'}</span>
                  </div>
                )}
              </div>

              {/* Detail */}
              {selectedFinding ? (
                <div className="scan-finding-detail">
                  <div className="scan-finding-detail-header">
                    <span className="scan-finding-detail-sev" style={{ color: SEV_COLORS[selectedFinding.severity] }}>{selectedFinding.severity.toUpperCase()}</span>
                    <span className="scan-finding-detail-name">{selectedFinding.name}</span>
                    <span className="scan-finding-detail-conf">{selectedFinding.confidence}</span>
                  </div>
                  <div className="scan-finding-detail-url">{selectedFinding.url}</div>

                  <div className="scan-detail-tabs">
                    <button className={detailTab === 'detail' ? 'active' : ''} onClick={() => setDetailTab('detail')}>Detail</button>
                    {selectedFinding.request_info && <button className={detailTab === 'request' ? 'active' : ''} onClick={() => setDetailTab('request')}>Request</button>}
                    {selectedFinding.request_info && <button className={detailTab === 'response' ? 'active' : ''} onClick={() => setDetailTab('response')}>Response</button>}
                  </div>

                  <div className="scan-detail-content">
                    {detailTab === 'detail' && (<>
                      {selectedFinding.parameter && <div className="scan-finding-detail-section"><label>Parameter</label><p className="scan-mono">{selectedFinding.parameter}</p></div>}
                      {selectedFinding.payload && <div className="scan-finding-detail-section"><label>Payload</label><pre className="scan-evidence-pre">{selectedFinding.payload}</pre></div>}
                      <div className="scan-finding-detail-section"><label>Detail</label><p style={{ whiteSpace: 'pre-wrap' }}>{selectedFinding.detail}</p></div>
                      {selectedFinding.evidence && (
                        <div className="scan-finding-detail-section scan-evidence">
                          <label onClick={() => setShowEvidence(!showEvidence)} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>{showEvidence ? <ChevronDown size={10} /> : <ChevronRight size={10} />} Evidence</label>
                          {showEvidence && <pre className="scan-evidence-pre">{selectedFinding.evidence}</pre>}
                        </div>
                      )}
                      {selectedFinding.remediation && (
                        <div className="scan-finding-detail-section scan-remediation"><label>Remediation</label><p style={{ whiteSpace: 'pre-wrap' }}>{selectedFinding.remediation}</p></div>
                      )}
                    </>)}
                    {detailTab === 'request' && selectedFinding.request_info && (
                      <pre className="scan-evidence-pre" style={{ maxHeight: 'none', flex: 1 }}>{selectedFinding.request_info.method} {selectedFinding.request_info.url}{'\n'}{selectedFinding.request_info.request_headers.join('\n')}{selectedFinding.request_info.request_body ? '\n\n' + selectedFinding.request_info.request_body : ''}</pre>
                    )}
                    {detailTab === 'response' && selectedFinding.request_info && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
                        <div className="scan-resp-meta">
                          <span className={`scan-resp-status ${selectedFinding.request_info.response_status < 400 ? 'ok' : 'err'}`}>{selectedFinding.request_info.response_status}</span>
                          <span>{selectedFinding.request_info.response_time_ms}ms</span>
                          <span>{selectedFinding.request_info.response_size}B</span>
                        </div>
                        <pre className="scan-evidence-pre" style={{ maxHeight: 'none', flex: 1 }}>{selectedFinding.request_info.response_headers.join('\n')}{'\n\n'}{selectedFinding.request_info.response_body_preview}</pre>
                      </div>
                    )}
                  </div>

                  <div className="scan-finding-actions">
                    <button className="scan-action-btn" onClick={() => sendToRepeater(selectedFinding)}><ExternalLink size={10} /> Repeater</button>
                    <button className="scan-action-btn" onClick={() => { sendTo('intruder', selectedFinding.request_info?.method || 'GET', selectedFinding.url, ''); }}><Zap size={10} /> Intruder</button>
                    <button className="scan-action-btn" onClick={() => copyFinding(selectedFinding)}><Copy size={10} /> Copy</button>
                    <button className="scan-action-btn" onClick={() => loadFindings(selectedTask!)}><RefreshCcw size={10} /> Retest</button>
                  </div>
                </div>
              ) : (
                <div className="scan-finding-detail" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <div className="scan-empty"><ShieldAlert size={24} strokeWidth={1} /><span>Select a finding</span></div>
                </div>
              )}
              </>)}
            </div>
          </div>
        ) : (
          <div className="scan-findings-panel" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div className="scan-empty"><Radar size={32} strokeWidth={1} /><span>Select a scan to view findings</span></div>
          </div>
        )}
      </div>
    </div>
  );
}
