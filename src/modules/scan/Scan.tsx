import { useState, useEffect, useRef, useCallback } from 'react';
import { Play, Radar, ShieldAlert, Trash2, Settings2, Download, FileText, RefreshCcw, ExternalLink, ChevronDown, ChevronRight } from 'lucide-react';
import { useAppStore } from '../../stores';
import './Scan.css';

interface ScanTask {
  id: string;
  target: string;
  type: string;
  status: string;
  progress: number;
  requests: number;
  findingCount: number;
  elapsedMs: number;
  startedAt: string;
  technologies: string[];
}

interface ScanFinding {
  id: string;
  finding_type: string;
  name: string;
  severity: string;
  confidence: string;
  url: string;
  parameter?: string;
  payload?: string;
  evidence?: string;
  detail: string;
  remediation: string;
  request_info?: {
    method: string;
    url: string;
    request_headers: string[];
    request_body?: string;
    response_status: number;
    response_headers: string[];
    response_body_preview: string;
    response_time_ms: number;
    response_size: number;
  };
}

type ScanCheck = { key: string; label: string; enabled: boolean };

const DEFAULT_CHECKS: ScanCheck[] = [
  { key: 'check_sqli', label: 'SQL Injection', enabled: true },
  { key: 'check_xss', label: 'Cross-Site Scripting', enabled: true },
  { key: 'check_ssrf', label: 'Server-Side Request Forgery', enabled: true },
  { key: 'check_ssti', label: 'Server-Side Template Injection', enabled: true },
  { key: 'check_xxe', label: 'XML External Entity', enabled: true },
  { key: 'check_path_traversal', label: 'Path Traversal / LFI', enabled: true },
  { key: 'check_command_injection', label: 'OS Command Injection', enabled: true },
  { key: 'check_open_redirect', label: 'Open Redirect', enabled: true },
  { key: 'check_cors', label: 'CORS Misconfiguration', enabled: true },
  { key: 'check_headers', label: 'Security Headers', enabled: true },
  { key: 'check_cookies', label: 'Cookie Flags', enabled: true },
  { key: 'check_info_disclosure', label: 'Information Disclosure', enabled: true },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626', high: '#ef4444', medium: '#f0c040', low: '#64b4ff', info: 'var(--text-3)',
};

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function Scan() {
  const [target, setTarget] = useState('https://');
  const [scanType, setScanType] = useState('crawl_and_audit');
  const [showConfig, setShowConfig] = useState(false);
  const [checks, setChecks] = useState<ScanCheck[]>(DEFAULT_CHECKS);
  const [maxRequests, setMaxRequests] = useState(500);
  const [maxDepth, setMaxDepth] = useState(3);
  const [followRedirects, setFollowRedirects] = useState(true);

  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [selectedTask, setSelectedTask] = useState<string | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<ScanFinding | null>(null);
  const [showEvidence, setShowEvidence] = useState(false);
  const [sevFilter, setSevFilter] = useState<string>('all');

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const { sendTo, openContextMenu } = useAppStore();

  // Start active scan
  const startScan = useCallback(async () => {
    if (!target || target === 'https://') return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const config: Record<string, unknown> = {
        max_depth: maxDepth,
        max_requests: maxRequests,
        follow_redirects: followRedirects,
        auto_crawl: true,
        crawl_depth: 2,
        timeout_ms: 10000,
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WonderSuite/1.0',
      };
      for (const c of checks) {
        config[c.key] = c.enabled;
      }

      const scanId: string = await invoke('scanner_start_active', { target, config });
      const task: ScanTask = {
        id: scanId, target, type: scanType, status: 'running', progress: 0,
        requests: 0, findingCount: 0, elapsedMs: 0, startedAt: new Date().toISOString(), technologies: [],
      };
      setTasks(t => [task, ...t]);
      setSelectedTask(scanId);
      startPolling(scanId);
    } catch (err) {
      console.error('Scan start failed:', err);
    }
  }, [target, scanType, checks, maxRequests, maxDepth, followRedirects]);

  const startPolling = (scanId: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const status: { scan_id: string; status: string; progress: number; total_requests: number; finding_count: number; elapsed_ms: number } =
          await invoke('scanner_status', { scanId });
        setTasks(prev => prev.map(t => t.id === scanId ? {
          ...t, status: status.status, progress: status.progress,
          requests: status.total_requests, findingCount: status.finding_count, elapsedMs: status.elapsed_ms,
        } : t));
        if (status.status !== 'running') {
          clearInterval(pollRef.current!);
          pollRef.current = null;
          loadFindings(scanId);
        }
      } catch { /* scan may not be ready */ }
    }, 1000);
  };

  const loadFindings = async (scanId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const result: { findings: ScanFinding[]; technologies: string[] } =
        await invoke('scanner_get_findings', { scanId, severityFilter: null });
      setFindings(result.findings || []);
      setTasks(prev => prev.map(t => t.id === scanId ? {
        ...t, findingCount: (result.findings || []).length, technologies: result.technologies || [],
      } : t));
    } catch (err) { console.error(err); }
  };

  const deleteScan = async (id: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('scanner_delete_scan', { scanId: id });
    } catch { /* ignore */ }
    setTasks(prev => prev.filter(t => t.id !== id));
    if (selectedTask === id) { setSelectedTask(null); setFindings([]); }
  };

  const generateReport = async (format: string) => {
    if (!selectedTask) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const report: string = await invoke('scanner_generate_report', { scanId: selectedTask, format });
      const blob = new Blob([report], { type: format === 'json' ? 'application/json' : 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url;
      a.download = `wondersuite-report-${Date.now()}.${format === 'json' ? 'json' : 'html'}`;
      a.click();
    } catch (err) { console.error(err); }
  };

  const sendToRepeater = (finding: ScanFinding) => {
    const url = finding.request_info?.url || finding.url;
    const method = finding.request_info?.method || 'GET';
    const raw = finding.request_info
      ? `${method} ${url} HTTP/1.1\n${finding.request_info.request_headers.join('\n')}${finding.request_info.request_body ? '\n\n' + finding.request_info.request_body : ''}`
      : `GET ${url} HTTP/1.1\nHost: ${new URL(url).hostname}`;
    sendTo('repeater', method, url, raw);
  };

  const handleContextMenu = (e: React.MouseEvent, finding: ScanFinding) => {
    e.preventDefault();
    const url = finding.request_info?.url || finding.url;
    const method = finding.request_info?.method || 'GET';
    const requestRaw = finding.request_info
      ? `${method} ${url} HTTP/1.1\n${finding.request_info.request_headers.join('\n')}${finding.request_info.request_body ? '\n\n' + finding.request_info.request_body : ''}`
      : `GET ${url} HTTP/1.1\nHost: ${new URL(url).hostname}`;
    
    const responseRaw = finding.request_info?.response_headers 
      ? `HTTP/1.1 ${finding.request_info.response_status} OK\n${finding.request_info.response_headers.join('\n')}\n\n${finding.request_info.response_body_preview || ''}`
      : undefined;

    openContextMenu(e.clientX, e.clientY, { method, url, requestRaw, responseRaw });
  };

  useEffect(() => {
    if (selectedTask) loadFindings(selectedTask);
  }, [selectedTask]);

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const activeTask = tasks.find(t => t.id === selectedTask);
  const filteredFindings = findings
    .filter(f => sevFilter === 'all' || f.severity === sevFilter)
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));

  const sevCounts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  };

  const toggleCheck = (key: string) => {
    setChecks(prev => prev.map(c => c.key === key ? { ...c, enabled: !c.enabled } : c));
  };

  return (
    <div className="scan">
      <div className="scan-toolbar">
        <Radar size={14} />
        <span className="scan-toolbar-title">Active Scanner</span>
        <div style={{ flex: 1 }} />
        <input className="scan-target-input" value={target} onChange={e => setTarget(e.target.value)}
          placeholder="https://target.example.com" onKeyDown={e => e.key === 'Enter' && startScan()} />
        <select className="scan-type-select" value={scanType} onChange={e => setScanType(e.target.value)}>
          <option value="crawl_and_audit">Crawl & Audit</option>
          <option value="passive_audit">Passive Audit</option>
          <option value="owasp_top10">OWASP Top 10</option>
          <option value="lightweight">Lightweight</option>
        </select>
        <button className="scan-config-btn" onClick={() => setShowConfig(!showConfig)} title="Scan Configuration">
          <Settings2 size={10} />
        </button>
        <button className="scan-start-btn" onClick={startScan}><Play size={10} /> Scan</button>
      </div>

      {showConfig && (
        <div className="scan-config-panel">
          <div className="scan-config-section">
            <span className="scan-config-title">Scan Checks</span>
            <div className="scan-config-checks-grid">
              {checks.map(c => (
                <label key={c.key} className="scan-config-check">
                  <input type="checkbox" checked={c.enabled} onChange={() => toggleCheck(c.key)} />
                  {c.label}
                </label>
              ))}
            </div>
          </div>
          <div className="scan-config-section">
            <span className="scan-config-title">Options</span>
            <div className="scan-config-options">
              <div className="scan-config-row"><label>Max Requests</label><input type="number" value={maxRequests} onChange={e => setMaxRequests(Number(e.target.value))} /></div>
              <div className="scan-config-row"><label>Crawl Depth</label><input type="number" value={maxDepth} onChange={e => setMaxDepth(Number(e.target.value))} /></div>
              <label className="scan-config-check"><input type="checkbox" checked={followRedirects} onChange={e => setFollowRedirects(e.target.checked)} /> Follow Redirects</label>
            </div>
          </div>
        </div>
      )}

      <div className="scan-body">
        {/* Scan History */}
        <div className="scan-task-list">
          {tasks.length === 0 ? (
            <div className="scan-empty">
              <Radar size={28} strokeWidth={1} />
              <span>No scans yet</span>
              <span className="scan-empty-sub">Enter a target URL and start the active scanner</span>
            </div>
          ) : tasks.map(task => (
            <div key={task.id} className={`scan-task ${selectedTask === task.id ? 'selected' : ''}`}
              onClick={() => setSelectedTask(task.id)}>
              <div className="scan-task-top">
                <div className={`scan-task-dot ${task.status === 'running' ? 'running' : task.status.startsWith('error') ? 'failed' : 'completed'}`} />
                <span className="scan-task-target">{task.target}</span>
                <button className="scan-task-del" onClick={e => { e.stopPropagation(); deleteScan(task.id); }}><Trash2 size={9} /></button>
              </div>
              <div className="scan-task-progress-bar"><div className="scan-task-progress-fill" style={{ width: `${task.progress}%` }} /></div>
              <div className="scan-task-meta">
                <span>{Math.round(task.progress)}%</span>
                <span>{task.requests} req</span>
                <span className={task.findingCount > 0 ? 'scan-has-findings' : ''}>{task.findingCount} findings</span>
                {task.elapsedMs > 0 && <span>{(task.elapsedMs / 1000).toFixed(1)}s</span>}
              </div>
              {task.technologies.length > 0 && (
                <div className="scan-task-techs">
                  {task.technologies.slice(0, 5).map(t => <span key={t} className="scan-tech-badge">{t}</span>)}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Findings Panel */}
        {activeTask ? (
          <div className="scan-findings-panel">
            <div className="scan-findings-header">
              <ShieldAlert size={12} />
              <span>Findings — {activeTask.target}</span>
              <div className="scan-sev-pills">
                <button className={`scan-sev-pill ${sevFilter === 'all' ? 'active' : ''}`} onClick={() => setSevFilter('all')}>All ({findings.length})</button>
                {Object.entries(sevCounts).filter(([, v]) => v > 0).map(([sev, count]) => (
                  <button key={sev} className={`scan-sev-pill ${sevFilter === sev ? 'active' : ''}`}
                    style={{ '--pill-color': SEVERITY_COLORS[sev] } as React.CSSProperties}
                    onClick={() => setSevFilter(sev)}>
                    {sev[0].toUpperCase()} ({count})
                  </button>
                ))}
              </div>
              <div style={{ flex: 1 }} />
              <button className="scan-action-btn" onClick={() => generateReport('html')} title="Download HTML Report"><FileText size={10} /> HTML</button>
              <button className="scan-action-btn" onClick={() => generateReport('json')} title="Download JSON Report"><Download size={10} /> JSON</button>
            </div>

            <div className="scan-findings-body">
              <div className="scan-findings-list">
                {filteredFindings.map(f => (
                  <div key={f.id} className={`scan-finding ${selectedFinding?.id === f.id ? 'selected' : ''}`}
                    onClick={() => { setSelectedFinding(f); setShowEvidence(false); }}
                    onContextMenu={(e) => handleContextMenu(e, f)}>
                    <span className="scan-finding-sev" style={{ background: SEVERITY_COLORS[f.severity] }}>
                      {f.severity[0].toUpperCase()}
                    </span>
                    <span className="scan-finding-name">{f.name}</span>
                    {f.parameter && <span className="scan-finding-param">{f.parameter}</span>}
                    <span className="scan-finding-conf">{f.confidence}</span>
                  </div>
                ))}
                {filteredFindings.length === 0 && (
                  <div className="scan-empty" style={{ padding: 20 }}>
                    <span style={{ fontSize: 11, color: 'var(--text-3)' }}>
                      {findings.length === 0 ? (activeTask.status === 'running' ? 'Scanning...' : 'No findings') : 'No findings match filter'}
                    </span>
                  </div>
                )}
              </div>

              {selectedFinding && (
                <div className="scan-finding-detail">
                  <div className="scan-finding-detail-header">
                    <span className="scan-finding-detail-sev" style={{ color: SEVERITY_COLORS[selectedFinding.severity] }}>
                      {selectedFinding.severity.toUpperCase()}
                    </span>
                    <span className="scan-finding-detail-name">{selectedFinding.name}</span>
                    <span className="scan-finding-detail-conf">{selectedFinding.confidence}</span>
                  </div>
                  <div className="scan-finding-detail-url">{selectedFinding.url}</div>

                  {selectedFinding.parameter && (
                    <div className="scan-finding-detail-section">
                      <label>Parameter</label>
                      <p className="scan-mono">{selectedFinding.parameter}</p>
                    </div>
                  )}
                  {selectedFinding.payload && (
                    <div className="scan-finding-detail-section">
                      <label>Payload</label>
                      <pre className="scan-evidence-pre">{selectedFinding.payload}</pre>
                    </div>
                  )}
                  <div className="scan-finding-detail-section">
                    <label>Detail</label>
                    <p style={{ whiteSpace: 'pre-wrap' }}>{selectedFinding.detail}</p>
                  </div>
                  {selectedFinding.evidence && (
                    <div className="scan-finding-detail-section scan-evidence">
                      <label onClick={() => setShowEvidence(!showEvidence)} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                        {showEvidence ? <ChevronDown size={10} /> : <ChevronRight size={10} />} Evidence
                      </label>
                      {showEvidence && <pre className="scan-evidence-pre">{selectedFinding.evidence}</pre>}
                    </div>
                  )}
                  {selectedFinding.remediation && (
                    <div className="scan-finding-detail-section scan-remediation">
                      <label>Remediation</label>
                      <p style={{ whiteSpace: 'pre-wrap' }}>{selectedFinding.remediation}</p>
                    </div>
                  )}

                  {selectedFinding.request_info && (
                    <div className="scan-finding-detail-section">
                      <label>Request / Response</label>
                      <div className="scan-req-resp">
                        <div className="scan-req-panel">
                          <span className="scan-req-title">Request</span>
                          <pre className="scan-evidence-pre">{selectedFinding.request_info.method} {selectedFinding.request_info.url}{'\n'}{selectedFinding.request_info.request_headers.join('\n')}{selectedFinding.request_info.request_body ? '\n\n' + selectedFinding.request_info.request_body : ''}</pre>
                        </div>
                        <div className="scan-req-panel">
                          <span className="scan-req-title">Response ({selectedFinding.request_info.response_status}) — {selectedFinding.request_info.response_time_ms}ms — {selectedFinding.request_info.response_size}B</span>
                          <pre className="scan-evidence-pre">{selectedFinding.request_info.response_headers.join('\n')}{'\n\n'}{selectedFinding.request_info.response_body_preview}</pre>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="scan-finding-actions">
                    <button className="scan-action-btn" onClick={() => sendToRepeater(selectedFinding)}>
                      <ExternalLink size={10} /> Send to Repeater
                    </button>
                    <button className="scan-action-btn" onClick={() => loadFindings(selectedTask!)}>
                      <RefreshCcw size={10} /> Retest
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="scan-findings-panel" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div className="scan-empty">
              <Radar size={32} strokeWidth={1} />
              <span>Select a scan to view findings</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
