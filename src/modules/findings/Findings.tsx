import { useState, useEffect, useCallback } from 'react';
import { BookMarked, Search, Inbox, Download } from 'lucide-react';
import { useVisibilityAwareInterval } from '../../hooks/useVisibilityAwareInterval';
import './Findings.css';

interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'certain' | 'firm' | 'tentative';
  url: string;
  path: string;
  description: string;
  remediation: string;
  evidence: string;
  foundAt: string;
  status: 'new' | 'confirmed' | 'false_positive' | 'fixed';
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

export function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);

  useEffect(() => {
    let unlisten: (() => void) | undefined;

    (async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen<any>('scanner-finding', (event) => {
          const finding = event.payload as Finding;
          setFindings((prev) => {
            if (prev.find((f) => f.id === finding.id)) return prev;
            return [...prev, finding];
          });
        });
      } catch {}

      await pollFindings();
    })();

    return () => { unlisten?.(); };
  }, []);

  const pollFindings = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const scans: Array<{ id: string }> = await invoke('scanner_list_scans');
      for (const scan of scans) {
        try {
          const result: { findings: Finding[] } = await invoke('scanner_get_findings', { scanId: scan.id });
          if (result.findings && result.findings.length > 0) {
            setFindings((prev) => {
              const existing = new Set(prev.map(f => f.id));
              const newFindings = result.findings.filter(f => !existing.has(f.id));
              return newFindings.length > 0 ? [...prev, ...newFindings] : prev;
            });
          }
        } catch { /* scan may not have findings yet */ }
      }
    } catch { /* scanner not available */ }
  }, []);

  useVisibilityAwareInterval(pollFindings, 5000);

  const toggleSeverity = (s: string) => {
    setSeverityFilter((f) => f.includes(s) ? f.filter((x) => x !== s) : [...f, s]);
  };

  const filtered = findings.filter((f) => {
    if (filter && !f.title.toLowerCase().includes(filter.toLowerCase()) && !f.url.includes(filter)) return false;
    if (severityFilter.length > 0 && !severityFilter.includes(f.severity)) return false;
    return true;
  });

  const exportFindings = () => {
    const json = JSON.stringify(findings, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wondersuite-findings-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const updateStatus = (id: string, status: Finding['status']) => {
    setFindings((prev) => prev.map((f) => f.id === id ? { ...f, status } : f));
    if (selected?.id === id) {
      setSelected((s) => s ? { ...s, status } : s);
    }
  };

  return (
    <div className="findings">
      <div className="findings-toolbar">
        <Search size={14} style={{ color: 'var(--text-3)' }} />
        <input className="findings-filter" placeholder="Search findings..." value={filter} onChange={(e) => setFilter(e.target.value)} />
        {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
          <button key={s} className={`findings-severity-btn ${s} ${severityFilter.includes(s) ? 'active' : ''}`} onClick={() => toggleSeverity(s)}>
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        {findings.length > 0 && (
          <button className="findings-severity-btn" style={{ color: 'var(--text-1)' }} onClick={exportFindings}>
            <Download size={11} /> Export
          </button>
        )}
        <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{filtered.length} findings</span>
      </div>

      <div className="findings-body">
        <div className="findings-list">
          {filtered.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-3)', gap: 8 }}>
              <Inbox size={28} />
              <span style={{ fontSize: 12 }}>No findings yet</span>
              <span style={{ fontSize: 11 }}>Run a scan to discover vulnerabilities</span>
            </div>
          ) : (
            filtered.map((f) => (
              <div key={f.id} className={`findings-item ${selected?.id === f.id ? 'active' : ''}`} onClick={() => setSelected(f)}>
                <div className="findings-item-header">
                  <div className="findings-severity-dot" style={{ background: SEVERITY_COLORS[f.severity] }} />
                  <span className="findings-item-title">{f.title}</span>
                  <span className="findings-item-confidence">{f.confidence}</span>
                </div>
                <div className="findings-item-url">{f.path}</div>
                <div className="findings-item-meta">
                  <span>{f.url}</span>
                  <span className={`findings-status-badge ${f.status}`}>{f.status}</span>
                </div>
              </div>
            ))
          )}
        </div>

        {selected ? (
          <div className="findings-detail">
            <div className="findings-detail-title">{selected.title}</div>
            <div className="findings-detail-meta">
              <span className="findings-detail-badge" style={{ background: `${SEVERITY_COLORS[selected.severity]}20`, color: SEVERITY_COLORS[selected.severity] }}>
                {selected.severity.toUpperCase()}
              </span>
              <span className="findings-detail-badge" style={{ background: 'var(--bg-2)', color: 'var(--text-1)' }}>
                {selected.confidence}
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-2)', fontFamily: 'monospace' }}>{selected.path}</span>
              <div style={{ flex: 1 }} />
              <select
                value={selected.status}
                onChange={(e) => updateStatus(selected.id, e.target.value as Finding['status'])}
                style={{ fontSize: 10, background: 'var(--bg-2)', border: '1px solid var(--border-0)', color: 'var(--text-1)', borderRadius: 3, padding: '2px 6px' }}
              >
                <option value="new">New</option>
                <option value="confirmed">Confirmed</option>
                <option value="false_positive">False Positive</option>
                <option value="fixed">Fixed</option>
              </select>
            </div>

            <div className="findings-section">
              <h3>Description</h3>
              <p>{selected.description}</p>
            </div>

            <div className="findings-section">
              <h3>Evidence</h3>
              <div className="findings-evidence">{selected.evidence}</div>
            </div>

            <div className="findings-section">
              <h3>Remediation</h3>
              <p>{selected.remediation}</p>
            </div>
          </div>
        ) : (
          <div className="findings-empty">
            <BookMarked size={24} style={{ marginRight: 8 }} />
            {findings.length === 0 ? 'No findings — run a scan first' : 'Select a finding to view details'}
          </div>
        )}
      </div>
    </div>
  );
}
