import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppStore } from '../../stores';
import type { ModuleId } from '../../types';
import './Dashboard.css';

interface SystemInfo {
  arch: string;
  arch_display: string;
  os: string;
  os_version: string;
  is_arm: boolean;
  cpu_cores: number;
}

interface BrowserInfo {
  name: string;
  version: string;
  engine: string;
}

interface McpActivity {
  id: number;
  tool_name: string;
  category: string;
  params_summary: string;
  result_summary: string;
  status: string;
  duration_ms: number;
  timestamp: string;
  target_url: string;
}

export function Dashboard() {
  const setModule = useAppStore((s) => s.setActiveModule);
  const [sysInfo, setSysInfo] = useState<SystemInfo | null>(null);
  const [browsers, setBrowsers] = useState<BrowserInfo[]>([]);
  const [proxyStatus, setProxyStatus] = useState<any>(null);
  const [launching, setLaunching] = useState(false);
  const [browserPid, setBrowserPid] = useState<number | null>(null);
  const [activity, setActivity] = useState<McpActivity[]>([]);
  const [uptime, setUptime] = useState(0);

  useEffect(() => {
    (async () => {
      try {
        const [info, brs, status] = await Promise.all([
          invoke<SystemInfo>('get_system_info'),
          invoke<BrowserInfo[]>('browser_detect'),
          invoke<any>('proxy_status'),
        ]);
        setSysInfo(info);
        setBrowsers(brs);
        setProxyStatus(status);
      } catch {}
    })();
  }, []);

  useEffect(() => {
    const i = setInterval(async () => {
      try {
        const [status, act] = await Promise.all([
          invoke<any>('proxy_status'),
          invoke<McpActivity[]>('get_mcp_activity', { sinceId: 0 }).catch(() => []),
        ]);
        setProxyStatus(status);
        if (Array.isArray(act)) setActivity(act.slice(0, 20));
      } catch {}
    }, 2000);
    return () => clearInterval(i);
  }, []);

  useEffect(() => {
    const start = Date.now();
    const i = setInterval(() => setUptime(Math.floor((Date.now() - start) / 1000)), 1000);
    return () => clearInterval(i);
  }, []);

  const launchBrowser = useCallback(async () => {
    setLaunching(true);
    try {
      if (!proxyStatus?.running) await invoke('proxy_start', { port: 8080 });
      const r = await invoke<any>('browser_launch', { browserName: null, proxyPort: 8080 });
      setBrowserPid(r.pid);
    } catch (e) { console.error(e); }
    setLaunching(false);
  }, [proxyStatus]);

  const fmt = (s: number) => {
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
  };

  const successCalls = activity.filter(a => a.status === 'success').length;
  const errorCalls = activity.filter(a => a.status === 'error').length;

  return (
    <div className="dashboard">

      {/* ─── Header Strip ─── */}
      <div className="dash-header">
        <div className="dash-title">
          <span>Dashboard</span>
        </div>
        <div className="dash-header-right">
          <span className="dash-uptime">{fmt(uptime)}</span>
          <button className="dash-launch-btn" onClick={launchBrowser} disabled={launching}>
            {launching ? 'Starting…' : browserPid ? 'Browser Open' : 'Launch Browser'}
          </button>
        </div>
      </div>

      <div className="dash-body">

        {/* ─── Status Bar ─── */}
        <div className="dash-status-bar">
          <div className="dash-status-item">
            <span className="dash-status-dot" data-active={proxyStatus?.running ? 'true' : 'false'} />
            <span className="dash-status-label">Proxy</span>
            <span className="dash-status-val">{proxyStatus?.running ? `:${proxyStatus.port}` : 'Off'}</span>
          </div>
          {sysInfo && (
            <>
              <div className="dash-status-sep" />
              <div className="dash-status-item">
                <span className="dash-status-label">Arch</span>
                <span className="dash-status-val">{sysInfo.arch_display}</span>
              </div>
              <div className="dash-status-sep" />
              <div className="dash-status-item">
                <span className="dash-status-label">Cores</span>
                <span className="dash-status-val">{sysInfo.cpu_cores}</span>
              </div>
              <div className="dash-status-sep" />
              <div className="dash-status-item">
                <span className="dash-status-label">OS</span>
                <span className="dash-status-val">{sysInfo.os_version}</span>
              </div>
            </>
          )}
          <div className="dash-status-sep" />
          <div className="dash-status-item">
            <span className="dash-status-label">Browsers</span>
            <span className="dash-status-val">{browsers.length}</span>
          </div>
          <div className="dash-status-sep" />
          <div className="dash-status-item">
            <span className="dash-status-label">MCP Tools</span>
            <span className="dash-status-val accent">66</span>
          </div>
        </div>

        {/* ─── Metrics Row ─── */}
        <div className="dash-metrics">
          <div className="dash-metric">
            <span className="dash-metric-num">{proxyStatus?.total_requests ?? 0}</span>
            <span className="dash-metric-label">Requests</span>
          </div>
          <div className="dash-metric">
            <span className="dash-metric-num">{proxyStatus?.pending_intercepts ?? 0}</span>
            <span className="dash-metric-label">Intercepted</span>
          </div>
          <div className="dash-metric">
            <span className="dash-metric-num">{successCalls}</span>
            <span className="dash-metric-label">Scans OK</span>
          </div>
          <div className="dash-metric">
            <span className="dash-metric-num err">{errorCalls}</span>
            <span className="dash-metric-label">Errors</span>
          </div>
          <div className="dash-metric">
            <span className="dash-metric-num">{activity.length}</span>
            <span className="dash-metric-label">MCP Calls</span>
          </div>
        </div>

        {/* ─── Two-col content ─── */}
        <div className="dash-columns">

          {/* Left */}
          <div className="dash-col">

            {/* Navigation */}
            <div className="dash-panel">
              <div className="dash-panel-title">Modules</div>
              <div className="dash-nav-grid">
                {[
                  { id: 'intercept', label: 'Intercept', desc: 'MITM proxy' },
                  { id: 'traffic', label: 'HTTP History', desc: 'Request log' },
                  { id: 'replay', label: 'Repeater', desc: 'Replay & edit' },
                  { id: 'attack', label: 'Intruder', desc: 'Fuzzing engine' },
                  { id: 'scan', label: 'Scanner', desc: 'Active scan' },
                  { id: 'discovery', label: 'Discovery', desc: 'Dirs & subs' },
                  { id: 'osint', label: 'OSINT', desc: 'DNS, WHOIS, ASN' },
                  { id: 'oast', label: 'OAST', desc: 'Blind callbacks' },
                  { id: 'websocket', label: 'WebSocket', desc: 'WS testing' },
                  { id: 'tokens', label: 'Decoder', desc: 'Encode/decode' },
                  { id: 'session', label: 'Session', desc: 'Cookie mgmt' },
                  { id: 'agent', label: 'Agent', desc: 'AI assistant' },
                ].map(m => (
                  <button key={m.id} className="dash-nav-item" onClick={() => setModule(m.id as ModuleId)}>
                    <span className="dash-nav-name">{m.label}</span>
                    <span className="dash-nav-desc">{m.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Payload Arsenal */}
            <div className="dash-panel">
              <div className="dash-panel-title">Payload Arsenal — 157,280 loaded</div>
              <div className="dash-payload-grid">
                {[
                  { name: 'XSS', n: '19.8k' }, { name: 'Fuzzing', n: '72k' },
                  { name: 'Traversal', n: '23k' }, { name: 'Auth', n: '21k' },
                  { name: 'CMDi', n: '9.3k' }, { name: 'LFI', n: '8k' },
                  { name: 'SQLi', n: '1.9k' }, { name: 'Open Redirect', n: '325' },
                  { name: 'XXE', n: '225' }, { name: 'SSTI', n: '118' },
                  { name: 'NoSQL', n: '46' }, { name: 'SSRF', n: '36' },
                ].map(p => (
                  <div key={p.name} className="dash-payload-item">
                    <span>{p.name}</span>
                    <span className="dash-payload-num">{p.n}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right: Activity Feed */}
          <div className="dash-col">
            <div className="dash-panel dash-panel-fill">
              <div className="dash-panel-title">
                Live Activity
                <span className="dash-badge">{activity.length}</span>
              </div>
              <div className="dash-activity-list">
                {activity.length === 0 ? (
                  <div className="dash-empty">No MCP activity yet — tool calls appear here in real-time</div>
                ) : (
                  activity.map(a => (
                    <div key={a.id} className={`dash-activity-row ${a.status}`}>
                      <span className="dash-act-time">{a.timestamp}</span>
                      <span className={`dash-act-cat ${a.category}`}>{a.category}</span>
                      <span className="dash-act-tool">{a.tool_name}</span>
                      <span className={`dash-act-status ${a.status}`}>
                        {a.status === 'success' ? '✓' : a.status === 'error' ? '✗' : '…'}
                      </span>
                      <span className="dash-act-summary">{a.params_summary || a.result_summary}</span>
                      <span className="dash-act-dur">
                        {a.duration_ms === 0 ? '—' : a.duration_ms < 1000 ? `${a.duration_ms}ms` : `${(a.duration_ms/1000).toFixed(1)}s`}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Browsers */}
            {browsers.length > 0 && (
              <div className="dash-panel">
                <div className="dash-panel-title">Detected Browsers</div>
                <div className="dash-browser-list">
                  {browsers.map((b, i) => (
                    <div key={i} className="dash-browser-row">
                      <span className="dash-browser-name">{b.name}</span>
                      <span className="dash-browser-ver">{b.version || '—'}</span>
                      <span className="dash-browser-engine">{b.engine}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
