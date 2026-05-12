import { useState, useEffect, useCallback, useRef } from 'react';
import { ChevronRight } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import { useAppStore } from '../../stores';
import { useVisibilityAwareInterval } from '../../hooks/useVisibilityAwareInterval';
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
  const [payloadStats, setPayloadStats] = useState<{ name: string; n: string; downloaded: boolean }[]>([]);
  const [payloadTotal, setPayloadTotal] = useState<number>(0);
  const [mcpToolCount, setMcpToolCount] = useState<number>(0);
  const [portConflict, setPortConflict] = useState<null | {
    role: string;
    port: number;
    holders: { pid: number; name: string; command: string; addr: string }[];
  }>(null);
  const [killingPid, setKillingPid] = useState<number | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [info, brs, status, payloads, tools] = await Promise.all([
          invoke<SystemInfo>('get_system_info'),
          invoke<BrowserInfo[]>('browser_detect'),
          invoke<any>('proxy_status'),
          invoke<any>('payload_list_categories').catch(() => null),
          invoke<Array<{ name: string }>>('mcp_list_tools').catch(() => [] as Array<{ name: string }>),
        ]);
        setSysInfo(info);
        setBrowsers(brs);
        setProxyStatus(status);
        setMcpToolCount(tools.length);
        if (payloads?.categories) {
          const fmt = (n: number): string => n >= 1000 ? `${(n/1000).toFixed(n >= 10000 ? 0 : 1)}k` : `${n}`;
          setPayloadStats(payloads.categories.map((c: any) => ({
            name: c.name.replace(/_/g, ' ').toUpperCase(),
            n: c.downloaded ? fmt(c.total_payloads) : '—',
            downloaded: c.downloaded,
          })));
          setPayloadTotal(payloads.total_payloads);
        }
      } catch {}
    })();
  }, []);

  const pollDashboard = useCallback(async () => {
    try {
      const [status, act] = await Promise.all([
        invoke<any>('proxy_status'),
        invoke<McpActivity[]>('get_mcp_activity', { sinceId: 0 }).catch(() => []),
      ]);
      setProxyStatus(status);
      if (Array.isArray(act)) setActivity(act.slice(0, 20));
    } catch {}
  }, []);

  useVisibilityAwareInterval(pollDashboard, 2000);

  const startRef = useRef(Date.now());
  const pollUptime = useCallback(() => {
    setUptime(Math.floor((Date.now() - startRef.current) / 1000));
  }, []);

  useVisibilityAwareInterval(pollUptime, 1000);

  const launchBrowser = useCallback(async () => {
    setLaunching(true);
    try {
      if (!proxyStatus?.running) await invoke('proxy_start', { port: 8080 });
      const preferSystem = localStorage.getItem('ws_prefer_system_browser') === '1';
      const noSandbox = localStorage.getItem('ws_browser_no_sandbox') === '1';
      const tlsImpersonate = localStorage.getItem('ws_tls_impersonate') !== '0';
      try { await invoke('proxy_set_tls_impersonate', { enabled: tlsImpersonate }); } catch {}
      const r = await invoke<any>('browser_launch', {
        browserName: null,
        proxyPort: 8080,
        preferSystemBrowser: preferSystem,
        noSandbox,
      });
      setBrowserPid(r.pid);
    } catch (e: any) {
      const msg = typeof e === 'string' ? e : (e?.toString?.() ?? '');
      try {
        const parsed = JSON.parse(msg);
        if (parsed?.kind === 'port_in_use') {
          setPortConflict({
            role: parsed.role || 'port',
            port: parsed.port,
            holders: parsed.holders || [],
          });
        } else {
          console.error(e);
        }
      } catch {
        console.error(e);
      }
    }
    setLaunching(false);
  }, [proxyStatus]);

  const killHolder = useCallback(async (pid: number) => {
    setKillingPid(pid);
    try {
      await invoke('kill_process', { pid });
      await new Promise(r => setTimeout(r, 300));
      setPortConflict(null);
      setKillingPid(null);
      launchBrowser();
    } catch (e) {
      console.error(e);
      setKillingPid(null);
    }
  }, [launchBrowser]);

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
            <span className="dash-status-val accent">{mcpToolCount || '—'}</span>
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
              <div className="dash-panel-title">
                Payload Arsenal — {payloadTotal > 0 ? `${payloadTotal.toLocaleString()} loaded` : 'not downloaded'}
                <button
                  className="dash-panel-action"
                  onClick={() => setModule('payloads')}
                  title="Open Payloads module">
                  {payloadTotal > 0 ? 'Manage' : 'Download'}
                  <ChevronRight size={11} />
                </button>
              </div>
              <div className="dash-payload-grid">
                {payloadStats.length === 0 ? (
                  <div className="dash-empty" style={{ gridColumn: '1 / -1' }}>
                    Open <b>Payloads</b> and click "Download All" to pull SecLists + PayloadsAllTheThings.
                  </div>
                ) : (
                  payloadStats.map(p => (
                    <div key={p.name} className={`dash-payload-item ${!p.downloaded ? 'dim' : ''}`}>
                      <span>{p.name}</span>
                      <span className="dash-payload-num">{p.n}</span>
                    </div>
                  ))
                )}
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

      {portConflict && (
        <div className="dash-modal-overlay" onClick={() => setPortConflict(null)}>
          <div className="dash-modal" onClick={e => e.stopPropagation()}>
            <div className="dash-modal-head">
              <strong>Port {portConflict.port} ({portConflict.role}) is already in use</strong>
              <button className="dash-modal-x" onClick={() => setPortConflict(null)}>×</button>
            </div>
            <p className="dash-modal-msg">
              {portConflict.holders.length === 0
                ? 'Could not identify which process is holding the port. Close other apps that may be using it and retry.'
                : `WonderSuite needs port ${portConflict.port} to launch the browser. The process${portConflict.holders.length > 1 ? 'es' : ''} listed below currently hold${portConflict.holders.length > 1 ? '' : 's'} it. You can terminate ${portConflict.holders.length > 1 ? 'them' : 'it'} and retry.`}
            </p>
            {portConflict.holders.length > 0 && (
              <div className="dash-modal-holders">
                {portConflict.holders.map(h => (
                  <div key={h.pid} className="dash-modal-holder">
                    <div className="dash-modal-holder-info">
                      <span className="dash-modal-holder-name">{h.name || '(unknown)'}</span>
                      <span className="dash-modal-holder-meta">PID {h.pid} · {h.addr}</span>
                    </div>
                    <button
                      className="dash-modal-kill"
                      disabled={killingPid !== null}
                      onClick={() => killHolder(h.pid)}>
                      {killingPid === h.pid ? 'Killing…' : 'Terminate'}
                    </button>
                  </div>
                ))}
              </div>
            )}
            <div className="dash-modal-foot">
              <button className="dash-modal-btn-secondary" onClick={() => setPortConflict(null)}>Close</button>
              <button className="dash-modal-btn-primary" onClick={() => { setPortConflict(null); launchBrowser(); }}>
                Retry
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
