import { useState, useEffect, useCallback } from 'react';
import {
  Activity,
  Repeat,
  Wrench,
  Inbox,
  Globe,
  Cpu,
  Shield,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import { useAppStore } from '../../stores';
import './Dashboard.css';

interface SystemInfo {
  arch: string;
  arch_display: string;
  os: string;
  os_version: string;
  is_arm: boolean;
  is_x64: boolean;
  cpu_cores: number;
  wondersuite_dir: string;
}

interface BrowserInfo {
  name: string;
  path: string;
  version: string;
  engine: string;
}

export function Dashboard() {
  const setModule = useAppStore((s) => s.setActiveModule);
  const [sysInfo, setSysInfo] = useState<SystemInfo | null>(null);
  const [browsers, setBrowsers] = useState<BrowserInfo[]>([]);
  const [proxyStatus, setProxyStatus] = useState<any>(null);
  const [browserLaunching, setBrowserLaunching] = useState(false);
  const [browserPid, setBrowserPid] = useState<number | null>(null);


  useEffect(() => {
    (async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
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
        const { invoke } = await import('@tauri-apps/api/core');
        setProxyStatus(await invoke<any>('proxy_status'));
      } catch {}
    }, 3000);
    return () => clearInterval(i);
  }, []);

  const launchBrowser = useCallback(async () => {
    setBrowserLaunching(true);
    try {
      const { invoke } = await import('@tauri-apps/api/core');

      // Auto-start proxy if not running
      if (!proxyStatus?.running) {
        await invoke('proxy_start', { port: 8080 });
      }

      const result = await invoke<any>('browser_launch', {
        browserName: null,
        proxyPort: 8080,
      });
      setBrowserPid(result.pid);
    } catch (e) {
      console.error('Browser launch error:', e);
    }
    setBrowserLaunching(false);
  }, [proxyStatus]);

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <button className="dashboard-browser-btn" onClick={launchBrowser} disabled={browserLaunching}>
          <Globe size={14} />
          {browserLaunching ? 'Launching...' : browserPid ? 'Open WonderBrowser' : 'Launch WonderBrowser'}
        </button>
      </div>

      <div className="dashboard-body">

        {sysInfo && (
          <div className="system-info-banner">
            <div className="system-info-item">
              <Cpu size={13} />
              <span className="system-info-label">Architecture</span>
              <span className={`system-info-value arch-badge ${sysInfo.is_arm ? 'arm' : 'x64'}`}>
                {sysInfo.arch_display}
              </span>
            </div>
            <div className="system-info-item">
              <span className="system-info-label">Windows</span>
              <span className="system-info-value">{sysInfo.os_version}</span>
            </div>
            <div className="system-info-item">
              <span className="system-info-label">Cores</span>
              <span className="system-info-value">{sysInfo.cpu_cores}</span>
            </div>
            <div className="system-info-item">
              <Shield size={13} />
              <span className="system-info-label">Proxy</span>
              <span className={`system-info-value ${proxyStatus?.running ? 'active' : ''}`}>
                {proxyStatus?.running ? `Active (:${proxyStatus.port})` : 'Off'}
              </span>
            </div>
            <div className="system-info-item">
              <Globe size={13} />
              <span className="system-info-label">Browsers</span>
              <span className="system-info-value">{browsers.length} detected</span>
            </div>
            <div className="system-info-item">
              <span className="system-info-label">OpenSSL</span>
              {proxyStatus?.has_openssl
                ? <span className="system-info-value active"><CheckCircle size={11} /> Ready</span>
                : <span className="system-info-value error"><XCircle size={11} /> Missing</span>
              }
            </div>
          </div>
        )}


        <div className="dashboard-grid">
          <div className="stat-card">
            <div className="stat-card-label">Requests</div>
            <div className="stat-card-value">{proxyStatus?.total_requests ?? 0}</div>
            <div className="stat-card-sub">{proxyStatus?.running ? 'Proxy active' : 'No traffic yet'}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Issues</div>
            <div className="stat-card-value">0</div>
            <div className="stat-card-sub">Nothing found</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Cached Certs</div>
            <div className="stat-card-value">{proxyStatus?.cached_certs ?? 0}</div>
            <div className="stat-card-sub">TLS identities</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Intercepted</div>
            <div className="stat-card-value">{proxyStatus?.pending_intercepts ?? 0}</div>
            <div className="stat-card-sub">{proxyStatus?.intercept_enabled ? 'Active' : 'Disabled'}</div>
          </div>
        </div>


        {browsers.length > 0 && (
          <div className="dashboard-section">
            <h2>Available Browsers</h2>
            <div className="browser-list">
              {browsers.map((b, i) => (
                <div key={i} className="browser-item">
                  <Globe size={14} className="browser-item-icon" />
                  <div className="browser-item-info">
                    <span className="browser-item-name">{b.name}</span>
                    <span className="browser-item-version">{b.version || 'Unknown version'}</span>
                  </div>
                  <span className="browser-item-engine">{b.engine}</span>
                </div>
              ))}
            </div>
          </div>
        )}


        <div className="dashboard-section">
          <h2>Quick Actions</h2>
          <div className="quick-actions">
            <button className="quick-action highlight" onClick={launchBrowser}>
              <div className="quick-action-icon"><Globe size={15} /></div>
              <div className="quick-action-text">
                <h3>WonderBrowser</h3>
                <p>Launch with proxy + CA</p>
              </div>
            </button>
            <button className="quick-action" onClick={() => setModule('replay')}>
              <div className="quick-action-icon"><Repeat size={15} /></div>
              <div className="quick-action-text">
                <h3>Send Request</h3>
                <p>HTTP client</p>
              </div>
            </button>
            <button className="quick-action" onClick={() => setModule('tools')}>
              <div className="quick-action-icon"><Wrench size={15} /></div>
              <div className="quick-action-text">
                <h3>Decoder</h3>
                <p>Encode / decode / hash</p>
              </div>
            </button>
            <button className="quick-action" onClick={() => setModule('traffic')}>
              <div className="quick-action-icon"><Activity size={15} /></div>
              <div className="quick-action-text">
                <h3>Traffic</h3>
                <p>View HTTP history</p>
              </div>
            </button>
          </div>
        </div>

        <div className="dashboard-section">
          <h2>Activity</h2>
          <div className="empty-state">
            <Inbox size={32} />
            <p>No recent activity</p>
          </div>
        </div>
      </div>
    </div>
  );
}
