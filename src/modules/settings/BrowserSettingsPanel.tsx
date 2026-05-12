import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Globe, Download, RefreshCw, CheckCircle, AlertTriangle, FolderOpen, Shield, Trash2,
} from 'lucide-react';
import { useAppStore } from '../../stores';
import './BrowserSettingsPanel.css';

interface ChromiumStatus {
  version: string;
  cached: boolean;
  cache_dir: string;
  disk_bytes: number;
}

interface MigrationReport {
  profile_migrated: boolean;
  legacy_profile_path: string | null;
  new_profile_path: string;
  legacy_ca_present: boolean;
  legacy_ca_subject: string | null;
  notes: string[];
}

function fmtBytes(n: number): string {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function BrowserSettingsPanel() {
  const { addToast } = useAppStore();
  const [status, setStatus] = useState<ChromiumStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [busyReinstall, setBusyReinstall] = useState(false);
  const [preferSystem, setPreferSystem] = useState<boolean>(
    () => localStorage.getItem('ws_prefer_system_browser') === '1',
  );
  const [noSandbox, setNoSandbox] = useState<boolean>(
    () => localStorage.getItem('ws_browser_no_sandbox') === '1',
  );
  const [tlsImpersonate, setTlsImpersonate] = useState<boolean>(
    () => localStorage.getItem('ws_tls_impersonate') !== '0',  // default ON
  );
  // MCP browser visible by default — user can intervene on captchas etc.
  const [mcpHeadless, setMcpHeadless] = useState<boolean>(
    () => localStorage.getItem('ws_mcp_browser_headless') === '1',
  );

  const [migration, setMigration] = useState<MigrationReport | null>(null);
  const [busyCa, setBusyCa] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const s = await invoke<ChromiumStatus>('chromium_status');
      setStatus(s);
    } catch (e: any) {
      addToast({ title: 'Browser', message: `Status check failed: ${e}`, type: 'error' });
    } finally {
      setLoading(false);
    }
    try {
      const r = await invoke<MigrationReport>('browser_migration_check');
      setMigration(r);
      if (r.profile_migrated) {
        addToast({
          title: 'Browser migration',
          message: `Moved legacy profile to ${r.new_profile_path}`,
          type: 'success',
        });
      }
    } catch {}

    // Sync the toggle UI with the backend's actual tls_impersonate state.
    // Backend default is true; localStorage may be stale across restarts.
    // Source of truth = localStorage; we push it to backend on every mount
    // so a freshly-launched proxy gets the user's intended setting.
    try {
      const want = localStorage.getItem('ws_tls_impersonate') !== '0';
      const current = await invoke<boolean>('proxy_get_tls_impersonate');
      if (current !== want) {
        await invoke('proxy_set_tls_impersonate', { enabled: want });
      }
      setTlsImpersonate(want);
    } catch {}

    // Sync MCP-browser-headless preference to backend on every mount.
    try {
      const want = localStorage.getItem('ws_mcp_browser_headless') === '1';
      const current = await invoke<boolean>('mcp_browser_get_headless');
      if (current !== want) {
        await invoke('mcp_browser_set_headless', { headless: want });
      }
      setMcpHeadless(want);
    } catch {}
  }, [addToast]);

  const removeLegacyCa = async () => {
    if (busyCa) return;
    if (!confirm(
      'Remove the legacy WonderSuite CA?\n\n' +
      'WonderSuite v0.2.0 no longer needs a CA in the OS trust store ' +
      '(WonderBrowser uses --ignore-certificate-errors instead).\n\n' +
      'External browsers that relied on the trusted CA will need to import a fresh one from the proxy.'
    )) return;
    setBusyCa(true);
    try {
      await invoke('browser_migration_remove_ca');
      addToast({ title: 'Browser', message: 'Legacy CA removed.', type: 'success' });
      const r = await invoke<MigrationReport>('browser_migration_check');
      setMigration(r);
    } catch (e: any) {
      addToast({ title: 'Browser', message: `CA removal failed: ${e}`, type: 'error' });
    } finally {
      setBusyCa(false);
    }
  };

  useEffect(() => {
    refresh();
  }, [refresh]);

  const toggleSystem = (next: boolean) => {
    setPreferSystem(next);
    if (next) localStorage.setItem('ws_prefer_system_browser', '1');
    else localStorage.removeItem('ws_prefer_system_browser');
  };

  const toggleNoSandbox = (next: boolean) => {
    setNoSandbox(next);
    if (next) localStorage.setItem('ws_browser_no_sandbox', '1');
    else localStorage.removeItem('ws_browser_no_sandbox');
  };

  const toggleMcpHeadless = async (next: boolean) => {
    setMcpHeadless(next);
    if (next) localStorage.setItem('ws_mcp_browser_headless', '1');
    else localStorage.removeItem('ws_mcp_browser_headless');
    try {
      await invoke('mcp_browser_set_headless', { headless: next });
      addToast({
        title: 'MCP browser',
        message: next
          ? 'Headless — agent runs the browser invisibly'
          : 'Visible — window stays open so you can step in on captchas',
        type: 'success',
      });
    } catch (e: any) {
      addToast({ title: 'MCP browser', message: `Toggle failed: ${e}`, type: 'error' });
      setMcpHeadless(!next);
      if (!next) localStorage.setItem('ws_mcp_browser_headless', '1');
      else localStorage.removeItem('ws_mcp_browser_headless');
    }
  };

  const toggleTlsImpersonate = async (next: boolean) => {
    setTlsImpersonate(next);
    localStorage.setItem('ws_tls_impersonate', next ? '1' : '0');
    try {
      await invoke('proxy_set_tls_impersonate', { enabled: next });
      addToast({
        title: 'TLS Impersonation',
        message: next
          ? 'Chrome 137 JA3/JA4 + HTTP/2 fingerprint ON for proxy upstream'
          : 'TLS impersonation OFF — falling back to native-tls (Cloudflare/Akamai will likely block)',
        type: next ? 'success' : 'warning',
      });
    } catch (e: any) {
      addToast({ title: 'Browser', message: `TLS impersonation toggle failed: ${e}`, type: 'error' });
      // Roll back UI state on backend failure so the toggle reflects truth.
      setTlsImpersonate(!next);
      localStorage.setItem('ws_tls_impersonate', !next ? '1' : '0');
    }
  };

  const reinstall = async () => {
    if (busyReinstall) return;
    if (!confirm('Reinstall WonderBrowser?\n\nThis will delete the cached Chromium and re-download it on next browser launch.')) {
      return;
    }
    setBusyReinstall(true);
    try {
      await invoke('chromium_reinstall');
      addToast({
        title: 'Browser',
        message: 'Cache cleared. Next browser launch will re-download Chromium.',
        type: 'success',
      });
      await refresh();
    } catch (e: any) {
      addToast({ title: 'Browser', message: `Reinstall failed: ${e}`, type: 'error' });
    } finally {
      setBusyReinstall(false);
    }
  };

  const download = async () => {
    try {
      const binary = await invoke<string>('chromium_ensure');
      addToast({ title: 'Browser', message: `Ready at ${binary}`, type: 'success' });
      await refresh();
    } catch (e: any) {
      addToast({ title: 'Browser', message: `Download failed: ${e}`, type: 'error' });
    }
  };

  return (
    <div className="settings-section">
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 16 }}>
        <Globe size={16} />
        <h2 style={{ margin: 0 }}>WonderBrowser</h2>
      </div>
      <p style={{ color: 'var(--text-2)', fontSize: 11, marginBottom: 24 }}>
        WonderSuite bundles its own pinned Chromium build (Chrome for Testing) so testing
        is isolated from your system Chrome and the version stays reproducible.
        The binary is verified against a pinned SHA-256.
      </p>

      <div className="settings-row" style={{ alignItems: 'flex-start' }}>
        <div className="settings-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Download size={12} /> Bundled Chromium
          </div>
          <span>Per-version cached locally, never auto-updated by Chrome itself.</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'flex-end' }}>
          {loading && (
            <div style={{ fontSize: 11, color: 'var(--text-3)' }}>
              <RefreshCw size={11} style={{ animation: 'bdl-rot 1s linear infinite' }} /> loading…
            </div>
          )}
          {!loading && status && (
            <>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 11 }}>
                {status.cached ? (
                  <>
                    <CheckCircle size={12} style={{ color: '#2ed573' }} />
                    <span>Installed</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle size={12} style={{ color: '#ffb86c' }} />
                    <span>Not yet downloaded</span>
                  </>
                )}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-2)', fontFamily: 'JetBrains Mono, monospace' }}>
                v{status.version}
                {status.cached && ` · ${fmtBytes(status.disk_bytes)}`}
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                {!status.cached ? (
                  <button className="bsp-btn bsp-btn-primary" onClick={download}>
                    <Download size={11} /> Download now
                  </button>
                ) : (
                  <>
                    <button
                      className="bsp-btn"
                      onClick={async () => {
                        try {
                          await invoke('reveal_in_explorer', { path: status.cache_dir });
                        } catch (e: any) {
                          addToast({ title: 'Browser', message: `Could not open ${status.cache_dir}: ${e}`, type: 'error' });
                        }
                      }}
                      title={status.cache_dir}
                    >
                      <FolderOpen size={11} /> Open cache dir
                    </button>
                    <button
                      className="bsp-btn bsp-btn-warning"
                      onClick={reinstall}
                      disabled={busyReinstall}
                    >
                      <Trash2 size={11} /> {busyReinstall ? 'Working…' : 'Reinstall'}
                    </button>
                  </>
                )}
              </div>
            </>
          )}
        </div>
      </div>

      <div className="settings-row">
        <div className="settings-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Globe size={12} /> Prefer system browser
          </div>
          <span>Use a detected Chrome / Edge / Brave instead of the bundled WonderBrowser. Falls back to system browser anyway if the bundled download fails.</span>
        </div>
        <button
          className={`settings-toggle ${preferSystem ? 'on' : ''}`}
          onClick={() => toggleSystem(!preferSystem)}
        />
      </div>

      <div className="settings-row">
        <div className="settings-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Shield size={12} /> Allow browser without sandbox
          </div>
          <span>Pass <code>--no-sandbox</code> to Chromium. Required only if you run WonderSuite as root on Linux or have a hardened kernel without user namespaces. Off by default.</span>
        </div>
        <button
          className={`settings-toggle ${noSandbox ? 'on' : ''}`}
          onClick={() => toggleNoSandbox(!noSandbox)}
        />
      </div>

      <div className="settings-row">
        <div className="settings-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Globe size={12} /> Impersonate Chrome TLS (JA3/JA4 + HTTP/2)
          </div>
          <span>
            Proxy upstream uses Chrome 137 JA3/JA4 + HTTP/2 fingerprint. Defeats Cloudflare, Akamai, DataDome, PerimeterX.
          </span>
        </div>
        <button
          className={`settings-toggle ${tlsImpersonate ? 'on' : ''}`}
          onClick={() => toggleTlsImpersonate(!tlsImpersonate)}
        />
      </div>

      <div className="settings-row">
        <div className="settings-label">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Globe size={12} /> Run MCP browser headless
          </div>
          <span>
            Hide the MCP browser window. Off by default — keep visible so you can help on captchas / 2FA.
          </span>
        </div>
        <button
          className={`settings-toggle ${mcpHeadless ? 'on' : ''}`}
          onClick={() => toggleMcpHeadless(!mcpHeadless)}
        />
      </div>

      {migration?.legacy_ca_present && (
        <div className="settings-row" style={{ alignItems: 'flex-start' }}>
          <div className="settings-label">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <AlertTriangle size={12} style={{ color: '#ffb86c' }} /> Legacy CA still in trust store
            </div>
            <span>
              v0.1.x installed a WonderSuite root CA into the Windows user trust store.
              v0.2.0 doesn't need it (the bundled browser uses <code>--ignore-certificate-errors</code> on its
              isolated profile). Removing the old CA is recommended.
              {migration.legacy_ca_subject && (
                <>
                  <br />
                  <code style={{ fontSize: 10, color: 'var(--text-3)' }}>{migration.legacy_ca_subject}</code>
                </>
              )}
            </span>
          </div>
          <button className="bsp-btn bsp-btn-danger" onClick={removeLegacyCa} disabled={busyCa}>
            <Trash2 size={11} /> {busyCa ? 'Working…' : 'Remove'}
          </button>
        </div>
      )}
    </div>
  );
}
