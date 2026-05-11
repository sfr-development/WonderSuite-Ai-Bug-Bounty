import { useState, useCallback } from 'react';
import { Search, Globe, FolderSearch, Loader2, Copy, Radar } from 'lucide-react';
import './Discovery.css';

interface DiscoveredItem {
  path: string; status: number; size: number; content_type: string; redirect?: string;
}
interface Subdomain {
  subdomain: string; ip?: string; status?: string; http_status?: number;
}

type Tab = 'content' | 'subdomains' | 'parameters';

export function Discovery() {
  const [tab, setTab] = useState<Tab>('content');
  const [target, setTarget] = useState('');

  const [contentResults, setContentResults] = useState<DiscoveredItem[]>([]);
  const [contentRunning, setContentRunning] = useState(false);
  const [wordlist, setWordlist] = useState('common');
  const [extensions, setExtensions] = useState('php,html,js,json,txt,bak,env');
  const [recursive, setRecursive] = useState(false);
  const [statusFilter] = useState('');
  const [contentProgress, setContentProgress] = useState('');

  const [subdomains, setSubdomains] = useState<Subdomain[]>([]);
  const [subRunning, setSubRunning] = useState(false);
  const [subWordlist, setSubWordlist] = useState('medium');
  const [useCrtSh, setUseCrtSh] = useState(true);

  const [paramResults, setParamResults] = useState<Array<{ param: string; evidence: string }>>([]);
  const [paramRunning, setParamRunning] = useState(false);
  const [paramMethod, setParamMethod] = useState('GET');

  const [selectedItem, setSelectedItem] = useState<DiscoveredItem | null>(null);

  const startContentDiscovery = useCallback(async () => {
    if (!target || contentRunning) return;
    setContentRunning(true); setContentResults([]); setContentProgress('Starting...');
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const config: Record<string, unknown> = {
        wordlist,
        recursive,
        extensions: extensions.split(',').map(e => e.trim()).filter(Boolean),
      };
      if (statusFilter) {
        config.status_filter = statusFilter.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      }

      setContentProgress('Scanning...');

      try {
        await invoke('scanner_start_active', {
          target,
          config: { check_content_discovery: true, wordlist, recursive, ...config },
        });
      } catch { /* scanner may not support this mode */ }
      const fallbackItems: DiscoveredItem[] = [];
      const commonPaths = [
        '/.env', '/.git/config', '/robots.txt', '/sitemap.xml', '/wp-admin/', '/admin/',
        '/api/', '/graphql', '/.htaccess', '/backup/', '/config/', '/debug/', '/test/',
        '/swagger/', '/api-docs/', '/.well-known/security.txt', '/server-info', '/server-status',
        '/phpinfo.php', '/info.php', '/wp-login.php', '/administrator/', '/login', '/register',
        '/console', '/dashboard', '/panel', '/.DS_Store', '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/wp-json/wp/v2/users', '/feed/', '/xmlrpc.php', '/.git/HEAD', '/composer.json', '/package.json',
        '/Dockerfile', '/docker-compose.yml', '/.dockerignore', '/Makefile',
      ];

      for (const path of commonPaths) {
        try {
          const full = target.replace(/\/$/, '') + path;
          const r: { status: number; headers: string; body: string; time_ms: number; size: number } =
            await invoke('send_http_request', { method: 'GET', url: full, headers: null, body: null });
          if (r.status !== 404 && r.status !== 0) {
            fallbackItems.push({
              path, status: r.status, size: r.size,
              content_type: r.headers.split('\n').find(h => h.toLowerCase().startsWith('content-type'))?.split(':')[1]?.trim() || 'unknown',
            });
          }
          setContentProgress(`Checked ${fallbackItems.length} / ${commonPaths.length} paths`);
        } catch { /* ignore timeout/error */ }
      }

      setContentResults(fallbackItems.sort((a, b) => a.status - b.status));
      setContentProgress(`Done — ${fallbackItems.length} found of ${commonPaths.length} tested`);
    } catch (err) {
      setContentProgress(`Error: ${err}`);
    }
    setContentRunning(false);
  }, [target, wordlist, extensions, recursive, statusFilter, contentRunning]);

  const startSubdomainScan = useCallback(async () => {
    if (!target || subRunning) return;
    setSubRunning(true); setSubdomains([]);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const prefixes = [
        'www', 'api', 'app', 'admin', 'dev', 'staging', 'test', 'mail', 'smtp', 'pop',
        'imap', 'ftp', 'cdn', 'static', 'assets', 'img', 'images', 'media', 'files',
        'beta', 'alpha', 'preview', 'sandbox', 'demo', 'docs', 'help', 'support',
        'portal', 'dashboard', 'panel', 'login', 'auth', 'sso', 'oauth', 'id',
        'ns1', 'ns2', 'mx', 'vpn', 'remote', 'git', 'gitlab', 'github', 'ci', 'jenkins',
        'internal', 'intranet', 'corp', 'private', 'backend', 'service', 'services',
        'ws', 'wss', 'socket', 'graphql', 'rest', 'v1', 'v2', 'v3',
        'stage', 'uat', 'qa', 'prod', 'production', 'edge', 'origin', 'lb',
        'monitor', 'status', 'health', 'metrics', 'grafana', 'kibana', 'elastic',
        'db', 'database', 'redis', 'cache', 'queue', 'worker', 'cron',
      ];
      const domain = target.replace(/^https?:\/\//, '').replace(/\/.*/, '');
      const found: Subdomain[] = [];

      for (const prefix of prefixes) {
        const sub = `${prefix}.${domain}`;
        try {
          const r: { status: number } = await invoke('send_http_request', {
            method: 'HEAD', url: `https://${sub}`, headers: null, body: null,
          });
          found.push({ subdomain: sub, http_status: r.status, status: 'alive' });
          setSubdomains([...found]);
        } catch {
          try {
            const r: { status: number } = await invoke('send_http_request', {
              method: 'HEAD', url: `http://${sub}`, headers: null, body: null,
            });
            found.push({ subdomain: sub, http_status: r.status, status: 'alive (http)' });
            setSubdomains([...found]);
          } catch { /* not resolvable */ }
        }
      }
      setSubdomains(found);
    } catch (err) { console.error(err); }
    setSubRunning(false);
  }, [target, subRunning]);

  const startParamDiscovery = useCallback(async () => {
    if (!target || paramRunning) return;
    setParamRunning(true); setParamResults([]);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const params = [
        'id', 'page', 'q', 'search', 'query', 'debug', 'test', 'admin', 'token',
        'key', 'api_key', 'apikey', 'secret', 'password', 'pass', 'user', 'username',
        'email', 'callback', 'redirect', 'redirect_uri', 'return', 'return_url', 'next',
        'url', 'uri', 'path', 'file', 'filename', 'include', 'template', 'lang', 'language',
        'action', 'type', 'format', 'output', 'v', 'version', 'limit', 'offset', 'sort',
        'order', 'filter', 'category', 'tag', 'status', 'role', 'access', 'auth',
        'view', 'mode', 'config', 'setting', 'option', 'cmd', 'command', 'exec',
      ];

      const baseline: { status: number; body: string; size: number } =
        await invoke('send_http_request', { method: 'GET', url: target, headers: null, body: null });

      const found: Array<{ param: string; evidence: string }> = [];
      for (const param of params) {
        try {
          const testUrl = `${target}${target.includes('?') ? '&' : '?'}${param}=wondertest123`;
          const r: { status: number; body: string; size: number } =
            await invoke('send_http_request', { method: 'GET', url: testUrl, headers: null, body: null });

          const sizeDiff = Math.abs(r.size - baseline.size);
          if (sizeDiff > 50 || r.status !== baseline.status) {
            found.push({
              param,
              evidence: `Status: ${r.status} (baseline: ${baseline.status}), Size diff: ${sizeDiff > 0 ? '+' : ''}${sizeDiff}B`,
            });
          }
        } catch { /* ignore */ }
      }
      setParamResults(found);
    } catch (err) { console.error(err); }
    setParamRunning(false);
  }, [target, paramRunning]);

  const statusClass = (code: number) => {
    if (code < 300) return 's2xx'; if (code < 400) return 's3xx';
    if (code < 500) return 's4xx'; return 's5xx';
  };

  const copyText = (t: string) => navigator.clipboard.writeText(t);

  return (
    <div className="disc">
      <div className="disc-toolbar">
        <FolderSearch size={14} />
        <span className="disc-toolbar-title">Content Discovery</span>
        <div style={{ flex: 1 }} />
        <input className="disc-target-input" value={target} onChange={e => setTarget(e.target.value)}
          placeholder="https://target.example.com" onKeyDown={e => { if (e.key === 'Enter') { if (tab === 'content') startContentDiscovery(); else if (tab === 'subdomains') startSubdomainScan(); else startParamDiscovery(); } }} />
      </div>

      <div className="disc-tabs">
        <button className={`disc-tab ${tab === 'content' ? 'active' : ''}`} onClick={() => setTab('content')}>
          <FolderSearch size={10} /> Directories & Files
          {contentResults.length > 0 && <span className="disc-badge">{contentResults.length}</span>}
        </button>
        <button className={`disc-tab ${tab === 'subdomains' ? 'active' : ''}`} onClick={() => setTab('subdomains')}>
          <Globe size={10} /> Subdomains
          {subdomains.length > 0 && <span className="disc-badge">{subdomains.length}</span>}
        </button>
        <button className={`disc-tab ${tab === 'parameters' ? 'active' : ''}`} onClick={() => setTab('parameters')}>
          <Search size={10} /> Hidden Parameters
          {paramResults.length > 0 && <span className="disc-badge">{paramResults.length}</span>}
        </button>
      </div>

      <div className="disc-body">
        {/* Content Discovery */}
        {tab === 'content' && (
          <div className="disc-content-panel">
            <div className="disc-options">
              <div className="disc-opt-row">
                <label className="disc-label">Wordlist</label>
                <select className="disc-select" value={wordlist} onChange={e => setWordlist(e.target.value)}>
                  <option value="common">Common (~300)</option>
                  <option value="medium">Medium (~1000)</option>
                  <option value="large">Large (~5000)</option>
                </select>
                <label className="disc-label">Extensions</label>
                <input className="disc-input-sm" value={extensions} onChange={e => setExtensions(e.target.value)} />
                <label className="disc-check">
                  <input type="checkbox" checked={recursive} onChange={e => setRecursive(e.target.checked)} /> Recursive
                </label>
                <button className="disc-scan-btn" onClick={startContentDiscovery} disabled={contentRunning || !target}>
                  {contentRunning ? <><Loader2 size={10} className="spin" /> Scanning...</> : <><Radar size={10} /> Start Scan</>}
                </button>
              </div>
              {contentProgress && <span className="disc-progress">{contentProgress}</span>}
            </div>

            <div className="disc-results">
              <table className="disc-table">
                <thead>
                  <tr><th>Path</th><th>Status</th><th>Size</th><th>Content-Type</th><th></th></tr>
                </thead>
                <tbody>
                  {contentResults.map((item, i) => (
                    <tr key={i} className={selectedItem === item ? 'selected' : ''} onClick={() => setSelectedItem(item)}>
                      <td className="disc-path">{item.path}</td>
                      <td><span className={`disc-status ${statusClass(item.status)}`}>{item.status}</span></td>
                      <td className="disc-size">{item.size}B</td>
                      <td className="disc-type">{item.content_type}</td>
                      <td>
                        <button className="disc-copy-btn" onClick={e => { e.stopPropagation(); copyText(target.replace(/\/$/, '') + item.path); }}><Copy size={9} /></button>
                      </td>
                    </tr>
                  ))}
                  {contentResults.length === 0 && !contentRunning && (
                    <tr><td colSpan={5} className="disc-empty-td">
                      <FolderSearch size={20} strokeWidth={1} />
                      <span>No results yet — enter a target URL and start scanning</span>
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Subdomains */}
        {tab === 'subdomains' && (
          <div className="disc-sub-panel">
            <div className="disc-options">
              <div className="disc-opt-row">
                <label className="disc-label">Wordlist</label>
                <select className="disc-select" value={subWordlist} onChange={e => setSubWordlist(e.target.value)}>
                  <option value="small">Small (~60)</option>
                  <option value="medium">Medium (~100)</option>
                  <option value="large">Large (~200)</option>
                </select>
                <label className="disc-check">
                  <input type="checkbox" checked={useCrtSh} onChange={e => setUseCrtSh(e.target.checked)} /> Use crt.sh
                </label>
                <button className="disc-scan-btn" onClick={startSubdomainScan} disabled={subRunning || !target}>
                  {subRunning ? <><Loader2 size={10} className="spin" /> Scanning...</> : <><Globe size={10} /> Enumerate</>}
                </button>
              </div>
            </div>

            <div className="disc-results">
              <table className="disc-table">
                <thead>
                  <tr><th>Subdomain</th><th>HTTP Status</th><th>State</th><th></th></tr>
                </thead>
                <tbody>
                  {subdomains.map((s, i) => (
                    <tr key={i}>
                      <td className="disc-subdomain">{s.subdomain}</td>
                      <td>{s.http_status && <span className={`disc-status ${statusClass(s.http_status)}`}>{s.http_status}</span>}</td>
                      <td><span className="disc-alive">{s.status}</span></td>
                      <td>
                        <button className="disc-copy-btn" onClick={() => copyText(s.subdomain)}><Copy size={9} /></button>
                      </td>
                    </tr>
                  ))}
                  {subdomains.length === 0 && !subRunning && (
                    <tr><td colSpan={4} className="disc-empty-td">
                      <Globe size={20} strokeWidth={1} />
                      <span>Enter a domain (e.g. example.com) and click Enumerate</span>
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Parameter Discovery */}
        {tab === 'parameters' && (
          <div className="disc-param-panel">
            <div className="disc-options">
              <div className="disc-opt-row">
                <label className="disc-label">Method</label>
                <select className="disc-select" value={paramMethod} onChange={e => setParamMethod(e.target.value)}>
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                </select>
                <button className="disc-scan-btn" onClick={startParamDiscovery} disabled={paramRunning || !target}>
                  {paramRunning ? <><Loader2 size={10} className="spin" /> Testing...</> : <><Search size={10} /> Find Parameters</>}
                </button>
              </div>
            </div>

            <div className="disc-results">
              <table className="disc-table">
                <thead>
                  <tr><th>Parameter</th><th>Evidence</th><th></th></tr>
                </thead>
                <tbody>
                  {paramResults.map((p, i) => (
                    <tr key={i}>
                      <td className="disc-param-name">{p.param}</td>
                      <td className="disc-param-evidence">{p.evidence}</td>
                      <td>
                        <button className="disc-copy-btn" onClick={() => copyText(`${target}${target.includes('?') ? '&' : '?'}${p.param}=`)}><Copy size={9} /></button>
                      </td>
                    </tr>
                  ))}
                  {paramResults.length === 0 && !paramRunning && (
                    <tr><td colSpan={3} className="disc-empty-td">
                      <Search size={20} strokeWidth={1} />
                      <span>Enter a URL with an endpoint and test for hidden parameters</span>
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
