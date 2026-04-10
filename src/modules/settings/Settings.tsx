import { useState, useEffect } from 'react';
import { Wrench, Palette, Shield, Plug, Power, Copy, CheckCircle, Zap, RefreshCw, Unlock, Link, List, Lock, Download, Check, AlertTriangle, Search } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import './Settings.css';


function CursorLogo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#000"/>
      <path d="M6 4L18 12L12 13.5L9.5 20L6 4Z" fill="#fff" stroke="#fff" strokeWidth="0.5" strokeLinejoin="round"/>
      <path d="M12 13.5L15.5 17L9.5 20L12 13.5Z" fill="#888" stroke="#fff" strokeWidth="0.3" strokeLinejoin="round"/>
    </svg>
  );
}

function WindsurfLogo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0F172A"/>
      <path d="M6 16C8 12 10 9 14 7" stroke="#38BDF8" strokeWidth="2" strokeLinecap="round"/>
      <path d="M8 18C10 14 13 11 18 9" stroke="#818CF8" strokeWidth="2" strokeLinecap="round"/>
      <path d="M10 20C13 16 16 13 20 11" stroke="#C084FC" strokeWidth="2" strokeLinecap="round"/>
    </svg>
  );
}

function AntigravityLogo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#1a1625"/>
      <path d="M12 4L4 20H20L12 4Z" fill="none" stroke="#A855F7" strokeWidth="1.5" strokeLinejoin="round"/>
      <path d="M12 10L8 18H16L12 10Z" fill="#A855F7" opacity="0.3"/>
      <circle cx="12" cy="14" r="1.5" fill="#A855F7"/>
    </svg>
  );
}

function VsCodeLogo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#1E1E1E"/>
      <path d="M17 3L7 12L17 21V3Z" fill="#007ACC" opacity="0.6"/>
      <path d="M17 3L5 10L7 12L17 7V3Z" fill="#2BA0D9"/>
      <path d="M17 21L5 14L7 12L17 17V21Z" fill="#2BA0D9"/>
      <path d="M17 3V21L20 19V5L17 3Z" fill="#007ACC"/>
    </svg>
  );
}

function VoidLogo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0a0a0a"/>
      <circle cx="12" cy="12" r="6" fill="none" stroke="#666" strokeWidth="1.5"/>
      <circle cx="12" cy="12" r="2" fill="#999"/>
      <path d="M12 6V4M12 20V18M6 12H4M20 12H18" stroke="#555" strokeWidth="1"/>
    </svg>
  );
}

function GeminiCliLogo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0D1117"/>
      <path d="M12 4C12 4 6 10 6 14C6 18 12 20 12 20" stroke="#4285F4" strokeWidth="1.5" strokeLinecap="round"/>
      <path d="M12 4C12 4 18 10 18 14C18 18 12 20 12 20" stroke="#EA4335" strokeWidth="1.5" strokeLinecap="round"/>
      <circle cx="12" cy="12" r="2" fill="#FBBC04"/>
    </svg>
  );
}

function IdeIconComponent({ type, size = 20 }: { type: string; size?: number }) {
  switch (type) {
    case 'cursor': return <CursorLogo size={size} />;
    case 'windsurf': return <WindsurfLogo size={size} />;
    case 'antigravity': return <AntigravityLogo size={size} />;
    case 'vscode': return <VsCodeLogo size={size} />;
    case 'void': return <VoidLogo size={size} />;
    case 'gemini-cli': return <GeminiCliLogo size={size} />;
    default: return <VsCodeLogo size={size} />;
  }
}

type SettingsTab = 'general' | 'mcp' | 'proxy' | 'appearance';


const mcpTools = [
  // HTTP
  { name: 'send_request', desc: 'Send HTTP request to any URL', category: 'http' },
  { name: 'repeat_request', desc: 'Replay request with modifications (Repeater)', category: 'http' },
  // Codec
  { name: 'encode', desc: 'Encode data (Base64, URL, HTML, Hex)', category: 'codec' },
  { name: 'decode', desc: 'Decode data (Base64, URL, HTML, Hex)', category: 'codec' },
  { name: 'hash', desc: 'Hash data (SHA-256, SHA-1, SHA-512, MD5)', category: 'codec' },
  { name: 'analyze_jwt', desc: 'Decode and validate JWT tokens', category: 'codec' },
  { name: 'smart_decode', desc: 'Auto-detect and decode encoding chains', category: 'codec' },
  // Proxy
  { name: 'proxy_start', desc: 'Start the MITM proxy engine', category: 'proxy' },
  { name: 'proxy_stop', desc: 'Stop the proxy engine', category: 'proxy' },
  { name: 'proxy_status', desc: 'Get proxy engine status and stats', category: 'proxy' },
  { name: 'proxy_toggle_intercept', desc: 'Enable/disable request interception', category: 'proxy' },
  { name: 'proxy_get_traffic', desc: 'Get captured HTTP traffic history', category: 'traffic' },
  { name: 'proxy_search_traffic', desc: 'Search traffic by host, path, or status', category: 'traffic' },
  { name: 'proxy_clear_traffic', desc: 'Clear all captured traffic', category: 'traffic' },
  { name: 'proxy_export_traffic', desc: 'Export traffic as JSON/CSV', category: 'traffic' },
  { name: 'proxy_add_match_replace', desc: 'Add match & replace rule for traffic', category: 'proxy' },
  { name: 'proxy_get_match_replace', desc: 'List match & replace rules', category: 'proxy' },
  { name: 'proxy_add_tls_passthrough', desc: 'Add TLS passthrough host', category: 'proxy' },
  { name: 'proxy_set_upstream', desc: 'Configure upstream proxy (HTTP/SOCKS5)', category: 'proxy' },
  { name: 'proxy_get_websocket_messages', desc: 'Get WebSocket messages', category: 'proxy' },
  { name: 'proxy_add_interception_rule', desc: 'Add request interception rule', category: 'proxy' },
  { name: 'proxy_get_capabilities', desc: 'Get proxy feature capabilities', category: 'proxy' },
  { name: 'proxy_get_statistics', desc: 'Get runtime statistics', category: 'proxy' },
  // Scanner
  { name: 'scan_target', desc: 'Passive security scan (header/cookie audit)', category: 'scanner' },
  { name: 'active_scan', desc: 'Full active scanner: auto-crawl → injection → tech fingerprint → info disclosure', category: 'scanner' },
  { name: 'full_auto_scan', desc: 'Full pipeline: recon → crawl → audit → report', category: 'scanner' },
  { name: 'custom_attack', desc: 'AI-driven custom payload injection with differential analysis', category: 'scanner' },
  // Intruder
  { name: 'generate_payload', desc: 'Generate fuzzing payloads (wordlists)', category: 'attack' },
  { name: 'fuzz_request', desc: 'Launch Intruder attack with payloads', category: 'attack' },
  { name: 'process_payload', desc: 'Encode/decode/hash/transform payloads', category: 'attack' },
  { name: 'grep_extract', desc: 'Regex extraction from responses', category: 'attack' },
  // Recon & Discovery
  { name: 'crawl_target', desc: 'Crawl website: follow links, extract forms/scripts', category: 'recon' },
  { name: 'discover_subdomains', desc: 'Enumerate subdomains (DNS + crt.sh)', category: 'recon' },
  { name: 'discover_content', desc: 'Directory/file brute-force (like ffuf)', category: 'recon' },
  { name: 'analyze_target', desc: 'Tech detection, WAF fingerprinting, headers', category: 'recon' },
  { name: 'find_secrets', desc: 'Find leaked API keys, tokens, passwords', category: 'recon' },
  // Exploit Tools
  { name: 'test_auth_bypass', desc: 'Test IDOR & auth bypass vulnerabilities', category: 'exploit' },
  { name: 'detect_smuggling', desc: 'HTTP request smuggling detection', category: 'exploit' },
  { name: 'test_open_redirect', desc: 'Open redirect bypass techniques', category: 'exploit' },
  { name: 'generate_csrf_poc', desc: 'Generate CSRF proof-of-concept HTML', category: 'exploit' },
  // Browser
  { name: 'browser_navigate', desc: 'Open URL in WonderBrowser, get page content', category: 'browser' },
  // Analysis
  { name: 'inspect_message', desc: 'Parse HTTP headers, params, cookies', category: 'tools' },
  { name: 'analyze_tokens', desc: 'Shannon entropy + FIPS analysis', category: 'tools' },
  { name: 'compare_data', desc: 'LCS diff between two texts', category: 'tools' },
  // Session & Scope
  { name: 'session_manage', desc: 'Cookie jar, macros, session rules', category: 'session' },
  { name: 'scope_manage', desc: 'Define target scope (include/exclude)', category: 'session' },
  // Reporting
  { name: 'generate_report', desc: 'Generate HTML/JSON vulnerability reports', category: 'report' },
  // Logger & Organizer
  { name: 'query_logs', desc: 'Query and filter request logs', category: 'tools' },
  { name: 'organize_findings', desc: 'Manage finding collections', category: 'tools' },
  // WebSocket
  { name: 'websocket_edit', desc: 'Modify and replay WebSocket frames', category: 'websocket' },
  // OAST / Collaborator (Blind Vulnerability Detection)
  { name: 'oast_generate_payload', desc: 'Generate blind vuln payloads with DNS/HTTP callbacks (Burp Collaborator)', category: 'oast' },
  { name: 'oast_poll_interactions', desc: 'Poll for OAST callback interactions', category: 'oast' },
  { name: 'oast_start_server', desc: 'Start OAST HTTP callback server', category: 'oast' },
  { name: 'oast_get_payloads', desc: 'List generated OAST payloads', category: 'oast' },
  // HTTP/2
  { name: 'h2_send_request', desc: 'Send HTTP/2 request with pseudo-headers', category: 'http' },
  { name: 'h2_detect_support', desc: 'Detect HTTP/2 protocol support', category: 'http' },
  { name: 'h2_translate', desc: 'Translate between HTTP/1.1 and HTTP/2 formats', category: 'http' },
  // DOM Invader
  { name: 'dom_invader', desc: 'Headless DOM XSS detection — sink/source analysis + reflection testing', category: 'exploit' },
  // OAST Extended
  { name: 'oast_start_dns_server', desc: 'Start DNS callback server for blind OOB detection', category: 'oast' },
  { name: 'oast_start_smtp_server', desc: 'Start SMTP callback server for email-based blind vulns', category: 'oast' },
  { name: 'collaborator_everywhere', desc: 'Auto-inject OAST payloads into 14+ HTTP headers', category: 'oast' },
  // mTLS
  { name: 'mtls_send_request', desc: 'Send request with client certificate (mTLS)', category: 'http' },
  // WebSocket Advanced
  { name: 'websocket_advanced', desc: 'WS match & replace rules, frame injection, binary editing', category: 'websocket' },
  // Bambda Filtering
  { name: 'bambda_filter', desc: 'Custom traffic filter expressions (Bambda-style)', category: 'tools' },
  // Advanced Pentesting
  { name: 'raw_tcp_send', desc: 'Raw TCP/TLS byte-level socket access with chunked sending', category: 'exploit' },
  { name: 'smuggling_send', desc: 'HTTP Request Smuggling — same-connection pipelining with timing', category: 'exploit' },
  { name: 'timing_attack', desc: 'Statistical differential timing analysis (t-test, Welch)', category: 'exploit' },
  { name: 'browser_execute_js', desc: 'Execute JavaScript in browser context via CDP', category: 'exploit' },
  { name: 'websocket_connect', desc: 'Full WebSocket lifecycle — connect, send, receive, close', category: 'websocket' },
  { name: 'session_from_browser', desc: 'Capture browser session (cookies, localStorage) for tools', category: 'session' },
  { name: 'oast_verify', desc: 'Self-testing OAST callback server with interaction logging', category: 'oast' },
  // Advanced Reconnaissance & Exploitation
  { name: 'dns_resolve', desc: 'DNS lookup with CDN detection + origin IP discovery', category: 'recon' },
  { name: 'race_request', desc: 'Barrier-synchronized parallel HTTP for race condition testing', category: 'exploit' },
  // HTTP/2 Smuggling
  { name: 'h2_detect_support', desc: 'Detect HTTP/2 support via ALPN negotiation', category: 'recon' },
  { name: 'h2_send_request', desc: 'Send HTTP/2 requests with pseudo-headers', category: 'http' },
  { name: 'h2_translate', desc: 'Translate between H1 and H2 request formats', category: 'codec' },
  // OSINT (Zero API Keys)
  { name: 'crtsh_search', desc: 'Certificate Transparency subdomain enumeration via crt.sh', category: 'osint' },
  { name: 'wayback_lookup', desc: 'Wayback Machine historical URL discovery (CDX API)', category: 'osint' },
  { name: 'whois_lookup', desc: 'RDAP/WHOIS domain & IP registration lookup', category: 'osint' },
  { name: 'asn_lookup', desc: 'ASN info via Team Cymru DNS + RDAP (no API key)', category: 'osint' },
  { name: 'favicon_hash', desc: 'Favicon MurmurHash3 for origin IP discovery', category: 'osint' },
  { name: 'discover_parameters', desc: 'Hidden parameter discovery via response differential', category: 'osint' },
  { name: 'graphql_introspect', desc: 'GraphQL schema extraction via introspection query', category: 'osint' },
  { name: 'js_link_finder', desc: 'Extract endpoints & secrets from JavaScript files', category: 'osint' },
  { name: 'reverse_ip_lookup', desc: 'PTR DNS + virtual host discovery (no API key)', category: 'osint' },
  // Nuclei Template Engine
  { name: 'template_list', desc: 'List/filter Nuclei templates by category, severity, tags', category: 'nuclei' },
  { name: 'template_search', desc: 'Full-text search across all Nuclei vulnerability templates', category: 'nuclei' },
  { name: 'template_scan', desc: 'Run Nuclei templates against a target with matcher engine', category: 'nuclei' },
];

const categoryColors: Record<string, string> = {
  http: '#3b82f6', codec: '#8b5cf6', proxy: '#06b6d4', traffic: '#0ea5e9',
  scanner: '#ef4444', attack: '#f59e0b', browser: '#22c55e', tools: '#64748b',
  session: '#ec4899', report: '#14b8a6', websocket: '#a855f7',
  recon: '#f97316', exploit: '#dc2626', oast: '#e11d48',
  osint: '#10b981', nuclei: '#f43f5e',
};

// ── IDE Definitions ─────────────────────────────────────────────────
interface IdeInfo {
  name: string;
  icon: string;
  detected: boolean;
  installed: boolean;
  configPath: string;
  configType: 'cursor' | 'windsurf' | 'vscode' | 'antigravity';
}

/**
 * Generate the correct MCP config JSON for each IDE type.
 * Different IDEs use different field names:
 *  - Antigravity / Gemini CLI: "serverUrl" inside "mcpServers"
 *  - Cursor / Windsurf / Void: "url" inside "mcpServers"
 *  - VS Code: nested "mcp.servers" with "type" + "url"
 */
function generateMcpConfigForIde(port: string, configType: string): string {
  const serverUrl = `http://127.0.0.1:${port}/mcp`;

  if (configType === 'vscode') {
    return JSON.stringify({
      mcp: {
        servers: {
          wondersuite: {
            type: "http",
            url: serverUrl,
            description: "WonderSuite — AI-Native Web Security Testing Platform"
          }
        }
      }
    }, null, 2);
  }

  if (configType === 'antigravity') {
    // Antigravity / Gemini CLI expect "serverUrl" (not "url")
    return JSON.stringify({
      mcpServers: {
        wondersuite: {
          serverUrl: serverUrl,
        }
      }
    }, null, 2);
  }

  // Cursor, Windsurf, Void — standard MCP format with "url"
  return JSON.stringify({
    mcpServers: {
      wondersuite: {
        url: serverUrl,
      }
    }
  }, null, 2);
}

export function Settings() {
  const [tab, setTab] = useState<SettingsTab>('mcp');
  const [mcpRunning, setMcpRunning] = useState(false);
  const [mcpPort, setMcpPort] = useState('3100');
  const [proxyPort, setProxyPort] = useState('8080');
  const [toolFilter, setToolFilter] = useState('');
  const [mcpError, setMcpError] = useState('');

  // Check MCP status on mount + auto-start
  useEffect(() => {
    (async () => {
      try {
        const running = await invoke<boolean>('mcp_status');
        setMcpRunning(running);
        if (!running) {
          try {
            await invoke('mcp_start', { port: parseInt(mcpPort) });
            setMcpRunning(true);
            console.log('[MCP] Auto-started on port', mcpPort);
          } catch (startErr: any) {
            const errStr = String(startErr);
            // Port already in use = likely already running from previous session
            if (errStr.includes('10048') || errStr.includes('already') || errStr.includes('in use')) {
              setMcpRunning(true); // Treat as running
              console.log('[MCP] Port already bound, treating as running');
            } else {
              console.error('[MCP] Auto-start failed:', startErr);
              setMcpError(errStr);
            }
          }
        }
      } catch (e: any) {
        console.error('[MCP] Status check error:', e);
      }
    })();
  }, []);

  const filteredTools = mcpTools.filter(t =>
    !toolFilter || t.name.includes(toolFilter.toLowerCase()) ||
    t.desc.toLowerCase().includes(toolFilter.toLowerCase()) ||
    t.category.includes(toolFilter.toLowerCase())
  );

  return (
    <div className="settings">
      <div className="settings-nav">
        <div className="settings-nav-title">Settings</div>
        <button className={`settings-nav-item ${tab === 'general' ? 'active' : ''}`} onClick={() => setTab('general')}>
          <Wrench size={14} /> General
        </button>
        <button className={`settings-nav-item ${tab === 'mcp' ? 'active' : ''}`} onClick={() => setTab('mcp')}>
          <Plug size={14} /> MCP Server
        </button>
        <button className={`settings-nav-item ${tab === 'proxy' ? 'active' : ''}`} onClick={() => setTab('proxy')}>
          <Shield size={14} /> Proxy
        </button>
        <button className={`settings-nav-item ${tab === 'appearance' ? 'active' : ''}`} onClick={() => setTab('appearance')}>
          <Palette size={14} /> Appearance
        </button>
      </div>

      <div className="settings-content">
        {tab === 'mcp' && (
          <>
            {/* ── MCP Server Status ─── */}
            <div className="settings-section">
              <h2>MCP Server</h2>
              <p>Expose WonderSuite tools to AI assistants via the Model Context Protocol</p>

              <div className="mcp-status">
                <div className={`mcp-status-dot ${mcpRunning ? 'running' : 'stopped'}`} />
                <div className="mcp-status-text">
                  <strong>{mcpRunning ? 'Running' : 'Stopped'}</strong>
                  <span>{mcpRunning ? `Listening on port ${mcpPort}` : 'Server is not running'}</span>
                </div>
                <button
                  className={`mcp-btn ${mcpRunning ? 'stop' : 'start'}`}
                  onClick={async () => {
                    setMcpError('');
                    try {
                      if (mcpRunning) {
                        await invoke('mcp_stop');
                        setMcpRunning(false);
                      } else {
                        await invoke('mcp_start', { port: parseInt(mcpPort) });
                        setMcpRunning(true);
                      }
                    } catch (e: any) {
                      const errStr = String(e);
                      if (errStr.includes('10048') || errStr.includes('already')) {
                        setMcpRunning(true); // Already running
                        setMcpError('');
                      } else {
                        console.error('MCP error:', e);
                        setMcpError(errStr);
                      }
                    }
                  }}
                >
                  <Power size={12} style={{ marginRight: 4 }} />
                  {mcpRunning ? 'Stop' : 'Start'}
                </button>
              </div>
              {mcpError && (
                <div style={{ color: '#ff6b6b', fontSize: 12, padding: '6px 12px', background: 'rgba(255,107,107,0.1)', borderRadius: 6, marginTop: 8 }}>
                  ⚠ {mcpError}
                </div>
              )}

              <div className="settings-row">
                <div className="settings-label">
                  Port
                  <span>TCP port for MCP server</span>
                </div>
                <input className="settings-input" value={mcpPort} onChange={(e) => setMcpPort(e.target.value)} style={{ minWidth: 80 }} />
              </div>
            </div>

            {/* ── IDE Integration ─── */}
            <IdeIntegration mcpPort={mcpPort} mcpRunning={mcpRunning} />

            {/* ── Available Tools ─── */}
            <div className="settings-section">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <h2>Available Tools ({mcpTools.length})</h2>
                <div style={{ position: 'relative' }}>
                  <Search size={12} style={{ position: 'absolute', left: 8, top: 8, color: 'var(--text-3)' }} />
                  <input
                    className="settings-input"
                    placeholder="Filter tools..."
                    value={toolFilter}
                    onChange={(e) => setToolFilter(e.target.value)}
                    style={{ minWidth: 180, paddingLeft: 26, height: 28 }}
                  />
                </div>
              </div>
              <p>These tools are exposed via MCP and can be used by AI assistants</p>

              <div className="mcp-tools-list" style={{ maxHeight: 400, overflowY: 'auto', border: '1px solid var(--border-0)', borderRadius: 'var(--radius-m)', padding: 2 }}>
                {filteredTools.map((tool) => (
                  <div key={tool.name} className="mcp-tool-item">
                    <span className="mcp-tool-name">{tool.name}</span>
                    <span className="mcp-tool-desc">{tool.desc}</span>
                    <span className="mcp-tool-badge" style={{
                      background: `${categoryColors[tool.category]}15`,
                      color: categoryColors[tool.category],
                      borderColor: `${categoryColors[tool.category]}30`,
                    }}>{tool.category}</span>
                  </div>
                ))}
                {filteredTools.length === 0 && (
                  <div style={{ padding: 16, textAlign: 'center', color: 'var(--text-3)', fontSize: 11 }}>No tools matching "{toolFilter}"</div>
                )}
              </div>
            </div>
          </>
        )}

        {tab === 'general' && (
          <>
          <GeneralSystemInfo />
          <div className="settings-section">
            <h2>General</h2>
            <p>Core application settings</p>

            <div className="settings-row">
              <div className="settings-label">
                Max traffic entries
                <span>Maximum stored HTTP messages</span>
              </div>
              <input className="settings-input" defaultValue="10000" style={{ minWidth: 80 }} />
            </div>

            <div className="settings-row">
              <div className="settings-label">
                Response size limit
                <span>Max response body size to store (MB)</span>
              </div>
              <input className="settings-input" defaultValue="10" style={{ minWidth: 80 }} />
            </div>

            <div className="settings-row">
              <div className="settings-label">
                Follow redirects
                <span>Automatically follow HTTP redirects</span>
              </div>
              <button className="settings-toggle on" onClick={() => {}} />
            </div>
          </div>
          </>
        )}

        {tab === 'proxy' && (
          <ProxySettings proxyPort={proxyPort} onPortChange={setProxyPort} />
        )}

        {tab === 'appearance' && (
          <div className="settings-section">
            <h2>Appearance</h2>
            <p>Customize the interface</p>

            <div className="settings-row">
              <div className="settings-label">
                Font size
                <span>Base font size for the UI</span>
              </div>
              <input className="settings-input" defaultValue="12" style={{ minWidth: 60 }} />
            </div>

            <div className="settings-row">
              <div className="settings-label">
                Editor font size
                <span>Font size for code editors</span>
              </div>
              <input className="settings-input" defaultValue="11" style={{ minWidth: 60 }} />
            </div>

            <div className="settings-row">
              <div className="settings-label">
                Compact mode
                <span>Reduce padding and spacing</span>
              </div>
              <button className="settings-toggle" onClick={() => {}} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
//  IDE Integration — Auto-detect installed IDEs & one-click MCP install
// ═══════════════════════════════════════════════════════════════════════

function IdeIntegration({ mcpPort, mcpRunning: _mcpRunning }: { mcpPort: string; mcpRunning: boolean }) {
  const [ides, setIdes] = useState<IdeInfo[]>([]);
  const [installing, setInstalling] = useState<string | null>(null);
  const [installStatus, setInstallStatus] = useState<Record<string, 'success' | 'error' | null>>({});

  useEffect(() => {
    detectIdes();
  }, []);

  const detectIdes = async () => {
    // Check for installed IDEs by probing their ACTUAL config directories
    const homeDir = await getHomeDir();
    const detectedIdes: IdeInfo[] = [];

    // Cursor — config lives at ~/.cursor/mcp.json
    const cursorDir = `${homeDir}/.cursor`;
    const cursorConfig = `${cursorDir}/mcp.json`;
    const cursorExists = await fileExists(cursorDir);
    if (cursorExists) {
      const cursorInstalled = await fileExists(cursorConfig);
      const hasMcp = cursorInstalled ? await configHasWondersuite(cursorConfig) : false;
      detectedIdes.push({
        name: 'Cursor', icon: 'cursor', detected: true, installed: hasMcp,
        configPath: cursorConfig, configType: 'cursor'
      });
    }

    // Windsurf (Codeium) — config lives at ~/.codeium/windsurf/mcp_config.json
    const windsurfDir = `${homeDir}/.codeium/windsurf`;
    const windsurfConfig = `${windsurfDir}/mcp_config.json`;
    const windsurfExists = await fileExists(windsurfDir);
    if (windsurfExists) {
      const windsurfInstalled = await fileExists(windsurfConfig);
      const hasMcp = windsurfInstalled ? await configHasWondersuite(windsurfConfig) : false;
      detectedIdes.push({
        name: 'Windsurf', icon: 'windsurf', detected: true, installed: hasMcp,
        configPath: windsurfConfig, configType: 'windsurf'
      });
    }

    // Antigravity — config lives at ~/.gemini/antigravity/mcp_config.json
    const antigravityDir = `${homeDir}/.gemini/antigravity`;
    const antigravityConfig = `${antigravityDir}/mcp_config.json`;
    const antigravityExists = await fileExists(antigravityDir);
    if (antigravityExists) {
      const antigravityInstalled = await fileExists(antigravityConfig);
      const hasMcp = antigravityInstalled ? await configHasWondersuite(antigravityConfig) : false;
      detectedIdes.push({
        name: 'Antigravity', icon: 'antigravity', detected: true, installed: hasMcp,
        configPath: antigravityConfig, configType: 'antigravity'
      });
    }

    // VS Code — config lives at ~/.vscode/mcp.json
    const vscodeDir = `${homeDir}/.vscode`;
    const vscodeConfig = `${vscodeDir}/mcp.json`;
    const vscodeExists = await fileExists(vscodeDir);
    if (vscodeExists) {
      const vscodeInstalled = await fileExists(vscodeConfig);
      const hasMcp = vscodeInstalled ? await configHasWondersuite(vscodeConfig) : false;
      detectedIdes.push({
        name: 'VS Code', icon: 'vscode', detected: true, installed: hasMcp,
        configPath: vscodeConfig, configType: 'vscode'
      });
    }

    // Void Editor — config lives at ~/.void-editor/mcp.json
    const voidDir = `${homeDir}/.void-editor`;
    const voidConfig = `${voidDir}/mcp.json`;
    const voidExists = await fileExists(voidDir);
    if (voidExists) {
      const voidInstalled = await fileExists(voidConfig);
      const hasMcp = voidInstalled ? await configHasWondersuite(voidConfig) : false;
      detectedIdes.push({
        name: 'Void', icon: 'void', detected: true, installed: hasMcp,
        configPath: voidConfig, configType: 'cursor'
      });
    }

    // Gemini CLI — config lives at ~/.gemini/settings/mcp.json
    const geminiDir = `${homeDir}/.gemini/settings`;
    const geminiConfig = `${geminiDir}/mcp.json`;
    const geminiExists = await fileExists(geminiDir);
    if (geminiExists) {
      const geminiInstalled = await fileExists(geminiConfig);
      const hasMcp = geminiInstalled ? await configHasWondersuite(geminiConfig) : false;
      detectedIdes.push({
        name: 'Gemini CLI', icon: 'gemini-cli', detected: true, installed: hasMcp,
        configPath: geminiConfig, configType: 'cursor'
      });
    }

    // If no IDEs detected, show common ones as not installed
    if (detectedIdes.length === 0) {
      detectedIdes.push(
        { name: 'Cursor', icon: 'cursor', detected: false, installed: false, configPath: '', configType: 'cursor' },
        { name: 'VS Code', icon: 'vscode', detected: false, installed: false, configPath: '', configType: 'vscode' },
      );
    }

    setIdes(detectedIdes);
  };

  const installMcp = async (ide: IdeInfo) => {
    setInstalling(ide.name);
    try {
      const config = generateMcpConfigForIde(mcpPort, ide.configType);

      // Write config file using Tauri
      const targetPath = ide.configPath;

      // Build the file content to write
      await writeMcpConfig(targetPath, config);

      setInstallStatus(prev => ({ ...prev, [ide.name]: 'success' }));
      setIdes(prev => prev.map(i =>
        i.name === ide.name ? { ...i, installed: true } : i
      ));
    } catch (e) {
      console.error(`Failed to install MCP for ${ide.name}:`, e);
      setInstallStatus(prev => ({ ...prev, [ide.name]: 'error' }));
    }
    setInstalling(null);
  };

  const ideIconColors: Record<string, string> = {
    cursor: '#00d4aa',
    windsurf: '#4e9eff',
    antigravity: '#a855f7',
    vscode: '#007acc',
    void: '#888888',
    'gemini-cli': '#4285F4',
  };

  return (
    <div className="settings-section">
      <h2>IDE Integration</h2>
      <p>Automatically install WonderSuite MCP tools into your AI code editors</p>

      <div className="ide-grid">
        {ides.map((ide) => {
          const status = installStatus[ide.name];
          const isInstalling = installing === ide.name;
          const color = ideIconColors[ide.icon] || '#64748b';

          return (
            <div key={ide.name} className="ide-card" style={{ borderColor: ide.detected ? `${color}30` : 'var(--border-0)' }}>
              <div className="ide-card-header">
                <div className="ide-icon" style={{ background: `${color}10`, color }}>
                  <IdeIconComponent type={ide.icon} size={22} />
                </div>
                <div className="ide-info">
                  <div className="ide-name">{ide.name}</div>
                  <div className="ide-status">
                    {ide.detected ? (
                      <span style={{ color: 'var(--green)', fontSize: 10, display: 'flex', alignItems: 'center', gap: 3 }}>
                        <Check size={10} /> Detected
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-3)', fontSize: 10 }}>Not found</span>
                    )}
                  </div>
                </div>
                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
                  {ide.installed && (
                    <span className="ide-installed-badge">
                      <Check size={9} /> Configured
                    </span>
                  )}
                </div>
              </div>

              {ide.detected && (
                <div className="ide-card-actions">
                  <div className="ide-config-path">
                    <span style={{ fontSize: 10, color: 'var(--text-3)' }}>{ide.configPath}</span>
                  </div>
                  <button
                    className={`ide-install-btn ${status === 'success' ? 'success' : status === 'error' ? 'error' : ''}`}
                    onClick={() => installMcp(ide)}
                    disabled={isInstalling}
                  >
                    {isInstalling ? (
                      <><RefreshCw size={11} className="spin" /> Installing...</>
                    ) : status === 'success' ? (
                      <><CheckCircle size={11} /> Installed</>
                    ) : status === 'error' ? (
                      <><AlertTriangle size={11} /> Retry</>
                    ) : ide.installed ? (
                      <><RefreshCw size={11} /> Reinstall</>
                    ) : (
                      <><Download size={11} /> Install MCP</>
                    )}
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Manual config */}
      <div style={{ marginTop: 16, padding: 12, background: 'var(--bg-1)', border: '1px solid var(--border-0)', borderRadius: 'var(--radius-m)' }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-0)', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Wrench size={11} /> Manual Configuration
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-2)', marginBottom: 8 }}>
          Add this to your IDE's MCP config file (mcp.json or settings):
        </div>
        <div style={{ position: 'relative' }}>
          <pre style={{
            fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--text-1)',
            background: 'var(--bg-0)', border: '1px solid var(--border-0)', borderRadius: 'var(--radius-s)',
            padding: 10, margin: 0, overflowX: 'auto', lineHeight: 1.5,
          }}>
{generateMcpConfigForIde(mcpPort, 'cursor')}
          </pre>
          <CopyButton text={generateMcpConfigForIde(mcpPort, 'cursor')} />
        </div>
      </div>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{
        position: 'absolute', top: 6, right: 6,
        background: copied ? 'var(--green)' : 'var(--bg-3)',
        border: 'none', borderRadius: 3, padding: '3px 8px',
        fontSize: 10, color: copied ? 'white' : 'var(--text-2)',
        cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3,
        transition: 'all 0.2s',
      }}
    >
      {copied ? <><Check size={9} /> Copied</> : <><Copy size={9} /> Copy</>}
    </button>
  );
}

// ── File system helpers (using Tauri backend) ───────────────────────
async function getHomeDir(): Promise<string> {
  try {
    const info = await invoke<any>('get_system_info');
    // Use home_dir directly, normalize to forward slashes for path joining
    return (info.home_dir || '').replace(/\\/g, '/');
  } catch {
    return 'C:/Users/ashom'; // fallback
  }
}

async function fileExists(path: string): Promise<boolean> {
  try {
    const normalized = path.replace(/\//g, '\\');
    const result = await invoke<boolean>('check_path_exists', { path: normalized });
    return !!result;
  } catch {
    return false;
  }
}

/** Check if an existing config file already has a 'wondersuite' entry */
async function configHasWondersuite(path: string): Promise<boolean> {
  try {
    const normalized = path.replace(/\//g, '\\');
    const content = await invoke<string>('read_file_content', { path: normalized });
    return content.includes('wondersuite');
  } catch {
    return false;
  }
}

async function writeMcpConfig(path: string, content: string): Promise<void> {
  const normalized = path.replace(/\//g, '\\');
  await invoke('write_mcp_config', { path: normalized, content }).catch(async (e) => {
    // Fallback: try to copy to clipboard
    console.warn('Could not write MCP config file directly. Copying to clipboard instead.', e);
    await navigator.clipboard.writeText(content);
    throw new Error('Config copied to clipboard. Please paste into ' + path);
  });
}

/** Proxy settings sub-component with real backend integration */
function ProxySettings({ proxyPort, onPortChange }: { proxyPort: string; onPortChange: (v: string) => void }) {
  const [proxyRunning, setProxyRunning] = useState(false);
  const [proxyStatus, setProxyStatus] = useState<any>(null);
  const [caCert, setCaCert] = useState<{ pem: string; path: string } | null>(null);
  const [copied, setCopied] = useState(false);
  // Match & Replace
  const [mrRules, setMrRules] = useState<any[]>([]);
  const [mrName, setMrName] = useState('');
  const [mrTarget, setMrTarget] = useState('request_header');
  const [mrMatch, setMrMatch] = useState('');
  const [mrReplace, setMrReplace] = useState('');
  const [mrIsRegex, setMrIsRegex] = useState(false);
  const [mrDirection, setMrDirection] = useState('both');
  // TLS Pass Through
  const [tlsEntries, setTlsEntries] = useState<any[]>([]);
  const [tlsHost, setTlsHost] = useState('');
  // Upstream Proxy
  const [upstream, setUpstream] = useState<any>({ enabled: false, proxy_type: 'http', host: '', port: 0, username: '', password: '' });
  // Interception Rules
  const [intRules, setIntRules] = useState<any[]>([]);
  // Response intercept
  const [responseIntercept, setResponseIntercept] = useState(false);
  // Expanded sections
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({ engine: true });

  const toggleSection = (s: string) => setExpandedSections(prev => ({ ...prev, [s]: !prev[s] }));

  useEffect(() => {
    const check = async () => {
      try {
        const status = await invoke<any>('proxy_status');
        setProxyRunning(status.running);
        setProxyStatus(status);
        setResponseIntercept(status.response_intercept_enabled || false);
      } catch {}
    };
    check();
    const i = setInterval(check, 2000);
    return () => clearInterval(i);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const [cert, mr, tls, up, ir] = await Promise.all([
          invoke<any>('proxy_get_ca_cert').catch(() => null),
          invoke<any[]>('proxy_get_match_replace_rules').catch(() => []),
          invoke<any[]>('proxy_get_tls_passthrough').catch(() => []),
          invoke<any>('proxy_get_upstream').catch(() => ({ enabled: false, proxy_type: 'http', host: '', port: 0 })),
          invoke<any[]>('proxy_get_interception_rules').catch(() => []),
        ]);
        if (cert) setCaCert(cert);
        setMrRules(mr);
        setTlsEntries(tls);
        setUpstream(up);
        setIntRules(ir);
      } catch {}
    })();
  }, []);

  const startProxy = async () => { try { await invoke('proxy_start', { port: parseInt(proxyPort) }); setProxyRunning(true); } catch (e) { console.error(e); } };
  const stopProxy = async () => { try { await invoke('proxy_stop'); setProxyRunning(false); } catch (e) { console.error(e); } };
  const copyCaCert = () => { if (caCert?.pem) { navigator.clipboard.writeText(caCert.pem); setCopied(true); setTimeout(() => setCopied(false), 2000); } };

  const addMrRule = async () => {
    if (!mrName || !mrMatch) return;
    const rule = { id: crypto.randomUUID(), enabled: true, name: mrName, target: mrTarget, match_pattern: mrMatch, replace_value: mrReplace, is_regex: mrIsRegex, direction: mrDirection };
    try { await invoke('proxy_add_match_replace_rule', { rule }); setMrRules(r => [...r, rule]); setMrName(''); setMrMatch(''); setMrReplace(''); } catch (e) { console.error(e); }
  };
  const removeMrRule = async (id: string) => { try { await invoke('proxy_remove_match_replace_rule', { id }); setMrRules(r => r.filter(x => x.id !== id)); } catch {} };

  const addTlsEntry = async () => {
    if (!tlsHost) return;
    const entry = { id: crypto.randomUUID(), enabled: true, host: tlsHost, port: null, notes: '' };
    try { await invoke('proxy_add_tls_passthrough', { entry }); setTlsEntries(e => [...e, entry]); setTlsHost(''); } catch (e) { console.error(e); }
  };
  const removeTlsEntry = async (id: string) => { try { await invoke('proxy_remove_tls_passthrough', { id }); setTlsEntries(e => e.filter(x => x.id !== id)); } catch {} };

  const saveUpstream = async () => { try { await invoke('proxy_set_upstream', { config: upstream }); } catch (e) { console.error(e); } };

  const toggleResponseIntercept = async () => {
    const next = !responseIntercept;
    try { await invoke('proxy_toggle_response_intercept', { enabled: next }); setResponseIntercept(next); } catch {}
  };

  const sectionHeader = (key: string, label: string, icon: React.ReactNode, count?: number) => (
    <div className="settings-section-header" style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none', marginBottom: expandedSections[key] ? 12 : 4 }} onClick={() => toggleSection(key)}>
      <span style={{ fontSize: 10, color: 'var(--text-3)', transition: 'transform .15s', transform: expandedSections[key] ? 'rotate(90deg)' : 'rotate(0deg)', display: 'inline-block' }}>▶</span>
      <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 6 }}>{icon} {label}</span>
      {count !== undefined && <span style={{ fontSize: 10, color: 'var(--text-3)', background: 'var(--bg-3)', borderRadius: 3, padding: '1px 6px' }}>{count}</span>}
    </div>
  );

  return (
    <>
      {/* ─── Proxy Engine ─── */}
      <div className="settings-section">
        {sectionHeader('engine', 'Proxy Engine', <Zap size={12} />)}
        {expandedSections.engine && <>
          <div className="mcp-status">
            <div className={`mcp-status-dot ${proxyRunning ? 'running' : 'stopped'}`} />
            <div className="mcp-status-text">
              <strong>{proxyRunning ? 'Running' : 'Stopped'}</strong>
              <span>{proxyRunning
                ? `127.0.0.1:${proxyPort} · ${proxyStatus?.total_requests || 0} requests · ${proxyStatus?.cached_certs || 0} certs · ${proxyStatus?.websocket_messages || 0} WS`
                : 'Proxy is not running'
              }</span>
            </div>
            <button className={`mcp-btn ${proxyRunning ? 'stop' : 'start'}`} onClick={proxyRunning ? stopProxy : startProxy}>
              <Power size={12} style={{ marginRight: 4 }} />{proxyRunning ? 'Stop' : 'Start'}
            </button>
          </div>

          <div className="settings-row">
            <div className="settings-label">Listen port<span>TCP port for proxy listener</span></div>
            <input className="settings-input" value={proxyPort} onChange={(e) => onPortChange(e.target.value)} disabled={proxyRunning} style={{ minWidth: 80 }} />
          </div>
          <div className="settings-row">
            <div className="settings-label">Listen interface<span>Network interface to bind</span></div>
            <input className="settings-input" defaultValue="127.0.0.1" disabled={proxyRunning} style={{ minWidth: 120 }} />
          </div>
          <div className="settings-row">
            <div className="settings-label">Intercept responses<span>Also pause and edit server responses</span></div>
            <button className={`settings-toggle ${responseIntercept ? 'on' : ''}`} onClick={toggleResponseIntercept} />
          </div>
        </>}
      </div>

      {/* ─── Match & Replace ─── */}
      <div className="settings-section">
        {sectionHeader('mr', 'Match & Replace', <RefreshCw size={12} />, mrRules.length)}
        {expandedSections.mr && <>
          <p style={{ fontSize: 11, color: 'var(--text-2)', margin: '0 0 10px' }}>Automatic in-flight modification of HTTP traffic</p>
          {mrRules.map(r => (
            <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', background: 'var(--bg-0)', border: '1px solid var(--border-0)', borderRadius: 'var(--radius-s)', marginBottom: 4, fontSize: 11 }}>
              <span style={{ fontWeight: 600, color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>●</span>
              <span style={{ fontWeight: 600, color: 'var(--text-0)', minWidth: 80 }}>{r.name}</span>
              <span style={{ color: 'var(--text-3)', fontSize: 10, padding: '1px 5px', background: 'var(--bg-3)', borderRadius: 3 }}>{r.target}</span>
              <span style={{ fontFamily: 'monospace', color: 'var(--red)', fontSize: 10 }}>{r.match_pattern}</span>
              <span style={{ color: 'var(--text-3)' }}>→</span>
              <span style={{ fontFamily: 'monospace', color: 'var(--green)', fontSize: 10 }}>{r.replace_value || '(empty)'}</span>
              {r.is_regex && <span style={{ fontSize: 9, color: 'var(--accent)', border: '1px solid var(--accent)', borderRadius: 2, padding: '0 3px' }}>regex</span>}
              <span style={{ flex: 1 }} />
              <button style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 14, padding: 0 }} onClick={() => removeMrRule(r.id)}>×</button>
            </div>
          ))}
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap', marginTop: 8 }}>
            <input className="settings-input" placeholder="Rule name" value={mrName} onChange={e => setMrName(e.target.value)} style={{ minWidth: 80, flex: '0 0 80px' }} />
            <select className="settings-input" value={mrTarget} onChange={e => setMrTarget(e.target.value)} style={{ minWidth: 100 }}>
              <option value="request_header">Req Header</option>
              <option value="request_body">Req Body</option>
              <option value="response_header">Resp Header</option>
              <option value="response_body">Resp Body</option>
              <option value="request_url">Req URL</option>
            </select>
            <input className="settings-input" placeholder="Match" value={mrMatch} onChange={e => setMrMatch(e.target.value)} style={{ flex: 1, minWidth: 80 }} />
            <input className="settings-input" placeholder="Replace" value={mrReplace} onChange={e => setMrReplace(e.target.value)} style={{ flex: 1, minWidth: 80 }} />
            <label style={{ fontSize: 10, color: 'var(--text-2)', display: 'flex', alignItems: 'center', gap: 3, cursor: 'pointer' }}>
              <input type="checkbox" checked={mrIsRegex} onChange={e => setMrIsRegex(e.target.checked)} /> Regex
            </label>
            <select className="settings-input" value={mrDirection} onChange={e => setMrDirection(e.target.value)} style={{ minWidth: 60 }}>
              <option value="both">Both</option>
              <option value="request">Request</option>
              <option value="response">Response</option>
            </select>
            <button className="mcp-btn start" onClick={addMrRule} style={{ padding: '3px 10px', fontSize: 11 }}>+ Add</button>
          </div>
        </>}
      </div>

      {/* ─── TLS Pass Through ─── */}
      <div className="settings-section">
        {sectionHeader('tls', 'TLS Pass Through', <Unlock size={12} />, tlsEntries.length)}
        {expandedSections.tls && <>
          <p style={{ fontSize: 11, color: 'var(--text-2)', margin: '0 0 10px' }}>Skip MITM interception for these hosts (raw TCP tunnel)</p>
          {tlsEntries.map(e => (
            <div key={e.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', background: 'var(--bg-0)', border: '1px solid var(--border-0)', borderRadius: 'var(--radius-s)', marginBottom: 4, fontSize: 11 }}>
              <span style={{ fontFamily: 'monospace', color: 'var(--text-0)' }}>{e.host}</span>
              {e.port && <span style={{ color: 'var(--text-3)' }}>:{e.port}</span>}
              <span style={{ flex: 1 }} />
              <button style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: 14, padding: 0 }} onClick={() => removeTlsEntry(e.id)}>×</button>
            </div>
          ))}
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 8 }}>
            <input className="settings-input" placeholder="*.google.com" value={tlsHost} onChange={e => setTlsHost(e.target.value)} style={{ flex: 1 }} />
            <button className="mcp-btn start" onClick={addTlsEntry} style={{ padding: '3px 10px', fontSize: 11 }}>+ Add</button>
          </div>
        </>}
      </div>

      {/* ─── Upstream Proxy ─── */}
      <div className="settings-section">
        {sectionHeader('upstream', 'Upstream Proxy', <Link size={12} />)}
        {expandedSections.upstream && <>
          <p style={{ fontSize: 11, color: 'var(--text-2)', margin: '0 0 10px' }}>Route all proxy traffic through an upstream HTTP or SOCKS5 proxy</p>
          <div className="settings-row">
            <div className="settings-label">Enable upstream proxy<span>Chain traffic through another proxy</span></div>
            <button className={`settings-toggle ${upstream.enabled ? 'on' : ''}`} onClick={() => { const u = { ...upstream, enabled: !upstream.enabled }; setUpstream(u); }} />
          </div>
          {upstream.enabled && <>
            <div className="settings-row">
              <div className="settings-label">Protocol<span>HTTP or SOCKS5</span></div>
              <select className="settings-input" value={upstream.proxy_type} onChange={e => setUpstream({ ...upstream, proxy_type: e.target.value })} style={{ minWidth: 80 }}>
                <option value="http">HTTP</option>
                <option value="socks5">SOCKS5</option>
              </select>
            </div>
            <div className="settings-row">
              <div className="settings-label">Host<span>Upstream proxy address</span></div>
              <input className="settings-input" value={upstream.host} onChange={e => setUpstream({ ...upstream, host: e.target.value })} placeholder="127.0.0.1" style={{ minWidth: 140 }} />
            </div>
            <div className="settings-row">
              <div className="settings-label">Port<span>Upstream proxy port</span></div>
              <input className="settings-input" type="number" value={upstream.port} onChange={e => setUpstream({ ...upstream, port: parseInt(e.target.value) || 0 })} style={{ minWidth: 80 }} />
            </div>
            <div className="settings-row">
              <div className="settings-label">Username<span>Optional authentication</span></div>
              <input className="settings-input" value={upstream.username || ''} onChange={e => setUpstream({ ...upstream, username: e.target.value })} style={{ minWidth: 140 }} />
            </div>
            <div className="settings-row">
              <div className="settings-label">Password<span>Optional authentication</span></div>
              <input className="settings-input" type="password" value={upstream.password || ''} onChange={e => setUpstream({ ...upstream, password: e.target.value })} style={{ minWidth: 140 }} />
            </div>
            <button className="mcp-btn start" onClick={saveUpstream} style={{ marginTop: 8, padding: '4px 16px', fontSize: 11 }}>Save Upstream Config</button>
          </>}
        </>}
      </div>

      {/* ─── Interception Rules ─── */}
      <div className="settings-section">
        {sectionHeader('rules', 'Interception Rules', <List size={12} />, intRules.length)}
        {expandedSections.rules && <>
          <p style={{ fontSize: 11, color: 'var(--text-2)', margin: '0 0 10px' }}>Control which requests/responses are intercepted vs. passed through</p>
          {intRules.map(r => (
            <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', background: 'var(--bg-0)', border: '1px solid var(--border-0)', borderRadius: 'var(--radius-s)', marginBottom: 4, fontSize: 11 }}>
              <span style={{ fontWeight: 600, color: r.enabled ? 'var(--green)' : 'var(--text-3)' }}>●</span>
              <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>{r.name}</span>
              <span style={{ fontSize: 10, color: 'var(--text-3)', padding: '1px 5px', background: 'var(--bg-3)', borderRadius: 3 }}>{r.action}</span>
            </div>
          ))}
        </>}
      </div>

      {/* ─── CA Certificate ─── */}
      <div className="settings-section">
        {sectionHeader('ca', 'CA Certificate', <Lock size={12} />)}
        {expandedSections.ca && caCert && <>
          <p style={{ fontSize: 11, color: 'var(--text-2)', margin: '0 0 10px' }}>Install this certificate as Trusted Root CA for HTTPS interception</p>
          <div className="settings-row">
            <div className="settings-label">Certificate file<span style={{ wordBreak: 'break-all' }}>{caCert.path}</span></div>
            <button className="mcp-btn start" onClick={copyCaCert} style={{ minWidth: 100 }}>
              {copied ? <><CheckCircle size={12} style={{ marginRight: 4 }} /> Copied</> : <><Copy size={12} style={{ marginRight: 4 }} /> Copy PEM</>}
            </button>
          </div>
          <div style={{ marginTop: 8, padding: 8, background: 'var(--bg-0)', border: '1px solid var(--border-0)', borderRadius: 'var(--radius-s)', maxHeight: 100, overflow: 'auto' }}>
            <pre style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: 'var(--text-2)', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {caCert.pem.slice(0, 400)}...
            </pre>
          </div>
        </>}
      </div>
    </>
  );
}

/** System information panel for General settings */
function GeneralSystemInfo() {
  const [sysInfo, setSysInfo] = useState<any>(null);
  const [browsers, setBrowsers] = useState<any[]>([]);

  useEffect(() => {
    (async () => {
      try {
        const [info, brs] = await Promise.all([
          invoke<any>('get_system_info'),
          invoke<any>('browser_detect'),
        ]);
        setSysInfo(info);
        setBrowsers(brs);
      } catch {}
    })();
  }, []);

  if (!sysInfo) return null;

  return (
    <div className="settings-section">
      <h2>System Information</h2>
      <p>Platform and architecture details</p>

      <div className="settings-row">
        <div className="settings-label">
          Architecture
          <span>CPU instruction set</span>
        </div>
        <span style={{
          padding: '2px 10px',
          borderRadius: 3,
          fontSize: 11,
          fontWeight: 700,
          letterSpacing: '0.03em',
          background: sysInfo.is_arm ? 'rgba(200,120,255,0.15)' : 'rgba(100,180,255,0.15)',
          color: sysInfo.is_arm ? '#c878ff' : '#64b4ff',
          border: `1px solid ${sysInfo.is_arm ? 'rgba(200,120,255,0.25)' : 'rgba(100,180,255,0.25)'}`,
        }}>
          {sysInfo.arch_display}
        </span>
      </div>

      <div className="settings-row">
        <div className="settings-label">
          Operating System
          <span>Windows version</span>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-0)', fontFamily: 'JetBrains Mono, monospace' }}>
          {sysInfo.os_version}
        </span>
      </div>

      <div className="settings-row">
        <div className="settings-label">
          CPU Cores
          <span>Available parallelism</span>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-0)', fontWeight: 600 }}>
          {sysInfo.cpu_cores}
        </span>
      </div>

      <div className="settings-row">
        <div className="settings-label">
          Data Directory
          <span>WonderSuite configuration path</span>
        </div>
        <span style={{ fontSize: 10, color: 'var(--text-2)', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all' }}>
          {sysInfo.wondersuite_dir}
        </span>
      </div>

      {browsers.length > 0 && (
        <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 8 }}>
          <div className="settings-label">
            Detected Browsers ({browsers.length})
            <span>Available for WonderBrowser</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, width: '100%' }}>
            {browsers.map((b: any, i: number) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '4px 8px', background: 'var(--bg-0)',
                border: '1px solid var(--border-0)', borderRadius: 'var(--radius-s)',
                fontSize: 11,
              }}>
                <span style={{ fontWeight: 600, color: 'var(--text-0)' }}>{b.name}</span>
                <span style={{ color: 'var(--text-3)', fontFamily: 'JetBrains Mono, monospace', fontSize: 10 }}>{b.version}</span>
                <span style={{ marginLeft: 'auto', fontSize: 9, color: 'var(--text-3)', padding: '1px 5px', background: 'var(--bg-3)', borderRadius: 2, fontWeight: 600 }}>{b.engine}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
