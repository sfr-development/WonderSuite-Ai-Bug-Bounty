import { useState, useEffect } from 'react';
import { Wrench, Palette, Shield, Plug, Power, Copy, CheckCircle, Zap, RefreshCw, Unlock, Link, List, Lock, Download, Check, AlertTriangle, Search, ZoomIn, LayoutGrid, Moon, Sun, Terminal, Globe } from 'lucide-react';
import { BrowserSettingsPanel } from './BrowserSettingsPanel';
import { invoke } from '@tauri-apps/api/core';
import { useAppStore } from '../../stores';
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

type SettingsTab = 'general' | 'mcp' | 'proxy' | 'appearance' | 'browser';


interface McpToolEntry {
  name: string;
  desc: string;
  category: string;
}

function categorize(name: string): string {
  if (/^proxy_(get_traffic|search_traffic|clear_traffic|export_traffic)/.test(name)) return 'traffic';
  if (name.startsWith('proxy_')) return 'proxy';
  if (name.startsWith('browser_')) return 'browser';
  if (name.startsWith('agent_browser_')) return 'browser';
  if (name.startsWith('session_')) return 'session';
  if (name.startsWith('websocket_') || name.startsWith('ws_')) return 'websocket';
  if (name.startsWith('oast_')) return 'oast';
  if (name.startsWith('scanner_') || name === 'active_scan' || name === 'passive_scan') return 'scanner';
  if (name.startsWith('intruder_') || name === 'fuzz_request') return 'intruder';
  if (/^(crtsh|wayback|whois|asn|favicon|reverse_ip|hackertarget|ip_geolocation|tech_detect)/.test(name)) return 'osint';
  if (/^(encode|decode|hash|analyze_jwt|smart_decode)$/.test(name)) return 'codec';
  if (/^(send_request|mtls_send_request|h2_send_request|send_to_repeater)$/.test(name)) return 'http';
  if (/^(crawl_target|discover_|find_secrets|dns_resolve|js_link_finder|graphql_introspect)/.test(name)) return 'recon';
  if (/^(raw_tcp_send|race_request)$/.test(name)) return 'exploit';
  if (/^(bambda_filter|generate_report)$/.test(name)) return 'tools';
  return 'other';
}

const categoryColors: Record<string, string> = {
  http: '#3b82f6', codec: '#8b5cf6', proxy: '#06b6d4', traffic: '#0ea5e9',
  browser: '#22c55e', tools: '#64748b', session: '#ec4899', websocket: '#a855f7',
  recon: '#f97316', exploit: '#dc2626', oast: '#e11d48', osint: '#10b981',
  scanner: '#eab308', intruder: '#f59e0b', other: '#94a3b8',
};

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
    return JSON.stringify({
      mcpServers: {
        wondersuite: {
          serverUrl: serverUrl,
        }
      }
    }, null, 2);
  }

  return JSON.stringify({
    mcpServers: {
      wondersuite: {
        url: serverUrl,
      }
    }
  }, null, 2);
}

export function Settings() {
  const { appearance, updateAppearance } = useAppStore();
  const [tab, setTab] = useState<SettingsTab>('mcp');
  const [mcpRunning, setMcpRunning] = useState(false);
  const [mcpPort, setMcpPort] = useState('3100');
  const [proxyPort, setProxyPort] = useState('8080');
  const [toolFilter, setToolFilter] = useState('');
  const [mcpError, setMcpError] = useState('');
  const [mcpTools, setMcpTools] = useState<McpToolEntry[]>([]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await invoke<Array<{ name: string; description: string }>>('mcp_list_tools');
        if (!cancelled) {
          setMcpTools(list.map(t => ({
            name: t.name,
            desc: t.description ?? '',
            category: categorize(t.name),
          })));
        }
      } catch {
        if (!cancelled) setMcpTools([]);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const running = await invoke<boolean>('mcp_status');
        setMcpRunning(running);
        if (!running) {
          try {
            await invoke('mcp_start', { port: parseInt(mcpPort) });
            setMcpRunning(true);
            console.log('[MCP] Started on port', mcpPort);
          } catch (startErr: any) {
            const errStr = String(startErr);
            if (errStr.includes('10048') || errStr.includes('already') || errStr.includes('in use')) {
              setMcpRunning(true);
              setMcpError('');
            } else {
              console.error('[MCP] Start failed:', startErr);
              setMcpError(errStr);
            }
          }
        }
      } catch (e: any) {
        console.error('[MCP] Status check error:', e);
        try {
          const resp = await fetch(`http://127.0.0.1:${mcpPort}/mcp`);
          if (resp.ok) {
            setMcpRunning(true);
            setMcpError('');
          }
        } catch { /* server truly not reachable */ }
      }
    };
    checkStatus();
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
        <button className={`settings-nav-item ${tab === 'browser' ? 'active' : ''}`} onClick={() => setTab('browser')}>
          <Globe size={14} /> Browser
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
            
            <GlobalScopeSettings />
          </div>
          </>
        )}

        {tab === 'proxy' && (
          <ProxySettings proxyPort={proxyPort} onPortChange={setProxyPort} />
        )}

        {tab === 'appearance' && (
          <div className="settings-section">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 16 }}>
              <Palette size={16} />
              <h2 style={{ margin: 0 }}>Appearance</h2>
            </div>
            <p style={{ color: 'var(--text-2)', fontSize: 11, marginBottom: 24 }}>Customize the visual interface of the suite to match your working style.</p>

            <div className="settings-row" style={{ alignItems: 'flex-start' }}>
              <div className="settings-label">
                Color Theme
                <span>Choose your preferred color palette</span>
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {[
                  { id: 'dark', label: 'Dark', icon: <Moon size={20} />, bg: '#1a1a1a', border: '#333' },
                  { id: 'light', label: 'Light', icon: <Sun size={20} />, bg: '#f8f9fa', border: '#dee2e6' },
                  { id: 'hacker', label: 'Hacker', icon: <Terminal size={20} />, bg: '#000000', border: '#39ff1440' }
                ].map(t => (
                  <div key={t.id} 
                       onClick={() => updateAppearance({ theme: t.id })}
                       style={{
                         display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, 
                         padding: '12px 16px', background: t.bg, border: `2px solid ${appearance.theme === t.id ? 'var(--accent)' : t.border}`,
                         borderRadius: 'var(--radius-m)', cursor: 'pointer', transition: 'var(--transition)',
                         minWidth: 80, filter: appearance.theme !== t.id ? 'opacity(0.6)' : 'none'
                       }}>
                    <div style={{ color: t.id === 'light' ? '#000' : (t.id === 'hacker' ? '#39ff14' : '#fff') }}>{t.icon}</div>
                    <span style={{ fontSize: 11, fontWeight: 600, color: t.id === 'light' ? '#000' : (t.id === 'hacker' ? '#39ff14' : '#fff') }}>{t.label}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="settings-row" style={{ alignItems: 'flex-start' }}>
              <div className="settings-label">
                Accent Color
                <span>Primary color for active states and highlights</span>
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {['#e8a145', '#5b9fd6', '#a78bda', '#4ec58a', '#d95757', '#e8873c', '#56c5c5'].map(color => (
                  <button key={color} onClick={() => updateAppearance({ accentColor: color })}
                          style={{
                            width: 28, height: 28, borderRadius: '50%', background: color, 
                            border: `2px solid ${appearance.accentColor === color ? 'white' : 'transparent'}`,
                            cursor: 'pointer', outline: 'none', transition: 'transform 0.15s',
                            transform: appearance.accentColor === color ? 'scale(1.15)' : 'scale(1)',
                            boxShadow: appearance.accentColor === color ? `0 0 10px ${color}80` : 'none'
                          }} />
                ))}
              </div>
            </div>

            <div className="settings-row">
              <div className="settings-label">
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}><ZoomIn size={12} /> UI Zoom Scale</div>
                <span>Zoom the entire interface in (%)</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <input type="range" min="80" max="130" step="5" 
                       value={appearance.uiScale} 
                       onChange={(e) => updateAppearance({ uiScale: parseInt(e.target.value) })}
                       style={{ width: 150 }} />
                <span style={{ fontSize: 11, fontFamily: 'monospace', width: 35 }}>{appearance.uiScale}%</span>
              </div>
            </div>

            <div className="settings-row">
              <div className="settings-label">
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}><LayoutGrid size={12} /> Compact Mode</div>
                <span>Reduce margins and padding to fit more data</span>
              </div>
              <button className={`settings-toggle ${appearance.compactMode ? 'on' : ''}`}
                      onClick={() => updateAppearance({ compactMode: !appearance.compactMode })} />
            </div>
          </div>
        )}

        {tab === 'browser' && <BrowserSettingsPanel />}
      </div>
    </div>
  );
}


function IdeIntegration({ mcpPort, mcpRunning: _mcpRunning }: { mcpPort: string; mcpRunning: boolean }) {
  const [ides, setIdes] = useState<IdeInfo[]>([]);
  const [installing, setInstalling] = useState<string | null>(null);
  const [installStatus, setInstallStatus] = useState<Record<string, 'success' | 'error' | null>>({});

  useEffect(() => {
    detectIdes();
  }, []);

  const detectIdes = async () => {
    const homeDir = await getHomeDir();
    const detectedIdes: IdeInfo[] = [];

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

      const targetPath = ide.configPath;

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

async function getHomeDir(): Promise<string> {
  try {
    const info = await invoke<any>('get_system_info');
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
  const [mrRules, setMrRules] = useState<any[]>([]);
  const [mrName, setMrName] = useState('');
  const [mrTarget, setMrTarget] = useState('request_header');
  const [mrMatch, setMrMatch] = useState('');
  const [mrReplace, setMrReplace] = useState('');
  const [mrIsRegex, setMrIsRegex] = useState(false);
  const [mrDirection, setMrDirection] = useState('both');
  const [tlsEntries, setTlsEntries] = useState<any[]>([]);
  const [tlsHost, setTlsHost] = useState('');
  const [upstream, setUpstream] = useState<any>({ enabled: false, proxy_type: 'http', host: '', port: 0, username: '', password: '' });
  const [intRules, setIntRules] = useState<any[]>([]);
  const [responseIntercept, setResponseIntercept] = useState(false);
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

  const startProxy = async () => { try { await invoke('proxy_start', { port: parseInt(proxyPort) }); setProxyRunning(true); } catch (e) { console.error(e); alert(e); } };
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

function GlobalScopeSettings() {
  const { globalScope, addScope, removeScope } = useAppStore();
  const [newScope, setNewScope] = useState('');

  const handleAdd = () => {
    if (newScope.trim()) {
      addScope(newScope.trim());
      setNewScope('');
    }
  };

  return (
    <div style={{ marginTop: 24, paddingTop: 16, borderTop: '1px solid var(--border-0)' }}>
      <h3>Global Target Scope</h3>
      <p style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 12 }}>
        Define URL patterns or hostnames that are in-scope for your assessment. 
        When populated, you can filter Traffic, Intruders, and Scanners to only show in-scope items.
      </p>
      
      {globalScope.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 12 }}>
          {globalScope.map((scope) => (
            <div key={scope} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '6px 12px', background: 'var(--bg-0)', border: '1px solid var(--border-0)',
              borderRadius: 'var(--radius-s)', fontSize: 11, fontFamily: 'monospace'
            }}>
              <span style={{ color: 'var(--text-0)' }}>{scope}</span>
              <button 
                onClick={() => removeScope(scope)}
                style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer' }}
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8 }}>
        <input 
          className="settings-input" 
          placeholder="e.g. *.example.com or regex" 
          value={newScope} 
          onChange={(e) => setNewScope(e.target.value)} 
          onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
          style={{ flex: 1 }}
        />
        <button className="mcp-btn start" onClick={handleAdd}>Add Scope</button>
      </div>
    </div>
  );
}
