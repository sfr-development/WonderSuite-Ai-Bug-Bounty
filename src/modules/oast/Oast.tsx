import { useState, useEffect, useCallback, useRef } from 'react';
import { Radio, Plus, Trash2, RefreshCcw, Wifi, Copy, Zap, Bug, Globe, Mail, Search } from 'lucide-react';
import './Oast.css';

interface OastPayload {
  id: string; correlation_id: string; subdomain: string; full_url: string;
  dns_payload: string; http_payload: string; smtp_payload: string;
  created_at: string; description: string;
}

interface OastInteraction {
  id: string; correlation_id: string; interaction_type: string;
  source_ip: string; timestamp: string; raw_data: string;
  details: Record<string, string>;
}

interface ServerStatus {
  http_running: boolean; http_port: number;
  dns_running: boolean; dns_port: number;
  smtp_running: boolean; smtp_port: number;
}

type Tab = 'server' | 'payloads' | 'interactions' | 'collaborator';

export function Oast() {
  const [tab, setTab] = useState<Tab>('server');
  const [status, setStatus] = useState<ServerStatus | null>(null);
  const [payloads, setPayloads] = useState<OastPayload[]>([]);
  const [interactions, setInteractions] = useState<OastInteraction[]>([]);
  const [selectedPayload, setSelectedPayload] = useState<OastPayload | null>(null);
  const [selectedInteraction, setSelectedInteraction] = useState<OastInteraction | null>(null);

  const [genDesc, setGenDesc] = useState('');
  const [genType, setGenType] = useState('generic');
  const [genTarget, setGenTarget] = useState('');
  const [serverDomain, setServerDomain] = useState<string>(() => localStorage.getItem('ws_oast_domain') || 'oast.wondersuite.local');
  const [collabHeaders, setCollabHeaders] = useState<Array<{ header: string; value: string; oast_payload: OastPayload }>>([]);

  const [filter, setFilter] = useState('');

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const s: ServerStatus = await invoke('oast_status');
      setStatus(s);
    } catch { /* ignore */ }
  }, []);

  const loadPayloads = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const p: OastPayload[] = await invoke('oast_get_payloads');
      setPayloads(p);
    } catch { setPayloads([]); }
  }, []);

  const loadInteractions = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const i: OastInteraction[] = await invoke('oast_poll_interactions', { correlationId: null });
      setInteractions(i);
    } catch { setInteractions([]); }
  }, []);

  useEffect(() => {
    loadStatus(); loadPayloads(); loadInteractions();
    pollRef.current = setInterval(() => { loadInteractions(); loadStatus(); }, 3000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  useEffect(() => {
    localStorage.setItem('ws_oast_domain', serverDomain);
  }, [serverDomain]);

  const startHttp = async (port?: number) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('oast_start_http', { port: port || 8888 });
      loadStatus();
    } catch (e) { console.error(e); }
  };
  const stopHttp = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('oast_stop_http');
      loadStatus();
    } catch (e) { console.error(e); }
  };

  const startDns = async (port?: number) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('oast_start_dns', { port: port || 8853 });
      loadStatus();
    } catch (e) { console.error(e); }
  };
  const stopDns = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('oast_stop_dns');
      loadStatus();
    } catch (e) { console.error(e); }
  };

  const startSmtp = async (port?: number) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('oast_start_smtp', { port: port || 2525 });
      loadStatus();
    } catch (e) { console.error(e); }
  };
  const stopSmtp = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('oast_stop_smtp');
      loadStatus();
    } catch (e) { console.error(e); }
  };

  const generate = async () => {
    if (!genDesc) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('oast_generate', { description: genDesc, vulnType: genType !== 'generic' ? genType : null, serverDomain });
      setGenDesc('');
      loadPayloads();
    } catch (e) { console.error(e); }
  };

  const generateScanPayloads = async () => {
    if (!genTarget) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('oast_generate_scan_payloads', { target: genTarget, serverDomain });
      loadPayloads();
    } catch (e) { console.error(e); }
  };

  const generateCollaborator = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const headers: Array<{ header: string; value: string; oast_payload: OastPayload }> =
        await invoke('oast_collaborator_everywhere', { serverDomain });
      setCollabHeaders(headers);
      loadPayloads();
    } catch (e) { console.error(e); }
  };

  const clearAll = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('oast_clear');
      setPayloads([]); setInteractions([]);
      setSelectedPayload(null); setSelectedInteraction(null);
    } catch (e) { console.error(e); }
  };

  const copyText = (text: string) => navigator.clipboard.writeText(text);

  const filteredPayloads = payloads.filter(p =>
    !filter || p.description.toLowerCase().includes(filter.toLowerCase()) ||
    p.correlation_id.includes(filter)
  );

  const filteredInteractions = interactions.filter(i =>
    !filter || i.correlation_id.includes(filter) ||
    i.interaction_type.includes(filter) || i.source_ip.includes(filter)
  );

  const interactionCounts: Record<string, number> = {};
  interactions.forEach(i => { interactionCounts[i.correlation_id] = (interactionCounts[i.correlation_id] || 0) + 1; });

  return (
    <div className="oast">
      <div className="oast-toolbar">
        <Radio size={14} />
        <span className="oast-toolbar-title">OAST / Collaborator</span>
        <div style={{ flex: 1 }} />
        <button className="oast-action-btn" onClick={() => { loadPayloads(); loadInteractions(); }}><RefreshCcw size={10} /> Refresh</button>
        <button className="oast-action-btn danger" onClick={clearAll}><Trash2 size={10} /> Clear All</button>
      </div>

      <div className="oast-tabs">
        <button className={`oast-tab ${tab === 'server' ? 'active' : ''}`} onClick={() => setTab('server')}>
          <Wifi size={10} /> Server
        </button>
        <button className={`oast-tab ${tab === 'payloads' ? 'active' : ''}`} onClick={() => setTab('payloads')}>
          <Bug size={10} /> Payloads <span className="oast-badge">{payloads.length}</span>
        </button>
        <button className={`oast-tab ${tab === 'interactions' ? 'active' : ''}`} onClick={() => setTab('interactions')}>
          <Zap size={10} /> Interactions <span className={`oast-badge ${interactions.length > 0 ? 'hit' : ''}`}>{interactions.length}</span>
        </button>
        <button className={`oast-tab ${tab === 'collaborator' ? 'active' : ''}`} onClick={() => setTab('collaborator')}>
          <Globe size={10} /> Collaborator Everywhere
        </button>
      </div>

      <div className="oast-body">
        {/* Server Tab */}
        {tab === 'server' && (
          <div className="oast-server-panel">
            <div className="oast-server-grid">
              {/* HTTP Server */}
              <div className="oast-server-card">
                <div className="oast-server-card-header">
                  <Globe size={16} />
                  <span>HTTP Callback Server</span>
                  <span className={`oast-status-dot ${status?.http_running ? 'on' : ''}`} />
                </div>
                <div className="oast-server-card-body">
                  <span className="oast-dim">Port: {status?.http_port || 8888}</span>
                  <span className={`oast-server-state ${status?.http_running ? 'running' : ''}`}>
                    {status?.http_running ? 'Running' : 'Stopped'}
                  </span>
                </div>
                {!status?.http_running ? (
                  <button className="oast-start-btn" onClick={() => startHttp()}>
                    <Wifi size={10} /> Start HTTP Server
                  </button>
                ) : (
                  <button className="oast-start-btn" onClick={stopHttp} style={{ background: 'rgba(239,68,68,0.15)', borderColor: '#ef4444', color: '#fca5a5' }}>
                    <Wifi size={10} /> Stop HTTP Server
                  </button>
                )}
              </div>

              {/* DNS Server */}
              <div className="oast-server-card">
                <div className="oast-server-card-header">
                  <Radio size={16} />
                  <span>DNS Callback Server</span>
                  <span className={`oast-status-dot ${status?.dns_running ? 'on' : ''}`} />
                </div>
                <div className="oast-server-card-body">
                  <span className="oast-dim">Port: {status?.dns_port || 8853}</span>
                  <span className={`oast-server-state ${status?.dns_running ? 'running' : ''}`}>
                    {status?.dns_running ? 'Running' : 'Stopped'}
                  </span>
                </div>
                {!status?.dns_running ? (
                  <button className="oast-start-btn" onClick={() => startDns()}>
                    <Wifi size={10} /> Start DNS Server
                  </button>
                ) : (
                  <button className="oast-start-btn" onClick={stopDns} style={{ background: 'rgba(239,68,68,0.15)', borderColor: '#ef4444', color: '#fca5a5' }}>
                    <Wifi size={10} /> Stop DNS Server
                  </button>
                )}
              </div>

              {/* SMTP Server */}
              <div className="oast-server-card">
                <div className="oast-server-card-header">
                  <Mail size={16} />
                  <span>SMTP Callback Server</span>
                  <span className={`oast-status-dot ${status?.smtp_running ? 'on' : ''}`} />
                </div>
                <div className="oast-server-card-body">
                  <span className="oast-dim">Port: {status?.smtp_port || 2525}</span>
                  <span className={`oast-server-state ${status?.smtp_running ? 'running' : ''}`}>
                    {status?.smtp_running ? 'Running' : 'Stopped'}
                  </span>
                </div>
                {!status?.smtp_running ? (
                  <button className="oast-start-btn" onClick={() => startSmtp()}>
                    <Wifi size={10} /> Start SMTP Server
                  </button>
                ) : (
                  <button className="oast-start-btn" onClick={stopSmtp} style={{ background: 'rgba(239,68,68,0.15)', borderColor: '#ef4444', color: '#fca5a5' }}>
                    <Wifi size={10} /> Stop SMTP Server
                  </button>
                )}
              </div>
            </div>

            {/* Server domain config */}
            <div className="oast-quick-gen" style={{ marginTop: 12 }}>
              <span className="oast-section-title">Callback Domain</span>
              <div className="oast-gen-row">
                <input className="oast-input"
                  placeholder="oast.your-domain.tld"
                  value={serverDomain}
                  onChange={e => setServerDomain(e.target.value.trim())} />
              </div>
              <span className="oast-dim">
                For real out-of-band testing you need a domain whose NS records point to this machine on the configured DNS port. Default <b>oast.wondersuite.local</b> only works for local probes hitting 127.0.0.1 directly.
              </span>
            </div>

            {/* Quick Generate */}
            <div className="oast-quick-gen">
              <span className="oast-section-title">Quick Generate Payloads</span>
              <div className="oast-gen-row">
                <input className="oast-input" placeholder="Target URL for scan payloads..."
                  value={genTarget} onChange={e => setGenTarget(e.target.value)} />
                <button className="oast-action-btn accent" onClick={generateScanPayloads}>
                  <Zap size={10} /> Generate Scan Payloads
                </button>
              </div>
              <span className="oast-dim">Generates SQLi, SSRF, XXE, and Command Injection OAST payloads</span>
            </div>
          </div>
        )}

        {/* Payloads Tab */}
        {tab === 'payloads' && (
          <div className="oast-payloads-panel">
            <div className="oast-payload-gen">
              <input className="oast-input" placeholder="Payload description..."
                value={genDesc} onChange={e => setGenDesc(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && generate()} />
              <select className="oast-select" value={genType} onChange={e => setGenType(e.target.value)}>
                <option value="generic">Generic</option>
                <option value="blind_sqli">Blind SQLi</option>
                <option value="blind_ssrf">Blind SSRF</option>
                <option value="blind_xxe">Blind XXE</option>
                <option value="blind_cmdi">Blind CMDi</option>
                <option value="blind_xss">Blind XSS</option>
              </select>
              <button className="oast-action-btn accent" onClick={generate}><Plus size={10} /> Generate</button>
            </div>

            <div className="oast-filter-row">
              <Search size={10} />
              <input className="oast-filter-input" placeholder="Filter payloads..."
                value={filter} onChange={e => setFilter(e.target.value)} />
            </div>

            <div className="oast-payload-list">
              {filteredPayloads.map(p => (
                <div key={p.id} className={`oast-payload-item ${selectedPayload?.id === p.id ? 'selected' : ''}`}
                  onClick={() => setSelectedPayload(p)}>
                  <div className="oast-payload-header">
                    <span className="oast-payload-desc">{p.description}</span>
                    <span className={`oast-hit-count ${(interactionCounts[p.correlation_id] || 0) > 0 ? 'hit' : ''}`}>
                      {interactionCounts[p.correlation_id] || 0} hits
                    </span>
                  </div>
                  <div className="oast-payload-meta">
                    <span className="oast-corr">ID: {p.correlation_id}</span>
                    <span className="oast-dim">{p.created_at}</span>
                  </div>
                </div>
              ))}
              {filteredPayloads.length === 0 && (
                <div className="oast-empty">
                  <Bug size={24} strokeWidth={1} />
                  <span>No payloads generated yet</span>
                  <span className="oast-dim">Generate a payload above or use Quick Generate on the Server tab</span>
                </div>
              )}
            </div>

            {/* Payload Detail */}
            {selectedPayload && (
              <div className="oast-payload-detail">
                <div className="oast-detail-header">
                  <span className="oast-detail-title">{selectedPayload.description}</span>
                  <button className="oast-detail-close" onClick={() => setSelectedPayload(null)}>×</button>
                </div>
                <div className="oast-detail-rows">
                  <div className="oast-detail-row">
                    <span className="oast-detail-label">Correlation ID</span>
                    <span className="oast-detail-value">{selectedPayload.correlation_id}</span>
                    <button className="oast-copy-btn" onClick={() => copyText(selectedPayload.correlation_id)}><Copy size={9} /></button>
                  </div>
                  <div className="oast-detail-row">
                    <span className="oast-detail-label">HTTP Payload</span>
                    <span className="oast-detail-value mono">{selectedPayload.http_payload}</span>
                    <button className="oast-copy-btn" onClick={() => copyText(selectedPayload.http_payload)}><Copy size={9} /></button>
                  </div>
                  <div className="oast-detail-row">
                    <span className="oast-detail-label">DNS Payload</span>
                    <span className="oast-detail-value mono">{selectedPayload.dns_payload}</span>
                    <button className="oast-copy-btn" onClick={() => copyText(selectedPayload.dns_payload)}><Copy size={9} /></button>
                  </div>
                  <div className="oast-detail-row">
                    <span className="oast-detail-label">SMTP Payload</span>
                    <span className="oast-detail-value mono">{selectedPayload.smtp_payload}</span>
                    <button className="oast-copy-btn" onClick={() => copyText(selectedPayload.smtp_payload)}><Copy size={9} /></button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Interactions Tab */}
        {tab === 'interactions' && (
          <div className="oast-interactions-panel">
            <div className="oast-filter-row">
              <Search size={10} />
              <input className="oast-filter-input" placeholder="Filter by correlation ID, type, or IP..."
                value={filter} onChange={e => setFilter(e.target.value)} />
              <button className="oast-action-btn" onClick={loadInteractions}><RefreshCcw size={10} /> Poll Now</button>
            </div>

            <div className="oast-interaction-list">
              {filteredInteractions.map(i => (
                <div key={i.id} className={`oast-interaction-item ${selectedInteraction?.id === i.id ? 'selected' : ''} ${i.interaction_type}`}
                  onClick={() => setSelectedInteraction(i)}>
                  <span className={`oast-int-type ${i.interaction_type}`}>{i.interaction_type.toUpperCase()}</span>
                  <span className="oast-int-corr">{i.correlation_id}</span>
                  <span className="oast-int-ip">{i.source_ip}</span>
                  <span className="oast-dim">{i.timestamp}</span>
                </div>
              ))}
              {filteredInteractions.length === 0 && (
                <div className="oast-empty">
                  <Radio size={24} strokeWidth={1} />
                  <span>No interactions received</span>
                  <span className="oast-dim">Inject OAST payloads into targets and wait for callbacks</span>
                </div>
              )}
            </div>

            {selectedInteraction && (
              <div className="oast-interaction-detail">
                <div className="oast-detail-header">
                  <span className={`oast-int-type ${selectedInteraction.interaction_type}`}>
                    {selectedInteraction.interaction_type.toUpperCase()}
                  </span>
                  <span className="oast-detail-title">from {selectedInteraction.source_ip}</span>
                  <button className="oast-detail-close" onClick={() => setSelectedInteraction(null)}>×</button>
                </div>
                <pre className="oast-raw-data">{selectedInteraction.raw_data}</pre>
                <div className="oast-detail-rows">
                  {Object.entries(selectedInteraction.details).map(([k, v]) => (
                    <div key={k} className="oast-detail-row">
                      <span className="oast-detail-label">{k}</span>
                      <span className="oast-detail-value mono">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Collaborator Everywhere Tab */}
        {tab === 'collaborator' && (
          <div className="oast-collab-panel">
            <div className="oast-collab-info">
              <span className="oast-section-title">Collaborator Everywhere</span>
              <span className="oast-dim">Auto-inject OAST payloads into 14 HTTP headers (Referer, X-Forwarded-For, etc.) to detect blind SSRF/XSS</span>
              <button className="oast-action-btn accent" onClick={generateCollaborator}>
                <Zap size={10} /> Generate Header Payloads
              </button>
            </div>

            {collabHeaders.length > 0 && (
              <div className="oast-collab-list">
                {collabHeaders.map((h, i) => (
                  <div key={i} className="oast-collab-item">
                    <span className="oast-collab-header">{h.header}</span>
                    <span className="oast-collab-value">{h.value}</span>
                    <button className="oast-copy-btn" onClick={() => copyText(`${h.header}: ${h.value}`)}><Copy size={9} /></button>
                    <span className={`oast-hit-count ${(interactionCounts[h.oast_payload.correlation_id] || 0) > 0 ? 'hit' : ''}`}>
                      {interactionCounts[h.oast_payload.correlation_id] || 0}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {collabHeaders.length === 0 && (
              <div className="oast-empty">
                <Globe size={24} strokeWidth={1} />
                <span>Click "Generate Header Payloads" to create injection headers</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
