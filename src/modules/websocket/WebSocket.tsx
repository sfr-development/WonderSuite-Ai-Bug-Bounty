import { useState, useEffect, useRef, useCallback } from 'react';
import { Cable, Plus, Trash2, Send, X, RefreshCcw, Wifi, ArrowUp, ArrowDown, ChevronRight } from 'lucide-react';
import './WebSocket.css';

interface WsConnection { id: string; url: string; status: string; message_count: number; connected_at: string; }
interface WsMessage { id: number; direction: string; data: string; msg_type: string; size: number; timestamp: string; }
interface WsRule { id: string; name: string; enabled: boolean; direction: string; match_pattern: string; replace_value: string; is_regex: boolean; }

type WsTab = 'connections' | 'messages' | 'rules';

export function WebSocket() {
  const [tab, setTab] = useState<WsTab>('connections');
  const [connections, setConnections] = useState<WsConnection[]>([]);
  const [selectedConn, setSelectedConn] = useState<string | null>(null);
  const [messages, setMessages] = useState<WsMessage[]>([]);
  const [rules, setRules] = useState<WsRule[]>([]);

  const [connectUrl, setConnectUrl] = useState('wss://');
  const [sendMsg, setSendMsg] = useState('');
  const [selectedMessage, setSelectedMessage] = useState<WsMessage | null>(null);

  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleDir, setNewRuleDir] = useState('both');
  const [newRuleMatch, setNewRuleMatch] = useState('');
  const [newRuleReplace, setNewRuleReplace] = useState('');
  const [newRuleRegex, setNewRuleRegex] = useState(false);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const msgEndRef = useRef<HTMLDivElement>(null);

  const loadConnections = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const data: WsConnection[] = await invoke('ws_list_connections');
      setConnections(data);
    } catch { setConnections([]); }
  }, []);

  const loadMessages = useCallback(async (connId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const data: WsMessage[] = await invoke('ws_get_messages', { connectionId: connId, sinceId: null });
      setMessages(data);
    } catch { setMessages([]); }
  }, []);

  const loadRules = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const data: WsRule[] = await invoke('ws_get_match_replace');
      setRules(data);
    } catch { setRules([]); }
  }, []);

  useEffect(() => {
    loadConnections();
    loadRules();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  useEffect(() => {
    if (selectedConn) {
      loadMessages(selectedConn);
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(() => {
        loadMessages(selectedConn);
        loadConnections();
      }, 1000);
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [selectedConn]);

  useEffect(() => {
    msgEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const connect = async () => {
    if (!connectUrl || connectUrl === 'wss://') return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const connId: string = await invoke('ws_connect', { url: connectUrl, headers: null });
      setSelectedConn(connId);
      setTab('messages');
      setTimeout(loadConnections, 500);
    } catch (err) { console.error(err); }
  };

  const sendFrame = async () => {
    if (!selectedConn || !sendMsg) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('ws_send_frame', { connectionId: selectedConn, message: sendMsg, msgType: null });
      setSendMsg('');
      setTimeout(() => loadMessages(selectedConn), 200);
    } catch (err) { console.error(err); }
  };

  const closeConnection = async (connId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('ws_close_connection', { connectionId: connId });
      if (selectedConn === connId) setSelectedConn(null);
      loadConnections();
    } catch { /* ignore */ }
  };

  const addRule = async () => {
    if (!newRuleName || !newRuleMatch) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('ws_add_match_replace', {
        name: newRuleName, direction: newRuleDir,
        matchPattern: newRuleMatch, replaceValue: newRuleReplace,
        isRegex: newRuleRegex,
      });
      setNewRuleName(''); setNewRuleMatch(''); setNewRuleReplace('');
      loadRules();
    } catch (err) { console.error(err); }
  };

  const removeRule = async (ruleId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('ws_remove_match_replace', { ruleId });
      loadRules();
    } catch { /* ignore */ }
  };

  const selectedConnData = connections.find(c => c.id === selectedConn);

  return (
    <div className="ws">
      <div className="ws-toolbar">
        <Cable size={14} />
        <span className="ws-toolbar-title">WebSocket Inspector</span>
        <div style={{ flex: 1 }} />
        <input className="ws-url-input" value={connectUrl} onChange={e => setConnectUrl(e.target.value)}
          placeholder="wss://echo.websocket.org" onKeyDown={e => e.key === 'Enter' && connect()} />
        <button className="ws-connect-btn" onClick={connect}><Wifi size={10} /> Connect</button>
      </div>

      <div className="ws-tabs">
        <button className={`ws-tab ${tab === 'connections' ? 'active' : ''}`} onClick={() => setTab('connections')}>
          <Cable size={10} /> Connections <span className="ws-badge">{connections.length}</span>
        </button>
        <button className={`ws-tab ${tab === 'messages' ? 'active' : ''}`} onClick={() => setTab('messages')}>
          <Send size={10} /> Messages {selectedConn && <span className="ws-badge">{messages.length}</span>}
        </button>
        <button className={`ws-tab ${tab === 'rules' ? 'active' : ''}`} onClick={() => setTab('rules')}>
          <RefreshCcw size={10} /> Match & Replace <span className="ws-badge">{rules.length}</span>
        </button>
      </div>

      <div className="ws-body">
        {/* Connections Tab */}
        {tab === 'connections' && (
          <div className="ws-connections-panel">
            {connections.length === 0 ? (
              <div className="ws-empty">
                <Cable size={28} strokeWidth={1} />
                <span>No WebSocket connections</span>
                <span className="ws-dim">Enter a WebSocket URL and click Connect</span>
              </div>
            ) : connections.map(conn => (
              <div key={conn.id} className={`ws-conn-item ${selectedConn === conn.id ? 'selected' : ''}`}
                onClick={() => { setSelectedConn(conn.id); setTab('messages'); }}>
                <div className={`ws-conn-dot ${conn.status === 'open' ? 'open' : conn.status.startsWith('error') ? 'error' : 'closed'}`} />
                <div className="ws-conn-info">
                  <span className="ws-conn-url">{conn.url}</span>
                  <div className="ws-conn-meta">
                    <span>{conn.status}</span>
                    <span>·</span>
                    <span>{conn.message_count} msgs</span>
                    <span>·</span>
                    <span>{conn.id}</span>
                  </div>
                </div>
                <button className="ws-conn-close" onClick={e => { e.stopPropagation(); closeConnection(conn.id); }}>
                  <X size={10} />
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Messages Tab */}
        {tab === 'messages' && (
          <div className="ws-messages-panel">
            {selectedConn ? (
              <>
                <div className="ws-messages-header">
                  <div className={`ws-conn-dot ${selectedConnData?.status === 'open' ? 'open' : 'closed'}`} />
                  <span className="ws-conn-active-url">{selectedConnData?.url}</span>
                  <span className="ws-dim">{selectedConnData?.status} · {messages.length} messages</span>
                </div>

                <div className="ws-messages-list">
                  {messages.map(msg => (
                    <div key={msg.id} className={`ws-msg ${msg.direction} ${selectedMessage?.id === msg.id ? 'selected' : ''}`}
                      onClick={() => setSelectedMessage(msg)}>
                      <div className="ws-msg-indicator">
                        {msg.direction === 'sent' ? <ArrowUp size={10} /> : <ArrowDown size={10} />}
                      </div>
                      <div className="ws-msg-content">
                        <div className="ws-msg-header">
                          <span className={`ws-msg-dir ${msg.direction}`}>
                            {msg.direction === 'sent' ? 'C→S' : 'S→C'}
                          </span>
                          <span className="ws-msg-type">{msg.msg_type}</span>
                          <span className="ws-dim">{msg.size}B</span>
                        </div>
                        <pre className="ws-msg-data">{msg.data.slice(0, 200)}{msg.data.length > 200 ? '...' : ''}</pre>
                      </div>
                    </div>
                  ))}
                  <div ref={msgEndRef} />
                  {messages.length === 0 && (
                    <div className="ws-empty" style={{ padding: 20 }}>
                      <span className="ws-dim">Waiting for messages...</span>
                    </div>
                  )}
                </div>

                {/* Composer */}
                <div className="ws-composer">
                  <textarea className="ws-composer-input" value={sendMsg} onChange={e => setSendMsg(e.target.value)}
                    placeholder="Type a message to send..." rows={2}
                    onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendFrame(); } }} />
                  <button className="ws-send-btn" onClick={sendFrame} disabled={!sendMsg}><Send size={10} /> Send</button>
                </div>

                {/* Selected message detail */}
                {selectedMessage && (
                  <div className="ws-msg-detail">
                    <div className="ws-msg-detail-header">
                      <span className={`ws-msg-dir ${selectedMessage.direction}`}>
                        {selectedMessage.direction === 'sent' ? 'Client → Server' : 'Server → Client'}
                      </span>
                      <span className="ws-dim">#{selectedMessage.id} · {selectedMessage.msg_type} · {selectedMessage.size}B</span>
                      <button className="ws-msg-detail-close" onClick={() => setSelectedMessage(null)}>×</button>
                    </div>
                    <pre className="ws-msg-detail-body">{selectedMessage.data}</pre>
                  </div>
                )}
              </>
            ) : (
              <div className="ws-empty">
                <Cable size={28} strokeWidth={1} />
                <span>Select a connection to view messages</span>
              </div>
            )}
          </div>
        )}

        {/* Rules Tab */}
        {tab === 'rules' && (
          <div className="ws-rules-panel">
            <div className="ws-rules-add">
              <input type="text" className="ws-rule-input" placeholder="Rule name..." value={newRuleName} onChange={e => setNewRuleName(e.target.value)} />
              <select className="ws-rule-select" value={newRuleDir} onChange={e => setNewRuleDir(e.target.value)}>
                <option value="both">Both</option>
                <option value="sent">Client → Server</option>
                <option value="received">Server → Client</option>
              </select>
              <input type="text" className="ws-rule-input" placeholder="Match pattern..." value={newRuleMatch} onChange={e => setNewRuleMatch(e.target.value)} />
              <input type="text" className="ws-rule-input" placeholder="Replace with..." value={newRuleReplace} onChange={e => setNewRuleReplace(e.target.value)} />
              <label className="ws-check"><input type="checkbox" checked={newRuleRegex} onChange={e => setNewRuleRegex(e.target.checked)} /> Regex</label>
              <button className="ws-rule-add-btn" onClick={addRule}><Plus size={9} /> Add</button>
            </div>
            <div className="ws-rules-list">
              {rules.map(r => (
                <div key={r.id} className="ws-rule-item">
                  <span className={`ws-rule-enabled ${r.enabled ? 'on' : ''}`}>●</span>
                  <span className="ws-rule-name">{r.name}</span>
                  <span className="ws-rule-dir">{r.direction}</span>
                  <span className="ws-rule-pattern">{r.match_pattern}</span>
                  <ChevronRight size={10} className="ws-dim" />
                  <span className="ws-rule-replace">{r.replace_value}</span>
                  {r.is_regex && <span className="ws-rule-regex-badge">regex</span>}
                  <button className="ws-rule-del" onClick={() => removeRule(r.id)}><Trash2 size={9} /></button>
                </div>
              ))}
              {rules.length === 0 && (
                <div className="ws-empty" style={{ padding: 20 }}>
                  <RefreshCcw size={24} strokeWidth={1} />
                  <span>No WebSocket match & replace rules</span>
                  <span className="ws-dim">Rules automatically modify WebSocket frames in transit</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
