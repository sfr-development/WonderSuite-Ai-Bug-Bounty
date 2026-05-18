import { useState, useEffect, useRef, useCallback } from 'react';
import { Plus, Trash2, Send, X, RefreshCcw, Wifi, ArrowUp, ArrowDown, ChevronRight, Cable, Play, Square, Variable, Copy, Download, Upload } from 'lucide-react';
import { notifyError } from '../../utils/notify';
import './WebSocket.css';

interface WsConnection { id: string; url: string; status: string; message_count: number; connected_at: string; }
interface WsMessage { id: number; direction: string; data: string; msg_type: string; size: number; timestamp: string; }
interface WsRule { id: string; name: string; enabled: boolean; direction: string; match_pattern: string; replace_value: string; is_regex: boolean; }

interface ReplayFrame { id: string; data: string; delayMs: number; }
interface ReplaySequence {
  id: string;
  name: string;
  variables: Array<{ key: string; value: string }>;
  frames: ReplayFrame[];
  loopCount: number;
  createdAt: string;
}
interface ReplayLogEntry { ts: string; kind: 'info' | 'sent' | 'error'; text: string; }

type WsTab = 'connections' | 'messages' | 'rules' | 'replay';

const REPLAY_STORAGE_KEY = 'ws_replay_sequences_v1';

function loadReplaySequences(): ReplaySequence[] {
  try {
    const raw = localStorage.getItem(REPLAY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

function saveReplaySequences(seqs: ReplaySequence[]) {
  try { localStorage.setItem(REPLAY_STORAGE_KEY, JSON.stringify(seqs)); } catch {}
}

function applyVars(data: string, variables: Array<{ key: string; value: string }>): string {
  const map = new Map(variables.filter(v => v.key).map(v => [v.key, v.value]));
  return data.replace(/\$\{([A-Za-z_][\w]*)\}/g, (_, name) => map.has(name) ? (map.get(name) ?? '') : `\${${name}}`);
}

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

  const [sequences, setSequences] = useState<ReplaySequence[]>(() => loadReplaySequences());
  const [selectedSeqId, setSelectedSeqId] = useState<string | null>(null);
  const [replayRunning, setReplayRunning] = useState(false);
  const [replayLog, setReplayLog] = useState<ReplayLogEntry[]>([]);
  const replayAbortRef = useRef(false);

  const persistSequences = useCallback((next: ReplaySequence[]) => {
    setSequences(next);
    saveReplaySequences(next);
  }, []);

  const activeSeq = sequences.find(s => s.id === selectedSeqId) || null;

  const createSequence = () => {
    const id = `seq-${Date.now()}`;
    const seq: ReplaySequence = {
      id,
      name: `Sequence ${sequences.length + 1}`,
      variables: [],
      frames: [{ id: `f-${Date.now()}`, data: '{}', delayMs: 0 }],
      loopCount: 1,
      createdAt: new Date().toISOString(),
    };
    persistSequences([...sequences, seq]);
    setSelectedSeqId(id);
  };

  const updateSequence = (id: string, patch: Partial<ReplaySequence>) => {
    persistSequences(sequences.map(s => s.id === id ? { ...s, ...patch } : s));
  };

  const deleteSequence = (id: string) => {
    persistSequences(sequences.filter(s => s.id !== id));
    if (selectedSeqId === id) setSelectedSeqId(null);
  };

  const addFrame = (seqId: string, afterIdx?: number) => {
    const seq = sequences.find(s => s.id === seqId);
    if (!seq) return;
    const newFrame: ReplayFrame = { id: `f-${Date.now()}`, data: '', delayMs: 100 };
    const idx = afterIdx !== undefined ? afterIdx + 1 : seq.frames.length;
    const frames = [...seq.frames];
    frames.splice(idx, 0, newFrame);
    updateSequence(seqId, { frames });
  };

  const updateFrame = (seqId: string, frameId: string, patch: Partial<ReplayFrame>) => {
    const seq = sequences.find(s => s.id === seqId);
    if (!seq) return;
    updateSequence(seqId, { frames: seq.frames.map(f => f.id === frameId ? { ...f, ...patch } : f) });
  };

  const removeFrame = (seqId: string, frameId: string) => {
    const seq = sequences.find(s => s.id === seqId);
    if (!seq) return;
    updateSequence(seqId, { frames: seq.frames.filter(f => f.id !== frameId) });
  };

  const moveFrame = (seqId: string, frameId: string, dir: -1 | 1) => {
    const seq = sequences.find(s => s.id === seqId);
    if (!seq) return;
    const idx = seq.frames.findIndex(f => f.id === frameId);
    if (idx < 0) return;
    const target = idx + dir;
    if (target < 0 || target >= seq.frames.length) return;
    const frames = [...seq.frames];
    [frames[idx], frames[target]] = [frames[target], frames[idx]];
    updateSequence(seqId, { frames });
  };

  const importLastMessageAsFrame = (seqId: string) => {
    const seq = sequences.find(s => s.id === seqId);
    if (!seq) return;
    const lastSent = [...messages].reverse().find(m => m.direction === 'sent');
    if (!lastSent) return;
    const newFrame: ReplayFrame = { id: `f-${Date.now()}`, data: lastSent.data, delayMs: 100 };
    updateSequence(seqId, { frames: [...seq.frames, newFrame] });
  };

  const exportSequence = (seq: ReplaySequence) => {
    const blob = new Blob([JSON.stringify(seq, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${seq.name.replace(/[^\w-]+/g, '_')}.replay.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const importSequence = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.frames)) {
          throw new Error('not a valid replay sequence');
        }
        const seq: ReplaySequence = {
          id: `seq-${Date.now()}`,
          name: parsed.name || 'Imported',
          variables: Array.isArray(parsed.variables) ? parsed.variables : [],
          frames: parsed.frames.map((f: ReplayFrame, i: number) => ({
            id: `f-${Date.now()}-${i}`,
            data: String(f.data ?? ''),
            delayMs: Number(f.delayMs) || 0,
          })),
          loopCount: Math.max(1, Number(parsed.loopCount) || 1),
          createdAt: new Date().toISOString(),
        };
        persistSequences([...sequences, seq]);
        setSelectedSeqId(seq.id);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        setReplayLog(l => [...l, { ts: new Date().toLocaleTimeString(), kind: 'error', text: `Import failed: ${msg}` }]);
      }
    };
    input.click();
  };

  const runReplay = async (seq: ReplaySequence) => {
    if (!selectedConn) {
      setReplayLog(l => [...l, { ts: new Date().toLocaleTimeString(), kind: 'error', text: 'No active WebSocket connection — select one in the Connections tab first.' }]);
      return;
    }
    if (replayRunning) return;

    replayAbortRef.current = false;
    setReplayRunning(true);
    setReplayLog([{ ts: new Date().toLocaleTimeString(), kind: 'info', text: `Replay started · ${seq.frames.length} frames × ${seq.loopCount} loop(s) · target ${selectedConn}` }]);

    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const loops = Math.max(1, Math.floor(seq.loopCount));
      for (let l = 0; l < loops; l++) {
        if (replayAbortRef.current) break;
        if (loops > 1) {
          setReplayLog(prev => [...prev, { ts: new Date().toLocaleTimeString(), kind: 'info', text: `── loop ${l + 1} / ${loops} ──` }]);
        }
        for (let i = 0; i < seq.frames.length; i++) {
          if (replayAbortRef.current) break;
          const f = seq.frames[i];
          if (f.delayMs > 0) {
            await new Promise(r => setTimeout(r, f.delayMs));
            if (replayAbortRef.current) break;
          }
          const payload = applyVars(f.data, seq.variables);
          try {
            await invoke('ws_send_frame', { connectionId: selectedConn, message: payload, msgType: null });
            const preview = payload.length > 80 ? payload.slice(0, 80) + '…' : payload;
            setReplayLog(prev => [...prev, { ts: new Date().toLocaleTimeString(), kind: 'sent', text: `#${i + 1} (+${f.delayMs}ms) ${preview}` }]);
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            setReplayLog(prev => [...prev, { ts: new Date().toLocaleTimeString(), kind: 'error', text: `#${i + 1} failed: ${msg}` }]);
          }
        }
      }
      if (replayAbortRef.current) {
        setReplayLog(prev => [...prev, { ts: new Date().toLocaleTimeString(), kind: 'info', text: 'Replay cancelled.' }]);
      } else {
        setReplayLog(prev => [...prev, { ts: new Date().toLocaleTimeString(), kind: 'info', text: 'Replay finished.' }]);
      }
    } finally {
      setReplayRunning(false);
    }
  };

  const stopReplay = () => { replayAbortRef.current = true; };

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
    } catch (err) { notifyError('WebSocket connect failed', err); }
  };

  const sendFrame = async () => {
    if (!selectedConn || !sendMsg) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('ws_send_frame', { connectionId: selectedConn, message: sendMsg, msgType: null });
      setSendMsg('');
      setTimeout(() => loadMessages(selectedConn), 200);
    } catch (err) { notifyError('WebSocket send failed', err); }
  };

  const closeConnection = async (connId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('ws_close_connection', { connectionId: connId });
      if (selectedConn === connId) setSelectedConn(null);
      loadConnections();
    } catch (err) { notifyError('WebSocket close failed', err); }
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
    } catch (err) { notifyError('Add WS rule failed', err); }
  };

  const removeRule = async (ruleId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('ws_remove_match_replace', { ruleId });
      loadRules();
    } catch (err) { notifyError('Remove WS rule failed', err); }
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
        <button className={`ws-tab ${tab === 'replay' ? 'active' : ''}`} onClick={() => setTab('replay')}>
          <Play size={10} /> Replay <span className="ws-badge">{sequences.length}</span>
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

        {tab === 'replay' && (
          <div className="ws-replay-panel">
            <aside className="ws-replay-sidebar">
              <div className="ws-replay-sidebar-head">
                <span>Sequences</span>
                <span className="ws-replay-sidebar-actions">
                  <button onClick={createSequence} title="New sequence"><Plus size={11} /></button>
                  <button onClick={importSequence} title="Import .replay.json"><Upload size={11} /></button>
                </span>
              </div>
              {sequences.length === 0 && (
                <div className="ws-empty" style={{ padding: 18, fontSize: 11 }}>
                  <Play size={20} strokeWidth={1} />
                  <span>No sequences yet</span>
                  <span className="ws-dim">Create one to script a replay flow</span>
                </div>
              )}
              {sequences.map(s => (
                <div key={s.id} className={`ws-replay-seq ${selectedSeqId === s.id ? 'selected' : ''}`}
                     onClick={() => setSelectedSeqId(s.id)}>
                  <div className="ws-replay-seq-info">
                    <span className="ws-replay-seq-name">{s.name}</span>
                    <span className="ws-dim" style={{ fontSize: 9 }}>
                      {s.frames.length} frame{s.frames.length !== 1 ? 's' : ''}
                      {s.loopCount > 1 ? ` · ×${s.loopCount}` : ''}
                      {s.variables.length > 0 ? ` · ${s.variables.length} var${s.variables.length !== 1 ? 's' : ''}` : ''}
                    </span>
                  </div>
                  <button className="ws-conn-close" onClick={e => { e.stopPropagation(); deleteSequence(s.id); }}>
                    <X size={10} />
                  </button>
                </div>
              ))}
            </aside>

            <div className="ws-replay-main">
              {activeSeq ? (
                <>
                  <div className="ws-replay-toolbar">
                    <input className="ws-replay-name-input"
                      value={activeSeq.name}
                      onChange={e => updateSequence(activeSeq.id, { name: e.target.value })}
                      placeholder="Sequence name" />
                    <div className="ws-replay-toolbar-spacer" />
                    <label className="ws-replay-loop-label">
                      <span className="ws-dim">Loop</span>
                      <input type="number" min={1} max={1000}
                        className="ws-replay-loop-input"
                        value={activeSeq.loopCount}
                        onChange={e => updateSequence(activeSeq.id, { loopCount: Math.max(1, Number(e.target.value) || 1) })} />
                    </label>
                    <button className="ws-action-btn"
                      onClick={() => exportSequence(activeSeq)}
                      title="Export sequence as JSON">
                      <Download size={10} /> Export
                    </button>
                    {replayRunning ? (
                      <button className="ws-action-btn danger" onClick={stopReplay}>
                        <Square size={10} /> Stop
                      </button>
                    ) : (
                      <button className="ws-action-btn accent"
                        onClick={() => runReplay(activeSeq)}
                        disabled={!selectedConn || activeSeq.frames.length === 0}
                        title={!selectedConn ? 'Select an active connection in the Connections tab first' : 'Run sequence'}>
                        <Play size={10} /> Run
                      </button>
                    )}
                  </div>

                  {!selectedConn && (
                    <div className="ws-replay-warn">
                      No active connection selected. Open or pick a connection in the <strong>Connections</strong> tab to enable Run.
                    </div>
                  )}

                  <div className="ws-replay-vars">
                    <div className="ws-replay-section-head">
                      <Variable size={11} />
                      <span>Variables</span>
                      <span className="ws-dim" style={{ fontSize: 10 }}>
                        Reference in frames as <code>$&#123;name&#125;</code>
                      </span>
                      <button className="ws-replay-mini-btn"
                        onClick={() => updateSequence(activeSeq.id, { variables: [...activeSeq.variables, { key: '', value: '' }] })}
                        title="Add variable">
                        <Plus size={9} /> Add
                      </button>
                    </div>
                    {activeSeq.variables.length === 0 ? (
                      <div className="ws-replay-vars-empty">No variables defined.</div>
                    ) : activeSeq.variables.map((v, i) => (
                      <div key={i} className="ws-replay-var-row">
                        <input className="ws-replay-var-key" placeholder="name"
                          value={v.key}
                          onChange={e => {
                            const next = [...activeSeq.variables];
                            next[i] = { ...next[i], key: e.target.value };
                            updateSequence(activeSeq.id, { variables: next });
                          }} />
                        <span className="ws-replay-var-eq">=</span>
                        <input className="ws-replay-var-val" placeholder="value"
                          value={v.value}
                          onChange={e => {
                            const next = [...activeSeq.variables];
                            next[i] = { ...next[i], value: e.target.value };
                            updateSequence(activeSeq.id, { variables: next });
                          }} />
                        <button className="ws-rule-del"
                          onClick={() => updateSequence(activeSeq.id, { variables: activeSeq.variables.filter((_, j) => j !== i) })}>
                          <Trash2 size={9} />
                        </button>
                      </div>
                    ))}
                  </div>

                  <div className="ws-replay-frames">
                    <div className="ws-replay-section-head">
                      <Send size={11} />
                      <span>Frames</span>
                      <span className="ws-dim" style={{ fontSize: 10 }}>Sent in order, client → server</span>
                      <button className="ws-replay-mini-btn"
                        onClick={() => importLastMessageAsFrame(activeSeq.id)}
                        disabled={!messages.some(m => m.direction === 'sent')}
                        title="Append the last sent message from the Messages tab as a new frame">
                        <Copy size={9} /> From Last Sent
                      </button>
                      <button className="ws-replay-mini-btn"
                        onClick={() => addFrame(activeSeq.id)}
                        title="Add frame">
                        <Plus size={9} /> Add Frame
                      </button>
                    </div>
                    {activeSeq.frames.map((f, i) => (
                      <div key={f.id} className="ws-replay-frame">
                        <div className="ws-replay-frame-head">
                          <span className="ws-replay-frame-num">#{i + 1}</span>
                          <label className="ws-replay-delay-label">
                            <span className="ws-dim">delay</span>
                            <input type="number" min={0} step={10}
                              className="ws-replay-delay-input"
                              value={f.delayMs}
                              onChange={e => updateFrame(activeSeq.id, f.id, { delayMs: Math.max(0, Number(e.target.value) || 0) })} />
                            <span className="ws-dim">ms</span>
                          </label>
                          <div className="ws-replay-toolbar-spacer" />
                          <button className="ws-replay-mini-btn icon"
                            onClick={() => moveFrame(activeSeq.id, f.id, -1)}
                            disabled={i === 0} title="Move up">
                            <ArrowUp size={10} />
                          </button>
                          <button className="ws-replay-mini-btn icon"
                            onClick={() => moveFrame(activeSeq.id, f.id, 1)}
                            disabled={i === activeSeq.frames.length - 1} title="Move down">
                            <ArrowDown size={10} />
                          </button>
                          <button className="ws-replay-mini-btn icon"
                            onClick={() => addFrame(activeSeq.id, i)} title="Insert frame after">
                            <Plus size={10} />
                          </button>
                          <button className="ws-replay-mini-btn icon danger"
                            onClick={() => removeFrame(activeSeq.id, f.id)} title="Remove frame">
                            <Trash2 size={10} />
                          </button>
                        </div>
                        <textarea className="ws-replay-frame-data"
                          spellCheck={false}
                          value={f.data}
                          onChange={e => updateFrame(activeSeq.id, f.id, { data: e.target.value })}
                          placeholder='Frame payload — supports ${variable} substitution'
                          rows={3} />
                      </div>
                    ))}
                    {activeSeq.frames.length === 0 && (
                      <div className="ws-empty" style={{ padding: 16, fontSize: 11 }}>
                        <span className="ws-dim">No frames. Add one to get started.</span>
                      </div>
                    )}
                  </div>

                  {replayLog.length > 0 && (
                    <div className="ws-replay-log">
                      <div className="ws-replay-section-head">
                        <span>Run Log</span>
                        <span className="ws-dim" style={{ fontSize: 10 }}>{replayLog.length} entries</span>
                        <div className="ws-replay-toolbar-spacer" />
                        <button className="ws-replay-mini-btn" onClick={() => setReplayLog([])}>
                          Clear
                        </button>
                      </div>
                      <div className="ws-replay-log-body">
                        {replayLog.map((e, i) => (
                          <div key={i} className={`ws-replay-log-row ${e.kind}`}>
                            <span className="ws-replay-log-ts">{e.ts}</span>
                            <span className="ws-replay-log-text">{e.text}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="ws-empty">
                  <Play size={28} strokeWidth={1} />
                  <span>No sequence selected</span>
                  <span className="ws-dim">Create a new sequence or pick one on the left.</span>
                  <button className="ws-action-btn accent" style={{ marginTop: 12 }}
                    onClick={createSequence}>
                    <Plus size={10} /> New Sequence
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
