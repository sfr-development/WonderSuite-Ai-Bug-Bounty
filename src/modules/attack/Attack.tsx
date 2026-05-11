import { useState, useEffect, useRef } from 'react';
import { Crosshair, Play, Square, Pause, Download, Plus, Trash2, Zap, Target, Hash, Key, ListPlus, Timer } from 'lucide-react';
import { useAppStore } from '../../stores';
import './Attack.css';

interface PayloadProcessor { processor_type: string; value?: string; replace_with?: string; }
interface PayloadSet {
  payload_type: string; values: string[];
  from?: number; to?: number; step?: number;
  charset?: string; min_len?: number; max_len?: number;
  count?: number; processors: PayloadProcessor[];
}
interface GrepRule { rule_type: string; pattern: string; name?: string; group?: number; }
interface AttackResult {
  id: number; position: number; payload: string;
  status: number; length: number; time_ms: number; error: string;
  grep_match: boolean; grep_extracts: Record<string, string>;
  response_headers: string; response_body_preview: string;
}

type Tab = 'positions' | 'payloads' | 'options' | 'results' | 'turbo';
type AttackType = 'sniper' | 'battering_ram' | 'pitchfork' | 'cluster_bomb';

const ATTACK_DESCRIPTIONS: Record<AttackType, string> = {
  sniper: 'Cycles through each position one at a time with the same payload set.',
  battering_ram: 'Sends the same payload to all positions simultaneously.',
  pitchfork: 'Iterates through payload sets in parallel (position N uses set N).',
  cluster_bomb: 'Tests every combination of all payload sets across all positions.',
};

const PROCESSOR_TYPES = [
  { value: 'url_encode', label: 'URL Encode' }, { value: 'url_decode', label: 'URL Decode' },
  { value: 'base64_encode', label: 'Base64 Encode' }, { value: 'base64_decode', label: 'Base64 Decode' },
  { value: 'md5', label: 'MD5 Hash' }, { value: 'sha1', label: 'SHA-1 Hash' }, { value: 'sha256', label: 'SHA-256 Hash' },
  { value: 'hex_encode', label: 'Hex Encode' }, { value: 'html_encode', label: 'HTML Encode' },
  { value: 'uppercase', label: 'Uppercase' }, { value: 'lowercase', label: 'Lowercase' },
  { value: 'reverse', label: 'Reverse' }, { value: 'prefix', label: 'Prefix' }, { value: 'suffix', label: 'Suffix' },
  { value: 'match_replace', label: 'Match & Replace' },
];

export function Attack() {
  const [tab, setTab] = useState<Tab>('positions');
  const [attackType, setAttackType] = useState<AttackType>('sniper');
  const [requestTemplate, setRequestTemplate] = useState('GET / HTTP/1.1\nHost: example.com\nUser-Agent: WonderSuite/1.0\n\n');


  const [payloadSets, setPayloadSets] = useState<PayloadSet[]>([{
    payload_type: 'simple_list', values: [], processors: [],
    from: 0, to: 100, step: 1, charset: 'abcdefghijklmnopqrstuvwxyz', min_len: 1, max_len: 3, count: 10,
  }]);
  const [activePayloadIdx, setActivePayloadIdx] = useState(0);
  const [payloadText, setPayloadText] = useState('');


  const [grepRules, setGrepRules] = useState<GrepRule[]>([]);
  const [grepInput, setGrepInput] = useState('');
  const [grepType, setGrepType] = useState<'match' | 'extract'>('match');


  const [threads] = useState(1);
  const [throttleMs, setThrottleMs] = useState(0);
  const [followRedirects, setFollowRedirects] = useState(true);

  const [turboUrl, setTurboUrl] = useState('https://example.com/api/action');
  const [turboMethod, setTurboMethod] = useState('POST');
  const [turboBody, setTurboBody] = useState('');
  const [turboHeaders, setTurboHeaders] = useState('Content-Type: application/json');
  const [turboCount, setTurboCount] = useState(10);
  const [turboTimeout, setTurboTimeout] = useState(5000);
  const [turboRunning, setTurboRunning] = useState(false);
  const [turboResults, setTurboResults] = useState<any[]>([]);
  const [turboSummary, setTurboSummary] = useState<any>(null);


  const [attackId, setAttackId] = useState<string | null>(null);
  const [status, setStatus] = useState<string>('idle');
  const [results, setResults] = useState<AttackResult[]>([]);
  const [totalPayloads, setTotalPayloads] = useState(0);
  const [completedPayloads, setCompletedPayloads] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [selectedResult, setSelectedResult] = useState<AttackResult | null>(null);
  const [sortKey, setSortKey] = useState<string>('id');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const { pendingSendTo, clearSendTo } = useAppStore();


  useEffect(() => {
    if (pendingSendTo && pendingSendTo.tool === 'intruder') {
      setRequestTemplate(pendingSendTo.requestRaw || `${pendingSendTo.method} ${pendingSendTo.url} HTTP/1.1\nHost: ${(() => { try { return new URL(pendingSendTo.url).hostname; } catch { return 'example.com'; } })()}\n\n`);
      setTab('positions');
      clearSendTo();
    }
  }, [pendingSendTo, clearSendTo]);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const positionCount = (requestTemplate.match(/§/g) || []).length / 2;

  const addMark = () => {
    const el = textareaRef.current;
    if (!el) return;
    const start = el.selectionStart;
    const end = el.selectionEnd;
    if (start === end) return;
    const before = requestTemplate.slice(0, start);
    const selected = requestTemplate.slice(start, end);
    const after = requestTemplate.slice(end);
    setRequestTemplate(before + '§' + selected + '§' + after);
  };

  const clearMarks = () => {
    setRequestTemplate(requestTemplate.split('§').join(''));
  };

  const autoMark = () => {
    let tpl = requestTemplate.split('§').join('');

    const lines = tpl.split('\n');
    const result: string[] = [];
    for (const line of lines) {
      if (line.includes('=') && !line.startsWith('Host:')) {
        result.push(line.replace(/=([^&\n\s]+)/g, '=§$1§'));
      } else if (line.includes(': ') && !line.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)/i)) {
        const idx = line.indexOf(': ');
        if (idx > 0 && !line.startsWith('Host:') && !line.startsWith('Content-Length:')) {
          result.push(line);
        } else {
          result.push(line);
        }
      } else {
        result.push(line);
      }
    }
    setRequestTemplate(result.join('\n'));
  };

  const startAttack = async () => {
    const sets = [...payloadSets];
    if (sets[activePayloadIdx]) {
      sets[activePayloadIdx] = { ...sets[activePayloadIdx], values: payloadText.split('\n').filter(l => l.trim()) };
    }

    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const id: string = await invoke('intruder_start', {
        config: {
          attack_type: attackType,
          request_template: requestTemplate,
          payload_sets: sets,
          grep_rules: grepRules,
          threads,
          throttle_ms: throttleMs,
          follow_redirects: followRedirects,
        },
      });
      setAttackId(id);
      setStatus('running');
      setResults([]);
      setCompletedPayloads(0);
      setTab('results');
      startPolling(id);
    } catch (err) {
      console.error('Attack start failed:', err);
    }
  };

  const startPolling = (id: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    let lastId = 0;
    pollRef.current = setInterval(async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const data: { status: string; total: number; completed: number; elapsed_ms: number; results: AttackResult[] } =
          await invoke('intruder_results', { attackId: id, sinceId: lastId });
        setStatus(data.status);
        setTotalPayloads(data.total);
        setCompletedPayloads(data.completed);
        setElapsed(data.elapsed_ms);
        if (data.results.length > 0) {
          setResults(prev => [...prev, ...data.results]);
          lastId = data.results[data.results.length - 1].id;
        }
        if (data.status !== 'running' && data.status !== 'paused') {
          clearInterval(pollRef.current!);
          pollRef.current = null;
        }
      } catch { /* not ready */ }
    }, 500);
  };

  const stopAttack = async () => {
    if (!attackId) return;
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('intruder_stop', { attackId }); setStatus('stopped');
  };
  const pauseAttack = async () => {
    if (!attackId) return;
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('intruder_pause', { attackId }); setStatus('paused');
  };
  const resumeAttack = async () => {
    if (!attackId) return;
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('intruder_resume', { attackId }); setStatus('running');
    startPolling(attackId);
  };

  const addPayloadSet = () => {
    setPayloadSets(prev => [...prev, {
      payload_type: 'simple_list', values: [], processors: [],
      from: 0, to: 100, step: 1, charset: 'abcdefghijklmnopqrstuvwxyz', min_len: 1, max_len: 3, count: 10,
    }]);
  };

  const addProcessor = (idx: number, type: string) => {
    setPayloadSets(prev => prev.map((s, i) => i === idx
      ? { ...s, processors: [...s.processors, { processor_type: type }] }
      : s));
  };

  const removeProcessor = (setIdx: number, procIdx: number) => {
    setPayloadSets(prev => prev.map((s, i) => i === setIdx
      ? { ...s, processors: s.processors.filter((_, pi) => pi !== procIdx) }
      : s));
  };

  const addGrepRule = () => {
    if (!grepInput.trim()) return;
    setGrepRules(prev => [...prev, { rule_type: grepType, pattern: grepInput, name: grepType === 'extract' ? `extract_${prev.length}` : undefined, group: 1 }]);
    setGrepInput('');
  };

  const exportResults = (format: 'csv' | 'json') => {
    if (format === 'json') {
      const data = JSON.stringify(results, null, 2);
      download(data, 'intruder-results.json', 'application/json');
    } else {
      const header = 'ID,Payload,Status,Length,Time(ms),GrepMatch,Error\n';
      const rows = results.map(r => `${r.id},"${r.payload}",${r.status},${r.length},${r.time_ms},${r.grep_match},"${r.error}"`).join('\n');
      download(header + rows, 'intruder-results.csv', 'text/csv');
    }
  };

  const download = (data: string, name: string, type: string) => {
    const blob = new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name; a.click();
  };

  const fireTurbo = async () => {
    setTurboRunning(true);
    setTurboResults([]);
    setTurboSummary(null);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const headerObj: Record<string, string> = {};
      turboHeaders.split('\n').forEach(line => {
        const idx = line.indexOf(':');
        if (idx > 0) headerObj[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      });
      const result: any = await invoke('mcp_call', {
        request: JSON.stringify({
          jsonrpc: '2.0', id: 1, method: 'tools/call',
          params: { name: 'race_request', arguments: {
            repeat_count: turboCount,
            gate_timeout_ms: turboTimeout,
            template_request: {
              method: turboMethod, url: turboUrl,
              body: turboBody || undefined,
              headers: Object.keys(headerObj).length > 0 ? headerObj : undefined,
            },
          }},
        }),
      });
      const parsed = typeof result === 'string' ? JSON.parse(result) : result;
      const content = parsed?.result?.content?.[0]?.text;
      if (content) {
        const data = JSON.parse(content);
        setTurboResults(data.results || []);
        setTurboSummary(data);
      }
    } catch (err: any) {
      console.error('Turbo failed:', err);
      setTurboSummary({ error: err?.toString() });
    } finally {
      setTurboRunning(false);
    }
  };

  const sortedResults = [...results].sort((a: any, b: any) => {
    const av = a[sortKey]; const bv = b[sortKey];
    const cmp = typeof av === 'number' ? av - bv : String(av).localeCompare(String(bv));
    return sortDir === 'asc' ? cmp : -cmp;
  });

  const handleSort = (key: string) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('asc'); }
  };

  useEffect(() => {
    if (payloadSets[activePayloadIdx]) {
      setPayloadText(payloadSets[activePayloadIdx].values.join('\n'));
    }
  }, [activePayloadIdx]);

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const progress = totalPayloads > 0 ? (completedPayloads / totalPayloads) * 100 : 0;
  const eta = completedPayloads > 0 && status === 'running'
    ? Math.round((elapsed / completedPayloads) * (totalPayloads - completedPayloads) / 1000) : 0;

  return (
    <div className="attack">
      <div className="attack-toolbar">
        <Crosshair size={14} />
        <span className="attack-toolbar-title">Intruder</span>
        <select className="attack-type-select" value={attackType} onChange={e => setAttackType(e.target.value as AttackType)}>
          <option value="sniper">Sniper</option>
          <option value="battering_ram">Battering Ram</option>
          <option value="pitchfork">Pitchfork</option>
          <option value="cluster_bomb">Cluster Bomb</option>
        </select>
        <div className="attack-position-count">
          <Target size={10} /> {positionCount} position{positionCount !== 1 ? 's' : ''}
        </div>
        <div style={{ flex: 1 }} />
        {status === 'running' && (
          <>
            <button className="attack-stop" onClick={pauseAttack}><Pause size={10} /> Pause</button>
            <button className="attack-stop" onClick={stopAttack}><Square size={10} /> Stop</button>
          </>
        )}
        {status === 'paused' && (
          <button className="attack-start" onClick={resumeAttack}><Play size={10} /> Resume</button>
        )}
        {status !== 'running' && status !== 'paused' && (
          <button className="attack-start" onClick={startAttack} disabled={positionCount === 0}>
            <Play size={10} /> Start Attack
          </button>
        )}
      </div>

      <div className="attack-type-desc">{ATTACK_DESCRIPTIONS[attackType]}</div>

      {(status === 'running' || status === 'paused') && (
        <div className="attack-progress">
          <div className="attack-progress-bar"><div className="attack-progress-fill" style={{ width: `${progress}%` }} /></div>
          <span>{completedPayloads}/{totalPayloads}</span>
          <span>·</span>
          <span>{(elapsed / 1000).toFixed(1)}s</span>
          {eta > 0 && <><span>·</span><span>ETA: {eta}s</span></>}
          {status === 'paused' && <span className="attack-paused-badge">PAUSED</span>}
        </div>
      )}

      <div className="attack-tabs">
        {(['positions', 'payloads', 'options', 'results', 'turbo'] as Tab[]).map(t => (
          <button key={t} className={`attack-tab ${tab === t ? 'active' : ''} ${t === 'turbo' ? 'turbo-tab' : ''}`} onClick={() => setTab(t)}>
            {t === 'positions' && <Target size={10} />}
            {t === 'payloads' && <ListPlus size={10} />}
            {t === 'options' && <Zap size={10} />}
            {t === 'results' && <Hash size={10} />}
            {t === 'turbo' && <Timer size={10} />}
            {t === 'turbo' ? 'Turbo Intruder' : t.charAt(0).toUpperCase() + t.slice(1)}
            {t === 'results' && results.length > 0 && <span className="attack-tab-badge">{results.length}</span>}
            {t === 'turbo' && turboResults.length > 0 && <span className="attack-tab-badge">{turboResults.length}</span>}
          </button>
        ))}
      </div>

      <div className="attack-body">
        {tab === 'positions' && (
          <div className="attack-panel">
            <div className="attack-positions-help">
              <span>Select text and click <code>Add §</code> to mark injection positions</span>
              <div className="attack-mark-actions">
                <button className="attack-mark-btn accent" onClick={addMark}><Plus size={9} /> Add §</button>
                <button className="attack-mark-btn" onClick={autoMark}><Zap size={9} /> Auto</button>
                <button className="attack-mark-btn" onClick={clearMarks}><Trash2 size={9} /> Clear</button>
              </div>
            </div>
            <textarea ref={textareaRef} className="attack-request-textarea" value={requestTemplate}
              onChange={e => setRequestTemplate(e.target.value)} spellCheck={false} />
          </div>
        )}

        {tab === 'payloads' && (
          <div className="attack-panel" style={{ display: 'flex', gap: 8 }}>
            <div className="attack-payload-sidebar">
              <span className="attack-payload-sidebar-title">Payload Sets</span>
              {payloadSets.map((s, i) => (
                <button key={i} className={`attack-payload-set-btn ${activePayloadIdx === i ? 'active' : ''}`}
                  onClick={() => setActivePayloadIdx(i)}>
                  Set {i + 1} <span className="attack-dim">({s.payload_type.replace('_', ' ')})</span>
                </button>
              ))}
              <button className="attack-payload-set-btn add" onClick={addPayloadSet}><Plus size={9} /> Add Set</button>
            </div>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div className="attack-payload-header">
                <span className="attack-payload-title">Payload Set {activePayloadIdx + 1}</span>
                <select className="attack-payload-type" value={payloadSets[activePayloadIdx]?.payload_type || 'simple_list'}
                  onChange={e => setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx ? { ...s, payload_type: e.target.value } : s))}>
                  <option value="simple_list">Simple List</option>
                  <option value="numbers">Numbers</option>
                  <option value="bruteforce">Brute Force</option>
                  <option value="null_payloads">Null Payloads</option>
                </select>
                <span className="attack-payload-count">{payloadSets[activePayloadIdx]?.payload_type === 'simple_list' ? payloadText.split('\n').filter(l => l.trim()).length + ' items' : ''}</span>
              </div>

              {payloadSets[activePayloadIdx]?.payload_type === 'simple_list' && (
                <textarea className="attack-payload-textarea" value={payloadText}
                  onChange={e => setPayloadText(e.target.value)} placeholder="One payload per line..." spellCheck={false} />
              )}
              {payloadSets[activePayloadIdx]?.payload_type === 'numbers' && (
                <div className="attack-number-config">
                  <div className="attack-option-group"><label>From</label><input type="number" value={payloadSets[activePayloadIdx].from || 0}
                    onChange={e => setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx ? { ...s, from: Number(e.target.value) } : s))} /></div>
                  <div className="attack-option-group"><label>To</label><input type="number" value={payloadSets[activePayloadIdx].to || 100}
                    onChange={e => setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx ? { ...s, to: Number(e.target.value) } : s))} /></div>
                  <div className="attack-option-group"><label>Step</label><input type="number" value={payloadSets[activePayloadIdx].step || 1}
                    onChange={e => setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx ? { ...s, step: Number(e.target.value) } : s))} /></div>
                </div>
              )}
              {payloadSets[activePayloadIdx]?.payload_type === 'bruteforce' && (
                <div className="attack-number-config">
                  <div className="attack-option-group"><label>Charset</label><input type="text" value={payloadSets[activePayloadIdx].charset || ''}
                    onChange={e => setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx ? { ...s, charset: e.target.value } : s))} /></div>
                  <div className="attack-option-group"><label>Min Length</label><input type="number" value={payloadSets[activePayloadIdx].min_len || 1}
                    onChange={e => setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx ? { ...s, min_len: Number(e.target.value) } : s))} /></div>
                  <div className="attack-option-group"><label>Max Length</label><input type="number" value={payloadSets[activePayloadIdx].max_len || 3}
                    onChange={e => setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx ? { ...s, max_len: Number(e.target.value) } : s))} /></div>
                </div>
              )}
              {payloadSets[activePayloadIdx]?.payload_type === 'null_payloads' && (
                <div className="attack-number-config">
                  <div className="attack-option-group"><label>Count</label><input type="number" value={payloadSets[activePayloadIdx].count || 10}
                    onChange={e => setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx ? { ...s, count: Number(e.target.value) } : s))} /></div>
                </div>
              )}


              <div className="attack-proc-section">
                <div className="attack-proc-header">
                  <span className="attack-payload-title"><Key size={10} /> Payload Processing</span>
                  <select className="attack-payload-type" onChange={e => { if (e.target.value) addProcessor(activePayloadIdx, e.target.value); e.target.value = ''; }}>
                    <option value="">+ Add Processor</option>
                    {PROCESSOR_TYPES.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                  </select>
                </div>
                {payloadSets[activePayloadIdx]?.processors.map((proc, pi) => (
                  <div key={pi} className="attack-proc-row">
                    <span className="attack-proc-label">{PROCESSOR_TYPES.find(p => p.value === proc.processor_type)?.label || proc.processor_type}</span>
                    {(proc.processor_type === 'prefix' || proc.processor_type === 'suffix') && (
                      <input type="text" className="attack-proc-input" placeholder="Value..."
                        value={proc.value || ''} onChange={e => {
                          setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx
                            ? { ...s, processors: s.processors.map((p, j) => j === pi ? { ...p, value: e.target.value } : p) } : s));
                        }} />
                    )}
                    {proc.processor_type === 'match_replace' && (
                      <>
                        <input type="text" className="attack-proc-input" placeholder="Match..."
                          value={proc.value || ''} onChange={e => {
                            setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx
                              ? { ...s, processors: s.processors.map((p, j) => j === pi ? { ...p, value: e.target.value } : p) } : s));
                          }} />
                        <input type="text" className="attack-proc-input" placeholder="Replace..."
                          value={proc.replace_with || ''} onChange={e => {
                            setPayloadSets(prev => prev.map((s, i) => i === activePayloadIdx
                              ? { ...s, processors: s.processors.map((p, j) => j === pi ? { ...p, replace_with: e.target.value } : p) } : s));
                          }} />
                      </>
                    )}
                    <button className="attack-proc-del" onClick={() => removeProcessor(activePayloadIdx, pi)}><Trash2 size={9} /></button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {tab === 'options' && (
          <div className="attack-panel">
            <div className="attack-options">
              <div className="attack-option-group"><label>Throttle (ms between requests)</label>
                <input type="number" value={throttleMs} onChange={e => setThrottleMs(Number(e.target.value))} /></div>
              <label className="attack-checkbox"><input type="checkbox" checked={followRedirects} onChange={e => setFollowRedirects(e.target.checked)} /> Follow Redirects</label>

              <div className="attack-grep-section">
                <span className="attack-payload-title">Grep — Match / Extract</span>
                <div className="attack-grep-add">
                  <select className="attack-payload-type" value={grepType} onChange={e => setGrepType(e.target.value as any)}>
                    <option value="match">Match</option>
                    <option value="extract">Extract</option>
                  </select>
                  <input type="text" className="attack-grep-input" placeholder={grepType === 'match' ? 'String or regex to match...' : 'Regex with capture group...'}
                    value={grepInput} onChange={e => setGrepInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && addGrepRule()} />
                  <button className="attack-mark-btn accent" onClick={addGrepRule}><Plus size={9} /> Add</button>
                </div>
                {grepRules.map((r, i) => (
                  <div key={i} className="attack-grep-rule">
                    <span className={`attack-grep-type ${r.rule_type}`}>{r.rule_type}</span>
                    <span className="attack-grep-pattern">{r.pattern}</span>
                    <button className="attack-proc-del" onClick={() => setGrepRules(prev => prev.filter((_, j) => j !== i))}><Trash2 size={9} /></button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {tab === 'results' && (
          <div className="attack-results">
            <div className="attack-results-actions">
              <button className="attack-mark-btn" onClick={() => exportResults('csv')}><Download size={9} /> CSV</button>
              <button className="attack-mark-btn" onClick={() => exportResults('json')}><Download size={9} /> JSON</button>
              <span className="attack-dim" style={{ marginLeft: 'auto', fontSize: 9 }}>
                {results.length} results · {results.filter(r => r.grep_match).length} grep matches
              </span>
            </div>
            <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
              <div className="attack-results-table">
                <table>
                  <thead>
                    <tr>
                      <th onClick={() => handleSort('id')} style={{ cursor: 'pointer' }}># {sortKey === 'id' && (sortDir === 'asc' ? '↑' : '↓')}</th>
                      <th onClick={() => handleSort('payload')} style={{ cursor: 'pointer' }}>Payload {sortKey === 'payload' && (sortDir === 'asc' ? '↑' : '↓')}</th>
                      <th onClick={() => handleSort('status')} style={{ cursor: 'pointer' }}>Status {sortKey === 'status' && (sortDir === 'asc' ? '↑' : '↓')}</th>
                      <th onClick={() => handleSort('length')} style={{ cursor: 'pointer' }}>Length {sortKey === 'length' && (sortDir === 'asc' ? '↑' : '↓')}</th>
                      <th onClick={() => handleSort('time_ms')} style={{ cursor: 'pointer' }}>Time {sortKey === 'time_ms' && (sortDir === 'asc' ? '↑' : '↓')}</th>
                      <th>Grep</th>
                      {Object.keys(results[0]?.grep_extracts || {}).map(k => <th key={k}>{k}</th>)}
                      <th>Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedResults.map(r => (
                      <tr key={r.id} className={`${r.grep_match ? 'grep-match' : ''} ${selectedResult?.id === r.id ? 'selected-row' : ''}`}
                        onClick={() => setSelectedResult(r)}>
                        <td className="attack-dim">{r.id}</td>
                        <td className="attack-payload-cell">{r.payload}</td>
                        <td><span className={`attack-status-badge code-${Math.floor(r.status / 100)}`}>{r.status || '—'}</span></td>
                        <td>{r.length}</td>
                        <td>{r.time_ms}ms</td>
                        <td>{r.grep_match ? <span className="attack-reflected">✓</span> : ''}</td>
                        {Object.keys(results[0]?.grep_extracts || {}).map(k => <td key={k} className="attack-extract-cell">{r.grep_extracts[k] || ''}</td>)}
                        <td className="attack-error">{r.error}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {selectedResult && (
                <div className="attack-result-detail">
                  <div className="attack-result-detail-header">
                    <span>#{selectedResult.id} — <span className="attack-payload-cell">{selectedResult.payload}</span></span>
                    <button className="attack-mark-btn" onClick={() => setSelectedResult(null)}>×</button>
                  </div>
                  <div className="attack-result-detail-meta">
                    <span>Status: <strong>{selectedResult.status}</strong></span>
                    <span>Length: <strong>{selectedResult.length}</strong></span>
                    <span>Time: <strong>{selectedResult.time_ms}ms</strong></span>
                  </div>
                  <div className="attack-result-detail-section">
                    <label>Response Headers</label>
                    <pre className="attack-detail-pre">{selectedResult.response_headers || '(none)'}</pre>
                  </div>
                  <div className="attack-result-detail-section">
                    <label>Response Body</label>
                    <pre className="attack-detail-pre">{selectedResult.response_body_preview || '(empty)'}</pre>
                  </div>
                  {Object.entries(selectedResult.grep_extracts).length > 0 && (
                    <div className="attack-result-detail-section">
                      <label>Grep Extracts</label>
                      {Object.entries(selectedResult.grep_extracts).map(([k, v]) => (
                        <div key={k} className="attack-extract-row"><strong>{k}:</strong> <span className="attack-reflected">{v}</span></div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {tab === 'turbo' && (
          <div className="attack-panel turbo-panel">
            <div className="turbo-header">
              <Timer size={14} className="turbo-icon" />
              <span className="turbo-title">Turbo Intruder — Race Condition Tester</span>
              <span className="turbo-desc">Fire N identical requests simultaneously using barrier synchronization. All requests release at the same microsecond to detect TOCTOU vulnerabilities.</span>
            </div>

            <div className="turbo-config">
              <div className="turbo-row">
                <div className="turbo-field">
                  <label>Method</label>
                  <select value={turboMethod} onChange={e => setTurboMethod(e.target.value)} className="attack-type-select">
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                    <option value="PATCH">PATCH</option>
                  </select>
                </div>
                <div className="turbo-field" style={{ flex: 1 }}>
                  <label>Target URL</label>
                  <input type="text" value={turboUrl} onChange={e => setTurboUrl(e.target.value)}
                    placeholder="https://target.com/api/transfer" className="turbo-input" />
                </div>
              </div>

              <div className="turbo-row">
                <div className="turbo-field">
                  <label>Concurrent Requests</label>
                  <input type="number" value={turboCount} onChange={e => setTurboCount(Math.min(50, Math.max(2, Number(e.target.value))))}
                    min={2} max={50} className="turbo-input turbo-small" />
                </div>
                <div className="turbo-field">
                  <label>Timeout (ms)</label>
                  <input type="number" value={turboTimeout} onChange={e => setTurboTimeout(Number(e.target.value))}
                    min={1000} max={30000} step={1000} className="turbo-input turbo-small" />
                </div>
              </div>

              <div className="turbo-field">
                <label>Headers (one per line, Key: Value)</label>
                <textarea value={turboHeaders} onChange={e => setTurboHeaders(e.target.value)}
                  className="turbo-textarea" rows={3} spellCheck={false}
                  placeholder={"Content-Type: application/json\nAuthorization: Bearer token123"} />
              </div>

              <div className="turbo-field">
                <label>Request Body</label>
                <textarea value={turboBody} onChange={e => setTurboBody(e.target.value)}
                  className="turbo-textarea" rows={4} spellCheck={false}
                  placeholder='{"amount": 100, "to": "attacker"}' />
              </div>

              <button className={`turbo-fire ${turboRunning ? 'running' : ''}`}
                onClick={fireTurbo} disabled={turboRunning || !turboUrl.trim()}>
                {turboRunning ? <><Square size={11} /> Running...</> : <><Zap size={11} /> Fire {turboCount} Requests</>}
              </button>
            </div>

            {turboSummary && (
              <div className="turbo-summary">
                <div className={`turbo-indicator ${turboSummary.all_same_status === false ? 'race-detected' : 'no-race'}`}>
                  {turboSummary.race_indicator || turboSummary.error || 'Completed'}
                </div>
                {!turboSummary.error && (
                  <div className="turbo-stats">
                    <span>Total: <strong>{turboSummary.total_ms}ms</strong></span>
                    <span>Fastest: <strong>{turboSummary.fastest_ms}ms</strong></span>
                    <span>Slowest: <strong>{turboSummary.slowest_ms}ms</strong></span>
                    <span>Spread: <strong>{turboSummary.timing_spread_ms}ms</strong></span>
                    <span>Codes: <strong>{turboSummary.status_codes?.join(', ')}</strong></span>
                  </div>
                )}
              </div>
            )}

            {turboResults.length > 0 && (
              <div className="turbo-results">
                <table>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Status</th>
                      <th>Response (ms)</th>
                      <th>Barrier Wait (µs)</th>
                      <th>Body Length</th>
                      <th>Body Preview</th>
                      <th>Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {turboResults.map((r, i) => (
                      <tr key={i} className={r.error ? 'turbo-error-row' : ''}>
                        <td className="attack-dim">{r.index ?? i}</td>
                        <td><span className={`attack-status-badge code-${Math.floor((r.status || 0) / 100)}`}>{r.status || '—'}</span></td>
                        <td>{r.response_ms ?? '—'}ms</td>
                        <td className="attack-dim">{r.barrier_wait_us ?? '—'}µs</td>
                        <td>{r.body_length ?? '—'}</td>
                        <td className="turbo-preview">{r.body_preview?.slice(0, 120) || ''}</td>
                        <td className="attack-error">{r.error || ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
