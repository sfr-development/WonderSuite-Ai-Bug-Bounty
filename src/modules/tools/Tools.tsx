import { useState } from 'react';
import { ArrowDown, Sparkles, ChevronRight, Key, Clock, Hash, FileCode, GitCompare } from 'lucide-react';
import './Tools.css';

type ToolTab = 'decoder' | 'jwt' | 'timestamp' | 'regex' | 'hash' | 'comparer';

const encoders: Record<string, (v: string) => string> = {
  Base64: (v) => btoa(v),
  URL: (v) => encodeURIComponent(v),
  HTML: (v) => v.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c)),
  Hex: (v) => Array.from(new TextEncoder().encode(v)).map((b) => b.toString(16).padStart(2, '0')).join(' '),
};

const decoders: Record<string, (v: string) => string> = {
  Base64: (v) => { try { return atob(v.trim()); } catch { return '[Invalid Base64]'; } },
  URL: (v) => { try { return decodeURIComponent(v); } catch { return '[Invalid]'; } },
  HTML: (v) => { const el = document.createElement('div'); el.innerHTML = v; return el.textContent || ''; },
  Hex: (v) => { try { return new TextDecoder().decode(new Uint8Array(v.trim().split(/\s+/).map((h) => parseInt(h, 16)))); } catch { return '[Invalid]'; } },
};

const hashFns: Record<string, (v: string) => Promise<string>> = {
  'SHA-256': async (v) => { const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v)); return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join(''); },
  'SHA-1': async (v) => { const d = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(v)); return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join(''); },
  'SHA-512': async (v) => { const d = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(v)); return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join(''); },
};

function decodeJWT(token: string) {
  try {
    const parts = token.trim().split('.');
    if (parts.length < 2) return { error: 'Invalid JWT format' };
    const decode = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
    const header = decode(parts[0]);
    const payload = decode(parts[1]);
    const exp = payload.exp ? new Date(payload.exp * 1000) : null;
    const iat = payload.iat ? new Date(payload.iat * 1000) : null;
    return { header, payload, signature: parts[2] || '', exp, iat, expired: exp ? exp < new Date() : null };
  } catch {
    return { error: 'Failed to decode JWT' };
  }
}

export function Tools() {
  const [activeTool, setActiveTool] = useState<ToolTab>('decoder');
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [chain, setChain] = useState<string[]>([]);

  // JWT state
  const [jwtInput, setJwtInput] = useState('');
  const [jwtResult, setJwtResult] = useState<ReturnType<typeof decodeJWT> | null>(null);

  // Timestamp state
  const [tsInput, setTsInput] = useState('');
  const [tsResult, setTsResult] = useState('');

  // Regex state
  const [regexPattern, setRegexPattern] = useState('');
  const [regexText, setRegexText] = useState('');
  const [regexMatches, setRegexMatches] = useState<string[]>([]);

  // Hash state
  const [hashInput, setHashInput] = useState('');
  const [hashResults, setHashResults] = useState<Record<string, string>>({});

  // Comparer state
  const [compareA, setCompareA] = useState('');
  const [compareB, setCompareB] = useState('');
  const [diffResult, setDiffResult] = useState<{type: string; text: string}[]>([]);

  const encode = (f: string) => { const fn = encoders[f]; if (fn) { setOutput(fn(input)); setChain((c) => [...c, `${f} Enc`]); } };
  const decode = (f: string) => { const fn = decoders[f]; if (fn) { setOutput(fn(input)); setChain((c) => [...c, `${f} Dec`]); } };
  const hash = async (a: string) => { const fn = hashFns[a]; if (fn) { setOutput(await fn(input)); setChain((c) => [...c, a]); } };

  const smart = () => {
    let v = input; const s: string[] = [];
    try { const d = atob(v); if (/^[\x20-\x7E\s]+$/.test(d)) { v = d; s.push('Base64'); } } catch {}
    try { const d = decodeURIComponent(v); if (d !== v) { v = d; s.push('URL'); } } catch {}
    setOutput(v);
    setChain(s.length ? s.map((x) => `${x} Dec`) : ['No encoding detected']);
  };

  const convertTimestamp = () => {
    const val = tsInput.trim();
    if (!val) return;
    const num = Number(val);
    if (!isNaN(num)) {
      const ms = num > 1e12 ? num : num * 1000;
      const d = new Date(ms);
      setTsResult(`UTC:   ${d.toUTCString()}\nISO:   ${d.toISOString()}\nLocal: ${d.toLocaleString()}\nUnix:  ${Math.floor(ms / 1000)}\nms:    ${ms}`);
    } else {
      const d = new Date(val);
      if (isNaN(d.getTime())) { setTsResult('Invalid date/timestamp'); return; }
      setTsResult(`UTC:   ${d.toUTCString()}\nISO:   ${d.toISOString()}\nLocal: ${d.toLocaleString()}\nUnix:  ${Math.floor(d.getTime() / 1000)}\nms:    ${d.getTime()}`);
    }
  };

  const testRegex = () => {
    try {
      const re = new RegExp(regexPattern, 'g');
      const matches = [...regexText.matchAll(re)].map((m) => m[0]);
      setRegexMatches(matches);
    } catch (e) {
      setRegexMatches([`Error: ${e instanceof Error ? e.message : String(e)}`]);
    }
  };

  const hashAll = async () => {
    const results: Record<string, string> = {};
    for (const [name, fn] of Object.entries(hashFns)) {
      results[name] = await fn(hashInput);
    }
    setHashResults(results);
  };

  return (
    <div className="tools">
      <div className="tools-nav">
        {([
          ['decoder', 'Decoder'],
          ['jwt', 'JWT'],
          ['timestamp', 'Timestamp'],
          ['regex', 'Regex'],
          ['hash', 'Hash'],
          ['comparer', 'Comparer'],
        ] as const).map(([id, label]) => (
          <button key={id} className={`tools-nav-item ${activeTool === id ? 'active' : ''}`} onClick={() => setActiveTool(id)}>{label}</button>
        ))}
      </div>

      {activeTool === 'decoder' && (
        <div className="decoder">
          <div>
            <div className="decoder-label">Input</div>
            <textarea className="decoder-textarea" value={input} onChange={(e) => { setInput(e.target.value); setChain([]); }} placeholder="Paste data here..." spellCheck={false} />
          </div>
          <div className="decoder-actions">
            <div className="decoder-group">
              <span className="decoder-group-label">Enc</span>
              {Object.keys(encoders).map((f) => <button key={f} className="decoder-btn" onClick={() => encode(f)}>{f}</button>)}
            </div>
            <div className="decoder-group">
              <span className="decoder-group-label">Dec</span>
              {Object.keys(decoders).map((f) => <button key={f} className="decoder-btn" onClick={() => decode(f)}>{f}</button>)}
            </div>
            <div className="decoder-group">
              <span className="decoder-group-label">Hash</span>
              {Object.keys(hashFns).map((f) => <button key={f} className="decoder-btn" onClick={() => hash(f)}>{f}</button>)}
            </div>
            <button className="decoder-smart" onClick={smart}><Sparkles size={12} />Smart</button>
          </div>
          <div className="decoder-arrow"><ArrowDown size={14} /></div>
          <div>
            <div className="decoder-label">Output</div>
            <textarea className="decoder-textarea" value={output} readOnly placeholder="Result..." />
          </div>
          {chain.length > 0 && (
            <div className="decoder-chain">
              {chain.map((step, i) => (
                <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                  {i > 0 && <ChevronRight size={10} />}
                  <span className="decoder-chain-step">{step}</span>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTool === 'jwt' && (
        <div className="decoder">
          <div>
            <div className="decoder-label">JWT Token</div>
            <textarea className="decoder-textarea" value={jwtInput} onChange={(e) => setJwtInput(e.target.value)} placeholder="eyJhbGciOiJIUzI1NiIs..." spellCheck={false} />
          </div>
          <button className="decoder-smart" onClick={() => setJwtResult(decodeJWT(jwtInput))} style={{ alignSelf: 'flex-start' }}>
            <Key size={12} /> Decode JWT
          </button>
          {jwtResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {'error' in jwtResult && jwtResult.error ? (
                <div className="decoder-textarea" style={{ minHeight: 'auto', padding: 8, color: 'var(--red)' }}>{jwtResult.error}</div>
              ) : (
                <>
                  <div>
                    <div className="decoder-label">Header</div>
                    <textarea className="decoder-textarea" readOnly value={JSON.stringify((jwtResult as any).header, null, 2)} style={{ minHeight: 60 }} />
                  </div>
                  <div>
                    <div className="decoder-label">
                      Payload
                      {(jwtResult as any).expired !== null && (
                        <span style={{ marginLeft: 8, color: (jwtResult as any).expired ? 'var(--red)' : 'var(--green)', fontWeight: 600 }}>
                          {(jwtResult as any).expired ? '● Expired' : '● Valid'}
                        </span>
                      )}
                    </div>
                    <textarea className="decoder-textarea" readOnly value={JSON.stringify((jwtResult as any).payload, null, 2)} style={{ minHeight: 100 }} />
                  </div>
                  <div className="decoder-chain">
                    {(jwtResult as any).iat && <span className="decoder-chain-step">Issued: {(jwtResult as any).iat.toLocaleString()}</span>}
                    {(jwtResult as any).exp && <span className="decoder-chain-step">Expires: {(jwtResult as any).exp.toLocaleString()}</span>}
                    <span className="decoder-chain-step">Sig: {((jwtResult as any).signature || '').slice(0, 20)}...</span>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {activeTool === 'timestamp' && (
        <div className="decoder">
          <div>
            <div className="decoder-label">Timestamp or Date</div>
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="decoder-textarea" style={{ minHeight: 'auto', height: 32, flex: 1 }} value={tsInput} onChange={(e) => setTsInput(e.target.value)} placeholder="1700000000 or 2024-01-15T10:30:00Z" onKeyDown={(e) => e.key === 'Enter' && convertTimestamp()} />
              <button className="decoder-smart" onClick={convertTimestamp} style={{ height: 32 }}>
                <Clock size={12} /> Convert
              </button>
              <button className="decoder-smart" onClick={() => { setTsInput(String(Math.floor(Date.now() / 1000))); }} style={{ height: 32 }}>Now</button>
            </div>
          </div>
          {tsResult && (
            <div>
              <div className="decoder-label">Result</div>
              <textarea className="decoder-textarea" readOnly value={tsResult} style={{ minHeight: 90 }} />
            </div>
          )}
        </div>
      )}

      {activeTool === 'regex' && (
        <div className="decoder">
          <div>
            <div className="decoder-label">Pattern</div>
            <input className="decoder-textarea" style={{ minHeight: 'auto', height: 32 }} value={regexPattern} onChange={(e) => setRegexPattern(e.target.value)} placeholder="\b\w+@\w+\.\w+\b" onKeyDown={(e) => e.key === 'Enter' && testRegex()} />
          </div>
          <div>
            <div className="decoder-label">Test String</div>
            <textarea className="decoder-textarea" value={regexText} onChange={(e) => setRegexText(e.target.value)} placeholder="Paste text to test against..." spellCheck={false} />
          </div>
          <button className="decoder-smart" onClick={testRegex} style={{ alignSelf: 'flex-start' }}>
            <FileCode size={12} /> Test
          </button>
          {regexMatches.length > 0 && (
            <div>
              <div className="decoder-label">Matches ({regexMatches.length})</div>
              <div className="mcp-tools-list" style={{ maxHeight: 200, overflow: 'auto' }}>
                {regexMatches.map((m, i) => (
                  <div key={i} className="mcp-tool-item">
                    <span style={{ color: 'var(--text-2)', fontFamily: 'monospace', fontSize: 10, minWidth: 30 }}>#{i + 1}</span>
                    <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{m}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTool === 'hash' && (
        <div className="decoder">
          <div>
            <div className="decoder-label">Input</div>
            <textarea className="decoder-textarea" value={hashInput} onChange={(e) => setHashInput(e.target.value)} placeholder="Enter text to hash..." spellCheck={false} />
          </div>
          <button className="decoder-smart" onClick={hashAll} style={{ alignSelf: 'flex-start' }}>
            <Hash size={12} /> Hash All
          </button>
          {Object.keys(hashResults).length > 0 && (
            <div>
              <div className="decoder-label">Results</div>
              <div className="mcp-tools-list">
                {Object.entries(hashResults).map(([algo, val]) => (
                  <div key={algo} className="mcp-tool-item">
                    <span style={{ fontWeight: 600, minWidth: 70, fontSize: 11 }}>{algo}</span>
                    <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--text-1)', wordBreak: 'break-all' }}>{val}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTool === 'comparer' && (
        <div className="decoder">
          <div style={{ display: 'flex', gap: 12, flex: 1 }}>
            <div style={{ flex: 1 }}>
              <div className="decoder-label">Item 1</div>
              <textarea className="decoder-textarea" value={compareA} onChange={(e) => setCompareA(e.target.value)} placeholder="Paste first response..." spellCheck={false} />
            </div>
            <div style={{ flex: 1 }}>
              <div className="decoder-label">Item 2</div>
              <textarea className="decoder-textarea" value={compareB} onChange={(e) => setCompareB(e.target.value)} placeholder="Paste second response..." spellCheck={false} />
            </div>
          </div>
          <button className="decoder-smart" onClick={() => {
            const linesA = compareA.split('\n');
            const linesB = compareB.split('\n');
            const maxLen = Math.max(linesA.length, linesB.length);
            const result: {type: string; text: string}[] = [];
            for (let i = 0; i < maxLen; i++) {
              const a = linesA[i] ?? '';
              const b = linesB[i] ?? '';
              if (a === b) {
                result.push({ type: 'same', text: a });
              } else {
                if (a) result.push({ type: 'removed', text: a });
                if (b) result.push({ type: 'added', text: b });
              }
            }
            setDiffResult(result);
          }} style={{ alignSelf: 'flex-start' }}>
            <GitCompare size={12} /> Compare
          </button>
          {diffResult.length > 0 && (
            <div>
              <div className="decoder-label">Diff Result</div>
              <div className="decoder-textarea" style={{ minHeight: 200, fontFamily: 'JetBrains Mono, monospace', fontSize: 10, lineHeight: 1.6, padding: 8, overflow: 'auto' }}>
                {diffResult.map((d, i) => (
                  <div key={i} style={{
                    color: d.type === 'removed' ? 'var(--red)' : d.type === 'added' ? 'var(--green)' : 'var(--text-2)',
                    background: d.type === 'removed' ? 'rgba(239,68,68,0.08)' : d.type === 'added' ? 'rgba(34,197,94,0.08)' : 'none',
                    padding: '0 4px',
                  }}>
                    {d.type === 'removed' ? '- ' : d.type === 'added' ? '+ ' : '  '}{d.text}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
