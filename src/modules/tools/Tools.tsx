import { useState } from 'react';
import { ArrowDown, Sparkles, ChevronRight, Key, Clock, Hash, FileCode, GitCompare, Globe, Shield, Copy, Search, RefreshCw } from 'lucide-react';
import './Tools.css';

type ToolTab = 'decoder' | 'jwt' | 'timestamp' | 'regex' | 'hash' | 'comparer' | 'iputil' | 'passgen' | 'headers' | 'research';

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

  const [jwtInput, setJwtInput] = useState('');
  const [jwtResult, setJwtResult] = useState<ReturnType<typeof decodeJWT> | null>(null);

  const [tsInput, setTsInput] = useState('');
  const [tsResult, setTsResult] = useState('');

  const [regexPattern, setRegexPattern] = useState('');
  const [regexText, setRegexText] = useState('');
  const [regexMatches, setRegexMatches] = useState<string[]>([]);

  const [hashInput, setHashInput] = useState('');
  const [hashResults, setHashResults] = useState<Record<string, string>>({});

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
          ['iputil', 'IP/CIDR'],
          ['passgen', 'PassGen'],
          ['headers', 'Headers'],
          ['research', 'Research'],
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

      {activeTool === 'iputil' && <IpUtilTool />}
      {activeTool === 'passgen' && <PassGenTool />}
      {activeTool === 'headers' && <HeadersTool />}
      {activeTool === 'research' && <ResearchTool />}
    </div>
  );
}

/* ─── IP/CIDR Calculator ─── */
function IpUtilTool() {
  const [ip, setIp] = useState(''); const [result, setResult] = useState('');
  const calc = () => {
    try {
      const [addr, bits] = ip.split('/'); const mask = bits ? parseInt(bits) : 32;
      const parts = addr.split('.').map(Number);
      if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255) || mask < 0 || mask > 32) { setResult('Invalid IP/CIDR'); return; }
      const ipNum = (parts[0]<<24 | parts[1]<<16 | parts[2]<<8 | parts[3]) >>> 0;
      const maskNum = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
      const network = (ipNum & maskNum) >>> 0; const broadcast = (network | ~maskNum) >>> 0;
      const toIp = (n: number) => `${(n>>>24)&0xff}.${(n>>>16)&0xff}.${(n>>>8)&0xff}.${n&0xff}`;
      const hosts = mask >= 31 ? (mask === 32 ? 1 : 2) : (broadcast - network - 1);
      setResult(`Network:   ${toIp(network)}/${mask}\nBroadcast: ${toIp(broadcast)}\nFirst:     ${toIp(network + 1)}\nLast:      ${toIp(broadcast - 1)}\nNetmask:   ${toIp(maskNum)}\nHosts:     ${hosts}\nWildcard:  ${toIp(~maskNum >>> 0)}\nBinary:    ${parts.map(p => p.toString(2).padStart(8,'0')).join('.')}\nHex:       0x${ipNum.toString(16).padStart(8,'0')}\nDecimal:   ${ipNum}`);
    } catch { setResult('Invalid input'); }
  };
  return (
    <div className="decoder">
      <div><div className="decoder-label">IP Address or CIDR</div>
        <div style={{display:'flex',gap:8}}>
          <input className="decoder-textarea" style={{minHeight:'auto',height:32,flex:1}} value={ip} onChange={e=>setIp(e.target.value)} placeholder="192.168.1.0/24 or 10.0.0.1" onKeyDown={e=>e.key==='Enter'&&calc()}/>
          <button className="decoder-smart" onClick={calc} style={{height:32}}><Globe size={12}/> Calculate</button>
        </div>
      </div>
      {result && <div><div className="decoder-label">Result</div><textarea className="decoder-textarea" readOnly value={result} style={{minHeight:160}}/></div>}
    </div>
  );
}

/* ─── Password Generator ─── */
function PassGenTool() {
  const [len, setLen] = useState(24); const [count, setCount] = useState(5);
  const [upper, setUpper] = useState(true); const [lower, setLower] = useState(true);
  const [digits, setDigits] = useState(true); const [symbols, setSymbols] = useState(true);
  const [passwords, setPasswords] = useState<string[]>([]);
  const generate = () => {
    let chars = '';
    if (upper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (lower) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (digits) chars += '0123456789';
    if (symbols) chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';
    if (!chars) { setPasswords(['Select at least one character set']); return; }
    const arr = new Uint32Array(len * count); crypto.getRandomValues(arr);
    const result: string[] = [];
    for (let i = 0; i < count; i++) {
      let pw = '';
      for (let j = 0; j < len; j++) pw += chars[arr[i * len + j] % chars.length];
      result.push(pw);
    }
    setPasswords(result);
  };
  const copyPw = async (pw: string) => { try { await navigator.clipboard.writeText(pw); } catch {} };
  return (
    <div className="decoder">
      <div style={{display:'flex',gap:12,flexWrap:'wrap',alignItems:'center'}}>
        <div><div className="decoder-label">Length</div><input type="number" className="decoder-textarea" style={{minHeight:'auto',height:32,width:70}} value={len} onChange={e=>setLen(+e.target.value)} min={4} max={128}/></div>
        <div><div className="decoder-label">Count</div><input type="number" className="decoder-textarea" style={{minHeight:'auto',height:32,width:70}} value={count} onChange={e=>setCount(+e.target.value)} min={1} max={50}/></div>
        <div style={{display:'flex',gap:8,marginTop:16}}>
          {[['A-Z',upper,setUpper],['a-z',lower,setLower],['0-9',digits,setDigits],['!@#',symbols,setSymbols]].map(([label,val,setter]:any)=>(
            <button key={label} className={`decoder-btn`} style={{padding:'4px 10px',border:'1px solid var(--border-1)',borderRadius:3,background:val?'var(--accent-muted)':'var(--bg-1)',color:val?'var(--accent)':'var(--text-2)'}} onClick={()=>setter(!val)}>{label}</button>
          ))}
        </div>
        <button className="decoder-smart" onClick={generate} style={{height:32,marginTop:16}}><Shield size={12}/> Generate</button>
      </div>
      {passwords.length > 0 && (
        <div><div className="decoder-label">Passwords</div>
          <div className="mcp-tools-list" style={{maxHeight:300,overflow:'auto'}}>
            {passwords.map((pw,i) => (
              <div key={i} className="mcp-tool-item" style={{display:'flex',alignItems:'center',gap:8}}>
                <span style={{fontFamily:'JetBrains Mono, monospace',fontSize:11,flex:1,wordBreak:'break-all'}}>{pw}</span>
                <button className="decoder-btn" onClick={()=>copyPw(pw)} style={{border:'none',padding:4}}><Copy size={11}/></button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── HTTP Header Builder ─── */
function HeadersTool() {
  const [headers, setHeaders] = useState<{key:string;value:string}[]>([{key:'',value:''}]);
  const [output, setOutput] = useState('');
  const presets: Record<string,{key:string;value:string}[]> = {
    'Auth Bearer': [{key:'Authorization',value:'Bearer <token>'}],
    'JSON POST': [{key:'Content-Type',value:'application/json'},{key:'Accept',value:'application/json'}],
    'CORS Bypass': [{key:'Origin',value:'https://target.com'},{key:'Access-Control-Request-Method',value:'POST'}],
    'WAF Bypass': [{key:'X-Forwarded-For',value:'127.0.0.1'},{key:'X-Real-IP',value:'127.0.0.1'},{key:'X-Originating-IP',value:'127.0.0.1'}],
    'Cache Poison': [{key:'X-Forwarded-Host',value:'evil.com'},{key:'X-Forwarded-Scheme',value:'nothttps'}],
  };
  const addRow = () => setHeaders(h => [...h, {key:'',value:''}]);
  const removeRow = (i:number) => setHeaders(h => h.filter((_,j)=>j!==i));
  const updateRow = (i:number, field:'key'|'value', val:string) => setHeaders(h => h.map((r,j)=>j===i?{...r,[field]:val}:r));
  const buildOutput = () => setOutput(headers.filter(h=>h.key).map(h=>`${h.key}: ${h.value}`).join('\n'));
  const applyPreset = (name:string) => { setHeaders(presets[name]||[]); };
  return (
    <div className="decoder">
      <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>
        {Object.keys(presets).map(name=>(
          <button key={name} className="decoder-btn" style={{border:'1px solid var(--border-1)',borderRadius:3,padding:'3px 8px'}} onClick={()=>applyPreset(name)}>{name}</button>
        ))}
      </div>
      <div style={{display:'flex',flexDirection:'column',gap:4}}>
        {headers.map((h,i)=>(
          <div key={i} style={{display:'flex',gap:6}}>
            <input className="decoder-textarea" style={{minHeight:'auto',height:28,flex:1}} value={h.key} onChange={e=>updateRow(i,'key',e.target.value)} placeholder="Header name"/>
            <input className="decoder-textarea" style={{minHeight:'auto',height:28,flex:2}} value={h.value} onChange={e=>updateRow(i,'value',e.target.value)} placeholder="Value"/>
            <button className="decoder-btn" style={{border:'none',color:'var(--red)',padding:4}} onClick={()=>removeRow(i)}>×</button>
          </div>
        ))}
        <div style={{display:'flex',gap:6}}>
          <button className="decoder-btn" style={{border:'1px solid var(--border-1)',borderRadius:3}} onClick={addRow}>+ Add</button>
          <button className="decoder-smart" onClick={buildOutput}><Copy size={12}/> Build</button>
        </div>
      </div>
      {output && <div><div className="decoder-label">Output</div><textarea className="decoder-textarea" readOnly value={output} style={{minHeight:80}}/></div>}
    </div>
  );
}

/* ─── Internet Research (linked to proxy/traffic) ─── */
function ResearchTool() {
  const [query, setQuery] = useState(''); const [results, setResults] = useState<{title:string;url:string;snippet:string}[]>([]);
  const [loading, setLoading] = useState(false); const [hosts, setHosts] = useState<string[]>([]);
  
  const loadHosts = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const traffic = await invoke<any[]>('proxy_get_traffic');
      const unique = [...new Set(traffic.map(t => t.host).filter(Boolean))];
      setHosts(unique);
    } catch {}
  };

  const search = async (q?: string) => {
    const term = q || query; if (!term.trim()) return;
    setLoading(true); setResults([]);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const searchResults = await invoke<any>('mcp_call_tool', {
        name: 'search_web', params: { query: term }
      }).catch(() => null);
      if (searchResults?.results) {
        setResults(searchResults.results.slice(0, 10));
      } else {
        setResults([
          { title: `Google: ${term}`, url: `https://www.google.com/search?q=${encodeURIComponent(term)}`, snippet: 'Open in browser' },
          { title: `Shodan: ${term}`, url: `https://www.shodan.io/search?query=${encodeURIComponent(term)}`, snippet: 'Search Shodan for host/service info' },
          { title: `CVE Details: ${term}`, url: `https://www.cvedetails.com/google-search-results.php?q=${encodeURIComponent(term)}`, snippet: 'Search CVE database' },
          { title: `ExploitDB: ${term}`, url: `https://www.exploit-db.com/search?q=${encodeURIComponent(term)}`, snippet: 'Search for known exploits' },
          { title: `HackerTarget: ${term}`, url: `https://hackertarget.com/ip-tools/`, snippet: 'OSINT tools and IP lookup' },
        ]);
      }
    } catch {
      setResults([{ title: 'Error', url: '', snippet: 'Failed to search. Use the links below manually.' }]);
    }
    setLoading(false);
  };

  return (
    <div className="decoder">
      <div><div className="decoder-label">Search Query</div>
        <div style={{display:'flex',gap:8}}>
          <input className="decoder-textarea" style={{minHeight:'auto',height:32,flex:1}} value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search for vulnerabilities, CVEs, techniques..." onKeyDown={e=>e.key==='Enter'&&search()}/>
          <button className="decoder-smart" onClick={()=>search()} style={{height:32}}>{loading?<RefreshCw size={12} className="spin"/>:<Search size={12}/>} Search</button>
          <button className="decoder-smart" onClick={loadHosts} style={{height:32}}><Globe size={12}/> Load Hosts</button>
        </div>
      </div>
      {hosts.length > 0 && (
        <div><div className="decoder-label">Discovered Hosts (from proxy traffic)</div>
          <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
            {hosts.map(h => (
              <button key={h} className="decoder-btn" style={{border:'1px solid var(--border-1)',borderRadius:3,padding:'3px 8px',fontSize:10}} onClick={()=>{setQuery(h);search(h);}}>{h}</button>
            ))}
          </div>
        </div>
      )}
      {results.length > 0 && (
        <div><div className="decoder-label">Results</div>
          <div className="mcp-tools-list" style={{maxHeight:400,overflow:'auto'}}>
            {results.map((r,i) => (
              <div key={i} className="mcp-tool-item" style={{flexDirection:'column',alignItems:'flex-start',gap:2,padding:8}}>
                <a href={r.url} target="_blank" rel="noopener" style={{color:'var(--accent)',fontWeight:600,fontSize:12}}>{r.title}</a>
                {r.url && <span style={{fontSize:9,color:'var(--text-3)',fontFamily:'monospace'}}>{r.url}</span>}
                <span style={{fontSize:11,color:'var(--text-2)'}}>{r.snippet}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
