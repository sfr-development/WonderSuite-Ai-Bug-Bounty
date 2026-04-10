import { useState, useCallback } from 'react';
import { KeyRound, BarChart3, CheckCircle, XCircle, Trash2 } from 'lucide-react';
import './Tokens.css';

interface AnalysisResult {
  entropy: number;
  rating: string;
  tokenCount: number;
  avgLength: number;
  uniqueChars: number;
  charDistribution: { char: string; freq: number; expected: number }[];
  bitAnalysis: number[];
  fipsMonobit: { pass: boolean; ones: number; total: number };
  fipsPoker: { pass: boolean; chi2: number };
  fipsRuns: { pass: boolean; runs: number };
  fipsLongRun: { pass: boolean; longest: number };
  duplicates: number;
  collisionRate: number;
}

function shannonEntropy(data: string): number {
  const freq: Record<string, number> = {};
  for (const c of data) freq[c] = (freq[c] || 0) + 1;
  const len = data.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

function fipsMonobit(bits: number[]): { pass: boolean; ones: number; total: number } {
  const ones = bits.filter(b => b === 1).length;
  const total = bits.length;
  return { pass: ones > total * 0.46 && ones < total * 0.54, ones, total };
}

function fipsPoker(bits: number[]): { pass: boolean; chi2: number } {
  const nibbles: Record<string, number> = {};
  for (let i = 0; i + 3 < bits.length; i += 4) {
    const key = bits.slice(i, i + 4).join('');
    nibbles[key] = (nibbles[key] || 0) + 1;
  }
  const k = Math.floor(bits.length / 4);
  const chi2 = (16 / k) * Object.values(nibbles).reduce((s, f) => s + f * f, 0) - k;
  return { pass: chi2 > 2.16 && chi2 < 46.17, chi2: Math.round(chi2 * 100) / 100 };
}

function fipsRuns(bits: number[]): { pass: boolean; runs: number } {
  let runs = 1;
  for (let i = 1; i < bits.length; i++) if (bits[i] !== bits[i - 1]) runs++;
  return { pass: runs > bits.length * 0.42 && runs < bits.length * 0.58, runs };
}

function fipsLongRun(bits: number[]): { pass: boolean; longest: number } {
  let max = 1, cur = 1;
  for (let i = 1; i < bits.length; i++) {
    if (bits[i] === bits[i - 1]) { cur++; max = Math.max(max, cur); }
    else cur = 1;
  }
  return { pass: max <= 26, longest: max };
}

function toBits(hex: string): number[] {
  return hex.split('').flatMap(c => {
    const n = parseInt(c, 16);
    return isNaN(n) ? [] : [n >> 3 & 1, n >> 2 & 1, n >> 1 & 1, n & 1];
  });
}

export function Tokens() {
  const [tokens, setTokens] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [tab, setTab] = useState<'summary' | 'distribution' | 'fips' | 'bits'>('summary');

  const analyze = useCallback(() => {
    const lines = tokens.split('\n').filter(Boolean);
    if (lines.length < 2) return;

    const allChars = lines.join('');
    const charSet = new Set(allChars);
    const avgLen = allChars.length / lines.length;

    const entropy = shannonEntropy(allChars);
    const maxEntropy = Math.log2(charSet.size);
    const normalized = maxEntropy > 0 ? (entropy / maxEntropy) * 100 : 0;

    // Character distribution
    const freq: Record<string, number> = {};
    for (const c of allChars) freq[c] = (freq[c] || 0) + 1;
    const expectedFreq = allChars.length / charSet.size;
    const charDistribution = Object.entries(freq)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 32)
      .map(([char, f]) => ({ char, freq: f, expected: expectedFreq }));

    // Bit-level analysis (per position)
    const maxLen = Math.max(...lines.map(l => l.length));
    const bitAnalysis: number[] = [];
    for (let pos = 0; pos < Math.min(maxLen, 64); pos++) {
      const chars = lines.map(l => l[pos]).filter(Boolean);
      if (chars.length > 1) {
        bitAnalysis.push(shannonEntropy(chars.join('')));
      }
    }

    // FIPS tests on hex data
    const hexData = allChars.replace(/[^0-9a-fA-F]/g, '');
    const bits = toBits(hexData);

    // Duplicates
    const unique = new Set(lines);
    const duplicates = lines.length - unique.size;

    setResult({
      entropy: normalized,
      rating: normalized > 90 ? 'Excellent' : normalized > 70 ? 'Reasonable' : normalized > 40 ? 'Poor' : 'Critical',
      tokenCount: lines.length,
      avgLength: Math.round(avgLen),
      uniqueChars: charSet.size,
      charDistribution,
      bitAnalysis,
      fipsMonobit: bits.length > 100 ? fipsMonobit(bits) : { pass: false, ones: 0, total: 0 },
      fipsPoker: bits.length > 100 ? fipsPoker(bits) : { pass: false, chi2: 0 },
      fipsRuns: bits.length > 100 ? fipsRuns(bits) : { pass: false, runs: 0 },
      fipsLongRun: bits.length > 100 ? fipsLongRun(bits) : { pass: false, longest: 0 },
      duplicates,
      collisionRate: duplicates / lines.length * 100,
    });
    setTab('summary');
  }, [tokens]);

  const generateSample = () => {
    const sample = Array.from({ length: 20 }, () =>
      Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
    ).join('\n');
    setTokens(sample);
  };

  const rc = (r: string) => r === 'Excellent' ? 'var(--green)' : r === 'Reasonable' ? '#eab308' : r === 'Poor' ? '#f0c040' : 'var(--red)';

  return (
    <div className="tokens">
      <div className="tokens-toolbar">
        <KeyRound size={14} />
        <span className="tokens-toolbar-title">Sequencer</span>
        <div style={{ flex: 1 }} />
        <button className="tokens-btn" onClick={generateSample}>Generate Sample</button>
        <button className="tokens-btn" onClick={() => { setTokens(''); setResult(null); }}><Trash2 size={10} /> Clear</button>
        <button className="tokens-btn primary" onClick={analyze} disabled={tokens.split('\n').filter(Boolean).length < 2}>
          <BarChart3 size={10} /> Analyze
        </button>
      </div>

      <div className="tokens-body">
        <div className="tokens-input-panel">
          <div className="tokens-input-header">
            Tokens (one per line)
            <span>{tokens.split('\n').filter(Boolean).length} loaded</span>
          </div>
          <textarea className="tokens-textarea" value={tokens} onChange={e => setTokens(e.target.value)}
            placeholder={"Paste session tokens, CSRF tokens, or other values here...\n\na1b2c3d4e5f6789012345\nf9e8d7c6b5a4321098765\n3c4d5e6f7a8b901234567\n..."} spellCheck={false} />
        </div>

        <div className="tokens-results-panel">
          {result ? (
            <>
              <div className="tokens-result-tabs">
                {(['summary', 'distribution', 'fips', 'bits'] as const).map(t => (
                  <button key={t} className={`tokens-result-tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
                    {t === 'summary' ? 'Summary' : t === 'distribution' ? 'Distribution' : t === 'fips' ? 'FIPS Tests' : 'Bit Analysis'}
                  </button>
                ))}
              </div>

              {tab === 'summary' && (
                <div className="tokens-summary">
                  <div className="tokens-score">
                    <div className="tokens-score-value" style={{ color: rc(result.rating) }}>
                      {Math.round(result.entropy)}%
                    </div>
                    <div className="tokens-score-label">Effective Entropy</div>
                    <div className="tokens-score-rating" style={{ color: rc(result.rating) }}>
                      {result.rating}
                    </div>
                  </div>
                  <div className="tokens-stats">
                    <div className="tokens-stat"><div className="tokens-stat-value">{result.tokenCount}</div><div className="tokens-stat-label">Tokens</div></div>
                    <div className="tokens-stat"><div className="tokens-stat-value">{result.avgLength}</div><div className="tokens-stat-label">Avg Length</div></div>
                    <div className="tokens-stat"><div className="tokens-stat-value">{result.uniqueChars}</div><div className="tokens-stat-label">Unique Chars</div></div>
                    <div className="tokens-stat"><div className="tokens-stat-value">{result.duplicates}</div><div className="tokens-stat-label">Duplicates</div></div>
                    <div className="tokens-stat"><div className="tokens-stat-value">{result.collisionRate.toFixed(1)}%</div><div className="tokens-stat-label">Collision Rate</div></div>
                  </div>
                </div>
              )}

              {tab === 'distribution' && (
                <div className="tokens-distribution">
                  <div className="tokens-chart">
                    {result.charDistribution.map((d, i) => (
                      <div key={i} className="tokens-bar-wrap" title={`'${d.char}': ${d.freq} (expected: ${Math.round(d.expected)})`}>
                        <div className="tokens-bar" style={{ height: `${(d.freq / result.charDistribution[0].freq) * 100}%` }} />
                        <span className="tokens-bar-label">{d.char}</span>
                      </div>
                    ))}
                  </div>
                  <div className="tokens-dist-expected">
                    <div className="tokens-dist-line" />
                    <span>Expected uniform frequency</span>
                  </div>
                </div>
              )}

              {tab === 'fips' && (
                <div className="tokens-fips">
                  {[
                    { name: 'Monobit Test', result: result.fipsMonobit, detail: `${result.fipsMonobit.ones} ones / ${result.fipsMonobit.total} bits` },
                    { name: 'Poker Test', result: result.fipsPoker, detail: `χ² = ${result.fipsPoker.chi2}` },
                    { name: 'Runs Test', result: result.fipsRuns, detail: `${result.fipsRuns.runs} runs` },
                    { name: 'Long Run Test', result: result.fipsLongRun, detail: `longest = ${result.fipsLongRun.longest}` },
                  ].map(test => (
                    <div key={test.name} className={`tokens-fips-row ${test.result.pass ? 'pass' : 'fail'}`}>
                      {test.result.pass ? <CheckCircle size={12} /> : <XCircle size={12} />}
                      <span className="tokens-fips-name">{test.name}</span>
                      <span className="tokens-fips-detail">{test.detail}</span>
                      <span className="tokens-fips-badge">{test.result.pass ? 'PASS' : 'FAIL'}</span>
                    </div>
                  ))}
                </div>
              )}

              {tab === 'bits' && (
                <div className="tokens-bit-analysis">
                  <div className="tokens-bit-header">Per-Position Entropy (bits)</div>
                  <div className="tokens-bit-chart">
                    {result.bitAnalysis.map((e, i) => (
                      <div key={i} className="tokens-bit-bar-wrap" title={`Position ${i}: ${e.toFixed(2)} bits`}>
                        <div className="tokens-bit-bar" style={{ height: `${Math.min(e / 4 * 100, 100)}%`, background: e > 3 ? 'var(--green)' : e > 2 ? '#eab308' : 'var(--red)' }} />
                        <span className="tokens-bit-pos">{i}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="tokens-empty">
              <KeyRound size={28} strokeWidth={1} />
              <p>Paste tokens and analyze</p>
              <span>Supports Shannon entropy, FIPS 140-2 tests, and per-position bit analysis</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
