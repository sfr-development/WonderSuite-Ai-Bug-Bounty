import { useState } from 'react';
import { useEffect } from 'react';
import { GitCompare, Trash2, ArrowLeftRight } from 'lucide-react';
import { useAppStore } from '../../stores';
import './Comparer.css';

interface DiffResult {
  type: 'equal' | 'add' | 'remove';
  value: string;
}

function computeWordDiff(a: string, b: string): DiffResult[] {
  const wordsA = a.split(/(\s+)/);
  const wordsB = b.split(/(\s+)/);


  // Simple LCS-based word diff
  const m = wordsA.length, n = wordsB.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) {
    dp[i][j] = wordsA[i - 1] === wordsB[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
  }

  let i = m, j = n;
  const ops: DiffResult[] = [];
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && wordsA[i - 1] === wordsB[j - 1]) {
      ops.unshift({ type: 'equal', value: wordsA[i - 1] });
      i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      ops.unshift({ type: 'add', value: wordsB[j - 1] });
      j--;
    } else {
      ops.unshift({ type: 'remove', value: wordsA[i - 1] });
      i--;
    }
  }

  return ops;
}

function computeLineDiff(a: string, b: string): DiffResult[] {
  const linesA = a.split('\n');
  const linesB = b.split('\n');

  const m = linesA.length, n = linesB.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) {
    dp[i][j] = linesA[i - 1] === linesB[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
  }
  let i = m, j = n;
  const ops: DiffResult[] = [];
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && linesA[i - 1] === linesB[j - 1]) {
      ops.unshift({ type: 'equal', value: linesA[i - 1] });
      i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      ops.unshift({ type: 'add', value: linesB[j - 1] });
      j--;
    } else {
      ops.unshift({ type: 'remove', value: linesA[i - 1] });
      i--;
    }
  }
  return ops;
}

export function Comparer() {
  const [left, setLeft] = useState('');
  const [right, setRight] = useState('');
  const [mode, setMode] = useState<'words' | 'lines'>('words');
  const [diff, setDiff] = useState<DiffResult[] | null>(null);

  const { pendingSendTo, clearSendTo } = useAppStore();

  useEffect(() => {
    if (pendingSendTo?.tool === 'comparer') {
      const { requestRaw, responseRaw, target } = pendingSendTo;
      const content = responseRaw ? `${requestRaw}\n\n${responseRaw}` : requestRaw;
      
      if (target === 'right') {
        setRight(content);
      } else {
        setLeft(content);
      }
      setDiff(null);
      clearSendTo();
    }
  }, [pendingSendTo, clearSendTo]);

  const runDiff = () => {
    const result = mode === 'words' ? computeWordDiff(left, right) : computeLineDiff(left, right);
    setDiff(result);
  };

  const swap = () => { const tmp = left; setLeft(right); setRight(tmp); setDiff(null); };

  const stats = diff ? {
    added: diff.filter(d => d.type === 'add').length,
    removed: diff.filter(d => d.type === 'remove').length,
    equal: diff.filter(d => d.type === 'equal').length,
  } : null;

  return (
    <div className="comparer">
      <div className="comparer-toolbar">
        <GitCompare size={14} />
        <span className="comparer-title">Comparer</span>
        <div className="comparer-mode">
          {(['words', 'lines'] as const).map(m => (
            <button key={m} className={`comparer-mode-btn ${mode === m ? 'active' : ''}`} onClick={() => { setMode(m); setDiff(null); }}>{m}</button>
          ))}
        </div>
        <div style={{ flex: 1 }} />
        <button className="comparer-action" onClick={swap}><ArrowLeftRight size={12} /> Swap</button>
        <button className="comparer-action primary" onClick={runDiff}><GitCompare size={12} /> Compare</button>
        <button className="comparer-action" onClick={() => { setLeft(''); setRight(''); setDiff(null); }}><Trash2 size={12} /> Clear</button>
      </div>

      <div className="comparer-body">
        <div className="comparer-inputs">
          <div className="comparer-input-panel">
            <div className="comparer-input-header">Item 1 <span>{left.length} chars</span></div>
            <textarea value={left} onChange={e => { setLeft(e.target.value); setDiff(null); }} placeholder="Paste first item here..." spellCheck={false} />
          </div>
          <div className="comparer-input-panel">
            <div className="comparer-input-header">Item 2 <span>{right.length} chars</span></div>
            <textarea value={right} onChange={e => { setRight(e.target.value); setDiff(null); }} placeholder="Paste second item here..." spellCheck={false} />
          </div>
        </div>

        {diff && (
          <div className="comparer-result">
            <div className="comparer-result-header">
              <span>Diff Result ({mode})</span>
              {stats && <span className="comparer-stats">
                <span className="diff-add">+{stats.added}</span>
                <span className="diff-remove">-{stats.removed}</span>
                <span className="diff-equal">={stats.equal}</span>
              </span>}
            </div>
            <div className="comparer-diff-view">
              {mode === 'lines' ? diff.map((d, i) => (
                <div key={i} className={`comparer-diff-line ${d.type}`}>
                  <span className="diff-prefix">{d.type === 'add' ? '+' : d.type === 'remove' ? '-' : ' '}</span>
                  {d.value}
                </div>
              )) : (
                <div className="comparer-diff-inline">
                  {diff.map((d, i) => (
                    <span key={i} className={`diff-word ${d.type}`}>{d.value}</span>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {!diff && !left && !right && (
          <div className="comparer-empty">
            <GitCompare size={32} strokeWidth={1} />
            <p>Paste two items to compare</p>
            <span>Supports word-level and line-level diff with highlighting</span>
          </div>
        )}
      </div>
    </div>
  );
}
