import { createHighlighter, type Highlighter } from 'shiki';

// Languages loaded into the single shared highlighter instance
const LANGS = [
  'javascript',
  'typescript',
  'css',
  'scss',
  'html',
  'xml',
  'json',
  'bash',
  'http',
  'markdown',
  'plaintext',
] as const;

export type HighlightLang = typeof LANGS[number] | string;

// WonderSuite dark theme — one-dark-pro matches the existing color palette
const THEME = 'one-dark-pro';

let _hl: Highlighter | null = null;
let _initPromise: Promise<Highlighter> | null = null;

export async function initHighlighter(): Promise<Highlighter> {
  if (_hl) return _hl;
  if (_initPromise) return _initPromise;
  _initPromise = createHighlighter({
    themes: [THEME],
    langs: [...LANGS],
  }).then(hl => {
    _hl = hl;
    return hl;
  });
  return _initPromise;
}

export async function highlight(code: string, lang: string): Promise<string> {
  const hl = await initHighlighter();
  const safeLang = (LANGS as readonly string[]).includes(lang) ? lang : 'plaintext';
  return hl.codeToHtml(code, { lang: safeLang, theme: THEME });
}

// Synchronous fallback — only works after initHighlighter() has resolved.
// Returns plain <pre><code> if called before init finishes.
export function highlightSync(code: string, lang: string): string {
  if (!_hl) return `<pre class="shiki-fallback"><code>${escHtml(code)}</code></pre>`;
  const safeLang = (LANGS as readonly string[]).includes(lang) ? lang : 'plaintext';
  return _hl.codeToHtml(code, { lang: safeLang, theme: THEME });
}

export function isHighlighterReady(): boolean {
  return _hl !== null;
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Canonical lang normaliser — maps mime/extension to a lang the highlighter knows
export function detectHighlightLang(mime?: string, path?: string): string {
  const p = (path || '').split('?')[0];
  const ext = p.split('.').pop()?.toLowerCase() || '';

  if (['ts', 'tsx'].includes(ext)) return 'typescript';
  if (['js', 'mjs', 'jsx', 'cjs'].includes(ext) || mime?.includes('javascript') || mime?.includes('ecmascript')) return 'javascript';
  if (['scss', 'less'].includes(ext)) return 'scss';
  if (ext === 'css' || mime?.includes('css')) return 'css';
  if (ext === 'json' || mime?.includes('json')) return 'json';
  if (['html', 'htm'].includes(ext) || mime?.includes('html')) return 'html';
  if (ext === 'xml' || mime?.includes('xml')) return 'xml';
  if (['sh', 'bash', 'zsh'].includes(ext) || mime?.includes('bash') || mime?.includes('shell')) return 'bash';
  if (mime?.includes('markdown') || ext === 'md') return 'markdown';
  return 'plaintext';
}
