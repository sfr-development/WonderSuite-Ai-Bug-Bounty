import { useEffect, useMemo, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { invoke } from '@tauri-apps/api/core';
import { ExternalLink, RefreshCw } from 'lucide-react';
import { useChangelogStore } from '../../stores/changelogStore';
import bundledChangelog from '../../../CHANGELOG.md?raw';
import './Changelog.css';

const GITHUB_REPO_URL = 'https://github.com/sfr-development/WonderSuite-Ai-Bug-Bounty';

interface ReleaseEntry {
  version: string;
  date: string | null;
  body: string;
  htmlUrl?: string;
  isLatest?: boolean;
  publishedAt?: string;
  source: 'github' | 'bundled';
}

// ── Parser for bundled CHANGELOG.md ──────────────────────────────────────
function parseBundledChangelog(md: string): ReleaseEntry[] {
  const lines = md.split(/\r?\n/);
  const out: ReleaseEntry[] = [];
  let current: ReleaseEntry | null = null;
  let bodyLines: string[] = [];
  const headerRe = /^##\s*\[([^\]]+)\]\s*(?:[—-]\s*([\d]{4}-[\d]{2}-[\d]{2}))?\s*$/;

  for (const line of lines) {
    const m = line.match(headerRe);
    if (m) {
      if (current) {
        current.body = bodyLines.join('\n').trim();
        if (current.version.toLowerCase() !== 'unreleased' || current.body.length > 0) {
          out.push(current);
        }
        bodyLines = [];
      }
      current = { version: m[1].trim(), date: m[2] ?? null, body: '', source: 'bundled' };
    } else if (current) {
      bodyLines.push(line);
    }
  }
  if (current) {
    current.body = bodyLines.join('\n').trim();
    if (current.version.toLowerCase() !== 'unreleased' || current.body.length > 0) {
      out.push(current);
    }
  }
  return out;
}

const normalizeVersion = (v: string) => v.replace(/^v/i, '').trim();

function compareVersions(a: string, b: string): number {
  const pa = normalizeVersion(a).split('.').map((x) => parseInt(x, 10) || 0);
  const pb = normalizeVersion(b).split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return iso;
  }
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '';
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return '';
  const s = Math.round(ms / 1000);
  if (s < 60) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d}d ago`;
  const mo = Math.round(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.round(mo / 12)}y ago`;
}

// ── Component ───────────────────────────────────────────────────────────
export function Changelog() {
  const { currentVersion, markAsSeen } = useChangelogStore();
  const [githubReleases, setGithubReleases] = useState<ReleaseEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  useEffect(() => { markAsSeen(); }, [markAsSeen]);

  const bundled = useMemo(() => parseBundledChangelog(bundledChangelog), []);

  const fetchGithub = async () => {
    setLoading(true);
    setError(null);
    try {
      // v0.3.13+: route through Rust to bypass webview CSP. Returns the raw
      // GitHub releases JSON string.
      const text = await invoke<string>('fetch_github_releases');
      const data = JSON.parse(text);
      const parsed: ReleaseEntry[] = (data as Array<{
        tag_name: string; name?: string; body?: string;
        published_at?: string; html_url?: string;
      }>).map((r) => ({
        version: normalizeVersion(r.tag_name),
        date: r.published_at ? r.published_at.slice(0, 10) : null,
        body: (r.body ?? '').trim(),
        htmlUrl: r.html_url,
        publishedAt: r.published_at,
        source: 'github' as const,
      }));
      setGithubReleases(parsed);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setGithubReleases(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchGithub(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const releases = useMemo<ReleaseEntry[]>(() => {
    // Merge strategy: pick the BEST body between bundled and GitHub for each
    // version. GitHub gives us live metadata (URLs, publish times) but its
    // body was historically the workflow's boilerplate ("This is an
    // automated release for WonderSuite..."). We prefer bundled body when
    // it's noticeably longer OR when GitHub body looks like the boilerplate.
    // GitHub metadata (htmlUrl, publishedAt) is always kept.
    const looksLikeBoilerplate = (s: string) =>
      /this is an automated release/i.test(s) ||
      /downloads available:/i.test(s) ||
      s.trim().length < 80;

    const byVersion = new Map<string, ReleaseEntry>();
    for (const r of bundled) byVersion.set(normalizeVersion(r.version), r);

    if (githubReleases) {
      for (const gh of githubReleases) {
        const key = normalizeVersion(gh.version);
        const local = byVersion.get(key);
        if (!local) {
          byVersion.set(key, gh);
          continue;
        }
        // Merge: GitHub metadata wins (htmlUrl, publishedAt, date), but the
        // body comes from whichever source has the richer content.
        const ghBoiler = looksLikeBoilerplate(gh.body);
        const preferBundled = ghBoiler || (local.body.length > gh.body.length + 200);
        byVersion.set(key, {
          ...gh,
          body: preferBundled ? local.body : gh.body,
          source: preferBundled ? 'bundled' : 'github',
        });
      }
    }

    const arr = Array.from(byVersion.values());
    arr.sort((a, b) => compareVersions(b.version, a.version));
    if (arr.length > 0) arr[0].isLatest = true;
    return arr;
  }, [bundled, githubReleases]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return releases;
    return releases.filter(
      (r) => r.version.toLowerCase().includes(q) || r.body.toLowerCase().includes(q),
    );
  }, [releases, search]);

  const isJustUpdated = useMemo(() => {
    if (releases.length === 0) return false;
    const top = releases[0];
    if (normalizeVersion(top.version) !== normalizeVersion(currentVersion)) return false;
    if (!top.publishedAt) return true;
    return (Date.now() - new Date(top.publishedAt).getTime()) / 86400000 < 14;
  }, [releases, currentVersion]);

  return (
    <div className="cl-root">
      {/* ── Hero ────────────────────────────────────────────────── */}
      <header className="cl-hero">
        <div className="cl-hero-text">
          <div className="cl-hero-eyebrow">RELEASE NOTES</div>
          <h1 className="cl-hero-title">What's new</h1>
          <p className="cl-hero-sub">
            You're on <span className="cl-version-tag">v{currentVersion}</span>
            {isJustUpdated && <span className="cl-just-pill">just updated</span>}
          </p>
        </div>
        <div className="cl-hero-actions">
          <div className="cl-search-wrap">
            <input
              type="text"
              className="cl-search"
              placeholder="Search releases…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button
            className="cl-refresh"
            onClick={fetchGithub}
            disabled={loading}
            title="Re-fetch from GitHub"
          >
            <RefreshCw size={13} className={loading ? 'spinning' : ''} />
            {loading ? 'Fetching…' : 'Refresh'}
          </button>
        </div>
      </header>

      {error && (
        <div className="cl-error">
          GitHub fetch failed ({error}). Showing offline bundled changelog.
        </div>
      )}

      {/* ── List ────────────────────────────────────────────────── */}
      <div className="cl-list">
        {filtered.length === 0 && (
          <div className="cl-empty">
            No releases match <b>"{search}"</b>.
          </div>
        )}
        {filtered.map((r) => {
          const isCurrent = normalizeVersion(r.version) === normalizeVersion(currentVersion);
          return (
            <article
              key={r.version}
              className={`cl-card ${r.isLatest ? 'is-latest' : ''} ${isCurrent ? 'is-current' : ''}`}
            >
              <div className="cl-card-spine" />
              <header className="cl-card-head">
                <div className="cl-card-titles">
                  <div className="cl-card-version">v{r.version}</div>
                  <div className="cl-card-meta">
                    {r.date && (
                      <>
                        <span>{formatDate(r.date)}</span>
                        <span className="cl-meta-dot">·</span>
                        <span className="cl-meta-rel">{relativeTime(r.publishedAt ?? r.date)}</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="cl-card-tags">
                  {r.isLatest && <span className="cl-tag cl-tag-new">Latest</span>}
                  {isCurrent && <span className="cl-tag cl-tag-installed">Installed</span>}
                  {r.htmlUrl && (
                    <a
                      href={r.htmlUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="cl-tag cl-tag-link"
                      title="Open on GitHub"
                    >
                      GitHub
                      <ExternalLink size={11} />
                    </a>
                  )}
                </div>
              </header>
              <div className="cl-card-body">
                {r.body ? (
                  <ReactMarkdown
                    remarkPlugins={[remarkGfm]}
                    components={{
                      a: ({ href, children }) => (
                        <a href={href} target="_blank" rel="noopener noreferrer">
                          {children}
                        </a>
                      ),
                    }}
                  >
                    {r.body}
                  </ReactMarkdown>
                ) : (
                  <p className="cl-empty-body">No release notes for this version.</p>
                )}
              </div>
            </article>
          );
        })}
      </div>

      <footer className="cl-footer">
        <span>SFR Development</span>
        <span className="cl-footer-dot">·</span>
        <a href={GITHUB_REPO_URL} target="_blank" rel="noopener noreferrer">
          View all releases on GitHub
          <ExternalLink size={11} />
        </a>
      </footer>
    </div>
  );
}
