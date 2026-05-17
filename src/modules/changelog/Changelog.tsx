import { useEffect, useMemo, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Sparkles, ExternalLink, RefreshCw, Tag, Clock } from 'lucide-react';
import { useChangelogStore } from '../../stores/changelogStore';
// Vite ?raw import: the file at the repo root is bundled into the binary at
// build time. Works offline; the GitHub fetch below adds richer data when the
// user is online but everything stays usable if not.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
import bundledChangelog from '../../../CHANGELOG.md?raw';
import './Changelog.css';

const GITHUB_RELEASES_API =
  'https://api.github.com/repos/sfr-development/WonderSuite-Ai-Bug-Bounty/releases?per_page=20';
const GITHUB_REPO_URL = 'https://github.com/sfr-development/WonderSuite-Ai-Bug-Bounty';

interface ReleaseEntry {
  version: string;          // "0.3.12"
  date: string | null;      // "2026-05-17"
  body: string;             // markdown
  htmlUrl?: string;         // GitHub release page
  isLatest?: boolean;
  publishedAt?: string;     // ISO from GitHub
  source: 'github' | 'bundled';
}

// ──────────────────────────────────────────────────────────────────────────
// Local CHANGELOG.md parser. The file follows Keep-a-Changelog conventions:
// `## [0.3.11] — 2026-05-17` is a release header; everything until the next
// `## […]` header is the release body. We strip the `## [version] — date`
// line itself out of the body so we can render it as a styled header.
// ──────────────────────────────────────────────────────────────────────────
function parseBundledChangelog(md: string): ReleaseEntry[] {
  const lines = md.split(/\r?\n/);
  const out: ReleaseEntry[] = [];
  let current: ReleaseEntry | null = null;
  let bodyLines: string[] = [];

  const headerRe = /^##\s*\[([^\]]+)\]\s*(?:[—-]\s*([\d]{4}-[\d]{2}-[\d]{2}))?\s*$/;

  for (const line of lines) {
    const m = line.match(headerRe);
    if (m) {
      // flush previous
      if (current) {
        current.body = bodyLines.join('\n').trim();
        if (current.version.toLowerCase() !== 'unreleased' || current.body.length > 0) {
          out.push(current);
        }
        bodyLines = [];
      }
      current = {
        version: m[1].trim(),
        date: m[2] ?? null,
        body: '',
        source: 'bundled',
      };
    } else if (current) {
      bodyLines.push(line);
    }
    // Lines before the first header (intro) are ignored — they're general info.
  }
  if (current) {
    current.body = bodyLines.join('\n').trim();
    if (current.version.toLowerCase() !== 'unreleased' || current.body.length > 0) {
      out.push(current);
    }
  }
  return out;
}

// Normalize "v0.3.12" / "0.3.12" / "0.3.12-beta" → "0.3.12"
function normalizeVersion(v: string): string {
  return v.replace(/^v/i, '').trim();
}

function compareVersions(a: string, b: string): number {
  const pa = normalizeVersion(a).split('.').map((x) => parseInt(x, 10) || 0);
  const pb = normalizeVersion(b).split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da !== db) return da - db;
  }
  return 0;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
    });
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

// ──────────────────────────────────────────────────────────────────────────
// Component
// ──────────────────────────────────────────────────────────────────────────
export function Changelog() {
  const { currentVersion, markAsSeen } = useChangelogStore();
  const [githubReleases, setGithubReleases] = useState<ReleaseEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  // Mark as seen — clears the sidebar "1" badge on open.
  useEffect(() => {
    markAsSeen();
  }, [markAsSeen]);

  const bundled = useMemo(() => parseBundledChangelog(bundledChangelog), []);

  const fetchGithub = async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(GITHUB_RELEASES_API, {
        headers: { Accept: 'application/vnd.github+json' },
      });
      if (!resp.ok) throw new Error(`GitHub API ${resp.status}`);
      const data = await resp.json();
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
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      setGithubReleases(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGithub();
    // We only fetch once per mount; the user can hit refresh manually.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Merge: prefer GitHub release bodies (richer, includes per-release URL),
  // fall back to bundled for any version GitHub doesn't have. Sorted newest
  // first by version.
  const releases = useMemo<ReleaseEntry[]>(() => {
    const byVersion = new Map<string, ReleaseEntry>();
    for (const r of bundled) {
      byVersion.set(normalizeVersion(r.version), r);
    }
    if (githubReleases) {
      for (const r of githubReleases) {
        byVersion.set(normalizeVersion(r.version), r);
      }
    }
    const arr = Array.from(byVersion.values());
    arr.sort((a, b) => compareVersions(b.version, a.version));
    // Mark the topmost release as "latest"
    if (arr.length > 0) arr[0].isLatest = true;
    return arr;
  }, [bundled, githubReleases]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return releases;
    return releases.filter(
      (r) =>
        r.version.toLowerCase().includes(q) ||
        r.body.toLowerCase().includes(q)
    );
  }, [releases, search]);

  const isJustUpdated = useMemo(() => {
    // "just downloaded a new update" = the user's installed version matches
    // the latest release published less than 14 days ago AND they haven't
    // marked it as seen before this mount.
    if (releases.length === 0) return false;
    const top = releases[0];
    const sameVersion = normalizeVersion(top.version) === normalizeVersion(currentVersion);
    if (!sameVersion) return false;
    if (!top.publishedAt) return true; // bundled-only — treat as "fresh"
    const ageDays = (Date.now() - new Date(top.publishedAt).getTime()) / 86400000;
    return ageDays < 14;
  }, [releases, currentVersion]);

  return (
    <div className="cl-root">
      <header className="cl-hero">
        <div className="cl-hero-left">
          <div className="cl-hero-icon">
            <Sparkles size={22} strokeWidth={1.8} />
          </div>
          <div>
            <h1 className="cl-hero-title">What's new in WonderSuite</h1>
            <p className="cl-hero-sub">
              Per-release notes from GitHub, mirrored offline. You're running{' '}
              <span className="cl-hero-version">v{currentVersion}</span>.
            </p>
          </div>
        </div>
        <div className="cl-hero-right">
          <input
            type="text"
            className="cl-search"
            placeholder="Search releases (e.g. proxy, intercept, 0.3.10)…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button
            className="cl-refresh"
            onClick={fetchGithub}
            disabled={loading}
            title="Re-fetch from GitHub"
          >
            <RefreshCw size={14} className={loading ? 'spinning' : ''} />
            <span>{loading ? 'Fetching…' : 'Refresh'}</span>
          </button>
        </div>
      </header>

      {isJustUpdated && (
        <div className="cl-just-updated">
          <Sparkles size={14} />
          <span>
            You just updated to <b>v{currentVersion}</b>. The new release is at the top.
          </span>
        </div>
      )}

      {error && (
        <div className="cl-error">
          <span>GitHub fetch failed: {error}. Showing offline bundled changelog.</span>
        </div>
      )}

      <div className="cl-list">
        {filtered.length === 0 && (
          <div className="cl-empty">
            No releases match "<b>{search}</b>".
          </div>
        )}
        {filtered.map((r) => {
          const isCurrent = normalizeVersion(r.version) === normalizeVersion(currentVersion);
          return (
            <article
              key={r.version}
              className={`cl-release ${r.isLatest ? 'is-latest' : ''} ${isCurrent ? 'is-current' : ''}`}
            >
              <header className="cl-release-header">
                <div className="cl-release-titles">
                  <span className="cl-version-chip">
                    <Tag size={12} />
                    v{r.version}
                  </span>
                  {r.isLatest && <span className="cl-badge-new">NEW</span>}
                  {isCurrent && !r.isLatest && <span className="cl-badge-installed">INSTALLED</span>}
                  {isCurrent && r.isLatest && <span className="cl-badge-installed">YOU'RE ON THIS</span>}
                </div>
                <div className="cl-release-meta">
                  {r.date && (
                    <span className="cl-date" title={r.date}>
                      <Clock size={11} />
                      {formatDate(r.date)} &middot; {relativeTime(r.publishedAt ?? r.date)}
                    </span>
                  )}
                  {r.htmlUrl && (
                    <a
                      href={r.htmlUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="cl-github-link"
                      title="Open on GitHub"
                    >
                      GitHub
                      <ExternalLink size={11} />
                    </a>
                  )}
                </div>
              </header>
              <div className="cl-release-body">
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
        Released by SFR Development &middot;{' '}
        <a href={GITHUB_REPO_URL} target="_blank" rel="noopener noreferrer">
          View all on GitHub <ExternalLink size={11} />
        </a>
      </footer>
    </div>
  );
}
