import { useState, useMemo, useRef, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { BookText, Search, Hash, ExternalLink, FileQuestion } from 'lucide-react';
import { DOC_GROUPS, DOC_PAGES, groupOf, titleOf } from './content/manifest';
import './Docs.css';

// Markdown content is bundled at build time — one .md file per page slug.
const rawPages = import.meta.glob('./content/*.md', {
  query: '?raw',
  eager: true,
  import: 'default',
}) as Record<string, string>;

const PAGES: Record<string, string> = {};
for (const path in rawPages) {
  const slug = path.replace('./content/', '').replace(/\.md$/, '');
  PAGES[slug] = rawPages[path];
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-');
}

function textOf(children: unknown): string {
  if (typeof children === 'string') return children;
  if (typeof children === 'number') return String(children);
  if (Array.isArray(children)) return children.map(textOf).join('');
  if (children && typeof children === 'object' && 'props' in (children as any)) {
    return textOf((children as any).props.children);
  }
  return '';
}

interface Heading {
  text: string;
  id: string;
}

function getHeadings(content: string): Heading[] {
  const out: Heading[] = [];
  const re = /^##\s+(.+)$/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content))) {
    const text = m[1].trim();
    out.push({ text, id: slugify(text) });
  }
  return out;
}

interface SearchHit {
  slug: string;
  title: string;
  group: string;
  snippet: string;
}

export function Docs() {
  const [activeSlug, setActiveSlug] = useState<string>(DOC_PAGES[0]?.slug ?? 'overview');
  const [query, setQuery] = useState('');
  const contentRef = useRef<HTMLDivElement>(null);

  const content = PAGES[activeSlug] ?? '';
  const headings = useMemo(() => getHeadings(content), [content]);

  const goToPage = useCallback((slug: string) => {
    setActiveSlug(slug);
    setQuery('');
    contentRef.current?.scrollTo({ top: 0 });
  }, []);

  const scrollToHeading = useCallback((id: string) => {
    const el = contentRef.current?.querySelector(`#${CSS.escape(id)}`);
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, []);

  const searchHits = useMemo<SearchHit[] | null>(() => {
    const q = query.trim().toLowerCase();
    if (q.length < 2) return null;
    const hits: SearchHit[] = [];
    for (const group of DOC_GROUPS) {
      for (const page of group.pages) {
        const body = PAGES[page.slug] ?? '';
        const titleMatch = page.title.toLowerCase().includes(q);
        const bodyIdx = body.toLowerCase().indexOf(q);
        if (!titleMatch && bodyIdx < 0) continue;
        let snippet = '';
        if (bodyIdx >= 0) {
          const start = Math.max(0, bodyIdx - 45);
          snippet =
            (start > 0 ? '…' : '') +
            body
              .slice(start, bodyIdx + q.length + 70)
              .replace(/\n+/g, ' ')
              .replace(/[#*`>|]/g, '')
              .trim() +
            '…';
        }
        hits.push({ slug: page.slug, title: page.title, group: group.title, snippet });
      }
    }
    return hits;
  }, [query]);

  const openExternal = useCallback((url: string) => {
    import('@tauri-apps/plugin-opener')
      .then((m) => m.openUrl(url))
      .catch(() => window.open(url, '_blank'));
  }, []);

  const mdComponents = useMemo(
    () => ({
      a({ href, children }: any) {
        const h: string = href ?? '';
        if (h.startsWith('page:')) {
          const target = h.slice(5);
          return (
            <a
              className="docs-md-link"
              onClick={(e) => {
                e.preventDefault();
                goToPage(target);
              }}
            >
              {children}
            </a>
          );
        }
        if (h.startsWith('#')) {
          return (
            <a
              className="docs-md-link"
              href={h}
              onClick={(e) => {
                e.preventDefault();
                scrollToHeading(h.slice(1));
              }}
            >
              {children}
            </a>
          );
        }
        return (
          <a
            className="docs-md-link docs-md-link-ext"
            onClick={(e) => {
              e.preventDefault();
              openExternal(h);
            }}
          >
            {children}
            <ExternalLink size={11} />
          </a>
        );
      },
      h1: ({ children }: any) => <h1 id={slugify(textOf(children))}>{children}</h1>,
      h2: ({ children }: any) => <h2 id={slugify(textOf(children))}>{children}</h2>,
      h3: ({ children }: any) => <h3 id={slugify(textOf(children))}>{children}</h3>,
    }),
    [goToPage, scrollToHeading, openExternal],
  );

  return (
    <div className="docs">
      <div className="docs-body">
        {/* ── Sidebar: search + table of contents ─── */}
        <aside className="docs-sidebar">
          <div className="docs-sidebar-head">
            <BookText size={15} />
            <span>Documentation</span>
          </div>
          <div className="docs-search">
            <Search size={13} />
            <input
              placeholder="Search docs…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <button className="docs-search-clear" onClick={() => setQuery('')}>
                ×
              </button>
            )}
          </div>

          <nav className="docs-nav">
            {searchHits ? (
              <div className="docs-results">
                <div className="docs-results-count">
                  {searchHits.length} {searchHits.length === 1 ? 'result' : 'results'}
                </div>
                {searchHits.map((hit) => (
                  <button
                    key={hit.slug}
                    className="docs-result"
                    onClick={() => goToPage(hit.slug)}
                  >
                    <div className="docs-result-title">{hit.title}</div>
                    <div className="docs-result-group">{hit.group}</div>
                    {hit.snippet && <div className="docs-result-snippet">{hit.snippet}</div>}
                  </button>
                ))}
                {searchHits.length === 0 && (
                  <div className="docs-results-empty">No matches</div>
                )}
              </div>
            ) : (
              DOC_GROUPS.map((group) => (
                <div key={group.title} className="docs-nav-group">
                  <div className="docs-nav-group-title">{group.title}</div>
                  {group.pages.map((page) => {
                    const isActive = page.slug === activeSlug;
                    return (
                      <div key={page.slug}>
                        <button
                          className={`docs-nav-item ${isActive ? 'active' : ''}`}
                          onClick={() => goToPage(page.slug)}
                        >
                          {page.title}
                        </button>
                        {isActive && headings.length > 0 && (
                          <div className="docs-nav-headings">
                            {headings.map((hd) => (
                              <button
                                key={hd.id}
                                className="docs-nav-heading"
                                onClick={() => scrollToHeading(hd.id)}
                              >
                                <Hash size={9} />
                                {hd.text}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              ))
            )}
          </nav>
        </aside>

        {/* ── Content pane ─── */}
        <div className="docs-content" ref={contentRef}>
          {content ? (
            <article className="docs-article">
              <div className="docs-breadcrumb">
                {groupOf(activeSlug)}
                <span className="docs-breadcrumb-sep">/</span>
                <span className="docs-breadcrumb-current">{titleOf(activeSlug)}</span>
              </div>
              <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                {content}
              </ReactMarkdown>
            </article>
          ) : (
            <div className="docs-empty">
              <FileQuestion size={28} />
              <span>This page has no content yet.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
