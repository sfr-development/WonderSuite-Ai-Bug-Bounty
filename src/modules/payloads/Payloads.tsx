import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Package, Download, Search, Copy, RefreshCcw, ChevronRight, Send, Zap, Folder, FolderCheck, Info, X, ShieldAlert } from 'lucide-react';
import { useAppStore } from '../../stores';
import { CATEGORY_INFO } from './category-info';
import './Payloads.css';

interface Category {
  name: string;
  downloaded: boolean;
  file_count: number;
  total_payloads: number;
  sources: string[];
}

interface CategoryList {
  categories: Category[];
  total_payloads: number;
  total_files: number;
  downloaded_categories: number;
  base_dir: string;
}

interface LoadResult {
  category: string;
  total: number;
  offset: number;
  limit: number;
  payloads: string[];
}

interface SearchHit { category: string; payload: string; }

const PAGE_SIZE = 200;

export function Payloads() {
  const { addToast, sendTo } = useAppStore();
  const [list, setList] = useState<CategoryList | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<LoadResult | null>(null);
  const [filter, setFilter] = useState('');
  const [searchMode, setSearchMode] = useState(false);
  const [searchResults, setSearchResults] = useState<SearchHit[]>([]);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [infoOpen, setInfoOpen] = useState<string | null>(null);

  const loadCategories = useCallback(async () => {
    try {
      const r = await invoke<CategoryList>('payload_list_categories');
      setList(r);
    } catch (e: any) {
      addToast({ title: 'Payloads', message: String(e), type: 'error' });
    }
  }, [addToast]);

  useEffect(() => { loadCategories(); }, [loadCategories]);

  useEffect(() => {
    if (!infoOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setInfoOpen(null); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [infoOpen]);

  const downloadCategory = async (cat: string) => {
    setDownloading(cat);
    try {
      await invoke('payload_download', { category: cat });
      addToast({ title: 'Download complete', message: `Category "${cat}" ready.`, type: 'success' });
      loadCategories();
    } catch (e: any) {
      addToast({ title: 'Download failed', message: String(e), type: 'error' });
    } finally {
      setDownloading(null);
    }
  };

  const downloadAll = async () => {
    setDownloading('all');
    try {
      await invoke('payload_download', { category: 'all' });
      addToast({ title: 'Download complete', message: 'All categories downloaded.', type: 'success' });
      loadCategories();
    } catch (e: any) {
      addToast({ title: 'Download failed', message: String(e), type: 'error' });
    } finally {
      setDownloading(null);
    }
  };

  const openCategory = async (cat: string, pageNum: number = 0) => {
    setSelected(cat); setPage(pageNum); setLoading(true);
    setSearchMode(false); setSearchResults([]);
    try {
      const r = await invoke<LoadResult>('payload_load', { category: cat, offset: pageNum * PAGE_SIZE, limit: PAGE_SIZE });
      setLoaded(r);
    } catch (e: any) {
      addToast({ title: 'Load failed', message: String(e), type: 'error' });
      setLoaded(null);
    } finally {
      setLoading(false);
    }
  };

  const runSearch = async () => {
    if (!filter.trim()) return;
    setSearchMode(true); setLoading(true); setSelected(null); setLoaded(null);
    try {
      const r = await invoke<{ total_matches: number; results: SearchHit[] }>('payload_search', { query: filter });
      setSearchResults(r.results || []);
    } catch (e: any) {
      addToast({ title: 'Search failed', message: String(e), type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const copyPayload = (p: string) => {
    navigator.clipboard.writeText(p);
    addToast({ title: 'Copied', message: p.length > 60 ? p.slice(0, 60) + '…' : p, type: 'success' });
  };

  const sendToRepeaterRaw = (p: string) => {
    const raw = `GET /?inject=${encodeURIComponent(p)} HTTP/1.1\nHost: example.com\nUser-Agent: WonderSuite\n`;
    sendTo('repeater', 'GET', `https://example.com/?inject=${encodeURIComponent(p)}`, raw);
    addToast({ title: 'Sent to Repeater', message: 'Open the Repeater tab to send.', type: 'info' });
  };

  const sendToAttack = (p: string) => {
    const raw = `GET /?inject=§${p}§ HTTP/1.1\nHost: example.com\nUser-Agent: WonderSuite\n`;
    sendTo('intruder', 'GET', `https://example.com/?inject=${encodeURIComponent(p)}`, raw);
    addToast({ title: 'Sent to Intruder', message: 'Payload wrapped in § markers.', type: 'info' });
  };

  const totalPages = loaded ? Math.ceil(loaded.total / PAGE_SIZE) : 0;
  const filteredCats = list?.categories ?? [];

  return (
    <div className="payloads-module">
      <div className="payloads-toolbar">
        <Package size={14} />
        <span className="payloads-title">Payload Arsenal</span>
        {list && (
          <span className="payloads-pill">
            {list.total_payloads.toLocaleString()} payloads · {list.downloaded_categories}/{list.categories.length} categories
          </span>
        )}
        <div className="payloads-spacer" />
        <button className="payloads-btn" onClick={() => loadCategories()} title="Refresh"><RefreshCcw size={11} /></button>
        <button
          className="payloads-btn accent"
          onClick={downloadAll}
          disabled={downloading !== null}>
          <Download size={11} /> {downloading === 'all' ? 'Downloading…' : 'Download All'}
        </button>
      </div>

      <div className="payloads-body">
        <aside className="payloads-sidebar">
          <div className="payloads-search">
            <Search size={11} />
            <input
              placeholder="Search across all payloads…"
              value={filter}
              onChange={e => setFilter(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runSearch()} />
            {filter && <button className="payloads-search-btn" onClick={runSearch}>Search</button>}
          </div>

          <div className="payloads-cat-list">
            {filteredCats.map(c => (
              <div
                key={c.name}
                className={`payloads-cat ${selected === c.name ? 'active' : ''} ${!c.downloaded ? 'missing' : ''}`}
                onClick={() => c.downloaded && openCategory(c.name)}>
                <div className="payloads-cat-head">
                  {c.downloaded ? <FolderCheck size={12} /> : <Folder size={12} />}
                  <span className="payloads-cat-name">{c.name}</span>
                  {c.downloaded && (
                    <span className="payloads-cat-count">{c.total_payloads.toLocaleString()}</span>
                  )}
                  {CATEGORY_INFO[c.name] && (
                    <button
                      className="payloads-info-btn"
                      onClick={(e) => { e.stopPropagation(); setInfoOpen(c.name); }}
                      title={`What is ${c.name}?`}>
                      <Info size={11} />
                    </button>
                  )}
                </div>
                {!c.downloaded && (
                  <button
                    className="payloads-cat-dl"
                    onClick={(e) => { e.stopPropagation(); downloadCategory(c.name); }}
                    disabled={downloading !== null}>
                    <Download size={9} /> {downloading === c.name ? '…' : 'Download'}
                  </button>
                )}
              </div>
            ))}
            {filteredCats.length === 0 && (
              <div className="payloads-empty"><span>No categories</span></div>
            )}
          </div>
          {list && <div className="payloads-base-dir" title={list.base_dir}>{list.base_dir}</div>}
        </aside>

        <main className="payloads-main">
          {loading && <div className="payloads-loading">Loading…</div>}

          {!loading && searchMode && (
            <>
              <div className="payloads-result-head">
                <ChevronRight size={11} />
                <span>Search results for <b>"{filter}"</b></span>
                <span className="payloads-pill">{searchResults.length} matches</span>
              </div>
              <div className="payloads-rows">
                {searchResults.map((r, idx) => (
                  <div key={idx} className="payloads-row">
                    <span className="payloads-row-cat">{r.category}</span>
                    <span className="payloads-row-val">{r.payload}</span>
                    <div className="payloads-row-actions">
                      <button onClick={() => copyPayload(r.payload)} title="Copy"><Copy size={10} /></button>
                      <button onClick={() => sendToRepeaterRaw(r.payload)} title="Send to Repeater"><Send size={10} /></button>
                      <button onClick={() => sendToAttack(r.payload)} title="Send to Intruder"><Zap size={10} /></button>
                    </div>
                  </div>
                ))}
                {searchResults.length === 0 && (
                  <div className="payloads-empty"><span>No matches.</span></div>
                )}
              </div>
            </>
          )}

          {!loading && !searchMode && loaded && (
            <>
              <div className="payloads-result-head">
                <ChevronRight size={11} />
                <span><b>{loaded.category}</b> — page {page + 1} of {totalPages || 1}</span>
                <span className="payloads-pill">{loaded.total.toLocaleString()} total</span>
                <div className="payloads-spacer" />
                <button
                  className="payloads-btn"
                  disabled={page === 0}
                  onClick={() => openCategory(loaded.category, page - 1)}>← Prev</button>
                <button
                  className="payloads-btn"
                  disabled={page + 1 >= totalPages}
                  onClick={() => openCategory(loaded.category, page + 1)}>Next →</button>
              </div>
              <div className="payloads-rows">
                {loaded.payloads.map((p, idx) => (
                  <div key={idx} className="payloads-row">
                    <span className="payloads-row-idx">{loaded.offset + idx + 1}</span>
                    <span className="payloads-row-val">{p}</span>
                    <div className="payloads-row-actions">
                      <button onClick={() => copyPayload(p)} title="Copy"><Copy size={10} /></button>
                      <button onClick={() => sendToRepeaterRaw(p)} title="Send to Repeater"><Send size={10} /></button>
                      <button onClick={() => sendToAttack(p)} title="Send to Intruder"><Zap size={10} /></button>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}

          {!loading && !searchMode && !loaded && (
            <div className="payloads-hero">
              <Package size={42} strokeWidth={1.2} />
              <h2>Pick a category</h2>
              <p>
                Categories with a green icon are downloaded and ready to browse.
                <br />Hit <b>Download All</b> to pull every SecLists / PayloadsAllTheThings file in one go.
              </p>
            </div>
          )}
        </main>
      </div>

      {infoOpen && CATEGORY_INFO[infoOpen] && (
        <CategoryInfoModal
          slug={infoOpen}
          onClose={() => setInfoOpen(null)}
          onCopy={copyPayload}
          onSendRepeater={sendToRepeaterRaw}
          onSendIntruder={sendToAttack} />
      )}
    </div>
  );
}

function CategoryInfoModal({
  slug, onClose, onCopy, onSendRepeater, onSendIntruder,
}: {
  slug: string;
  onClose: () => void;
  onCopy: (p: string) => void;
  onSendRepeater: (p: string) => void;
  onSendIntruder: (p: string) => void;
}) {
  const info = CATEGORY_INFO[slug];
  if (!info) return null;
  return (
    <div className="payloads-modal-overlay" onClick={onClose}>
      <div className="payloads-modal" onClick={e => e.stopPropagation()}>
        <header className="payloads-modal-head">
          <div className="payloads-modal-title-wrap">
            <ShieldAlert size={16} />
            <span className="payloads-modal-slug">{slug}</span>
            <span className="payloads-modal-label">{info.label}</span>
          </div>
          <button className="payloads-modal-close" onClick={onClose} title="Close (Esc)"><X size={14} /></button>
        </header>

        <div className="payloads-modal-body">
          <p className="payloads-modal-desc">{info.description}</p>

          <section>
            <h4>Where to inject</h4>
            <ul className="payloads-modal-list">
              {info.inject_at.map((s, i) => <li key={i}>{s}</li>)}
            </ul>
          </section>

          <section>
            <h4>Example payloads</h4>
            <div className="payloads-modal-examples">
              {info.examples.map((ex, i) => (
                <div key={i} className="payloads-modal-example">
                  <code className="payloads-modal-payload">{ex.payload}</code>
                  <p className="payloads-modal-explain">{ex.explain}</p>
                  <div className="payloads-modal-actions">
                    <button onClick={() => onCopy(ex.payload)} title="Copy"><Copy size={10} /> Copy</button>
                    <button onClick={() => onSendRepeater(ex.payload)} title="Send to Repeater"><Send size={10} /> Repeater</button>
                    <button onClick={() => onSendIntruder(ex.payload)} title="Send to Intruder"><Zap size={10} /> Intruder</button>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section>
            <h4>Notable real-world cases</h4>
            <ul className="payloads-modal-cases">
              {info.famous.map((c, i) => (
                <li key={i}>
                  <strong>{c.title}</strong> — {c.detail}
                </li>
              ))}
            </ul>
          </section>

          <section>
            <h4>Mitigation</h4>
            <p className="payloads-modal-mitigation">{info.mitigation}</p>
          </section>
        </div>
      </div>
    </div>
  );
}
