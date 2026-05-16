import { useState, useEffect, useCallback } from 'react';
import { Cookie, ListChecks, Play, Plus, Trash2, Download, Upload, RefreshCcw, Check, X, ToggleLeft, ToggleRight, Zap, Link2, Link2Off } from 'lucide-react';
import { useVisibilityAwareInterval } from '../../hooks/useVisibilityAwareInterval';
import './Session.css';

type SessionTab = 'cookies' | 'macros' | 'rules';

interface CookieItem {
  name: string; value: string; domain: string; path: string;
  secure: boolean; httponly: boolean; samesite?: string; expires?: string;
}

interface MacroStep {
  method: string; url: string; headers: Record<string, string>;
  body?: string; extract?: { name: string; source: string; regex: string; group: number };
}

interface MacroItem { id: string; name: string; description: string; steps: MacroStep[]; }

interface RuleItem {
  id: string; name: string; enabled: boolean;
  scope: string; actions: Array<{ type: string; [k: string]: string }>;
}

export function Session() {
  const [tab, setTab] = useState<SessionTab>('cookies');

  const [cookies, setCookies] = useState<CookieItem[]>([]);
  const [cookieFilter, setCookieFilter] = useState('');
  const [editCookie, setEditCookie] = useState<Partial<CookieItem> | null>(null);

  const [macros, setMacros] = useState<MacroItem[]>([]);
  const [selectedMacro, setSelectedMacro] = useState<string | null>(null);
  const [editingMacro, setEditingMacro] = useState<{ name: string; description: string; steps: MacroStep[] } | null>(null);
  const [macroResult, setMacroResult] = useState<Record<string, string> | null>(null);

  const [rules, setRules] = useState<RuleItem[]>([]);

  const [browserSyncLive, setBrowserSyncLive] = useState(false);

  const pollBrowserSync = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const live = await invoke<boolean>('session_browser_sync_status');
      setBrowserSyncLive(live);
    } catch { setBrowserSyncLive(false); }
  }, []);

  useVisibilityAwareInterval(pollBrowserSync, 4000);

  const loadCookies = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const data: CookieItem[] = await invoke('session_get_cookies', { domain: null });
      setCookies(data);
    } catch { setCookies([]); }
  }, []);

  const loadMacros = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const data: MacroItem[] = await invoke('session_get_macros');
      setMacros(data);
    } catch { setMacros([]); }
  }, []);

  const loadRules = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const data: RuleItem[] = await invoke('session_get_rules');
      setRules(data);
    } catch { setRules([]); }
  }, []);

  useEffect(() => {
    loadCookies(); loadMacros(); loadRules();
  }, []);

  const saveCookie = async () => {
    if (!editCookie?.name || !editCookie?.domain) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('session_set_cookie', {
        name: editCookie.name, value: editCookie.value || '',
        domain: editCookie.domain, path: editCookie.path || '/',
        secure: editCookie.secure || false, httponly: editCookie.httponly || false,
        samesite: editCookie.samesite || null,
      });
      setEditCookie(null); loadCookies();
    } catch (err) { console.error(err); }
  };

  const deleteCookie = async (name: string, domain: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('session_remove_cookie', { name, domain });
      loadCookies();
    } catch { /* ignore */ }
  };

  const clearAllCookies = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('session_clear_cookies');
      loadCookies();
    } catch { /* ignore */ }
  };

  const exportCookies = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const json: string = await invoke('session_export_cookies');
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'cookies.json'; a.click();
    } catch { /* ignore */ }
  };

  const importCookies = async () => {
    const input = document.createElement('input');
    input.type = 'file'; input.accept = '.json';
    input.onchange = async () => {
      if (!input.files?.[0]) return;
      const text = await input.files[0].text();
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        await invoke('session_import_cookies', { json: text });
        loadCookies();
      } catch (err) { console.error(err); }
    };
    input.click();
  };

  const createMacro = async () => {
    if (!editingMacro?.name) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('session_create_macro', {
        name: editingMacro.name,
        description: editingMacro.description,
        steps: editingMacro.steps,
      });
      setEditingMacro(null); loadMacros();
    } catch (err) { console.error(err); }
  };

  const runMacro = async (macroId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const result: { extracted_values: Record<string, string> } = await invoke('session_run_macro', { macroId });
      setMacroResult(result.extracted_values);
    } catch (err) { console.error(err); }
  };

  const deleteMacro = async (macroId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('session_delete_macro', { macroId });
      if (selectedMacro === macroId) setSelectedMacro(null);
      loadMacros();
    } catch { /* ignore */ }
  };

  const toggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('session_toggle_rule', { ruleId, enabled });
      loadRules();
    } catch { /* ignore */ }
  };

  const deleteRule = async (ruleId: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('session_delete_rule', { ruleId });
      loadRules();
    } catch { /* ignore */ }
  };

  const addMacroStep = () => {
    if (!editingMacro) return;
    setEditingMacro(prev => prev ? {
      ...prev,
      steps: [...prev.steps, { method: 'GET', url: '', headers: {}, }],
    } : null);
  };

  const filteredCookies = cookies.filter(c =>
    !cookieFilter || c.domain.includes(cookieFilter) || c.name.includes(cookieFilter)
  );

  const activeMacro = macros.find(m => m.id === selectedMacro);

  return (
    <div className="session">
      <div className="session-toolbar">
        <Cookie size={14} />
        <span className="session-toolbar-title">Session Manager</span>
        <div style={{ flex: 1 }} />
      </div>

      <div className="session-tabs">
        <button className={`session-tab ${tab === 'cookies' ? 'active' : ''}`} onClick={() => setTab('cookies')}>
          <Cookie size={10} /> Cookie Jar <span className="session-badge">{cookies.length}</span>
        </button>
        <button className={`session-tab ${tab === 'macros' ? 'active' : ''}`} onClick={() => setTab('macros')}>
          <Zap size={10} /> Macros <span className="session-badge">{macros.length}</span>
        </button>
        <button className={`session-tab ${tab === 'rules' ? 'active' : ''}`} onClick={() => setTab('rules')}>
          <ListChecks size={10} /> Session Rules <span className="session-badge">{rules.length}</span>
        </button>
      </div>

      <div className="session-body">
        {/* Cookie Jar Tab */}
        {tab === 'cookies' && (
          <div className="session-cookie-panel">
            <div className="session-cookie-actions">
              <input type="text" className="session-filter-input" placeholder="Filter by domain or name..."
                value={cookieFilter} onChange={e => setCookieFilter(e.target.value)} />
              <button className="session-action-btn" onClick={() => setEditCookie({ name: '', value: '', domain: '', path: '/' })}><Plus size={9} /> Add</button>
              <button className="session-action-btn" onClick={exportCookies}><Download size={9} /> Export</button>
              <button className="session-action-btn" onClick={importCookies}><Upload size={9} /> Import</button>
              <button className="session-action-btn danger" onClick={clearAllCookies}><Trash2 size={9} /> Clear All</button>
              <button className="session-action-btn" onClick={loadCookies}><RefreshCcw size={9} /></button>
              <span
                className={`session-browser-sync ${browserSyncLive ? 'live' : 'idle'}`}
                title={browserSyncLive
                  ? 'WonderBrowser is open — every cookie edit is pushed via CDP Network.setCookie.'
                  : 'No active WonderBrowser CDP session. Open a browser to enable live-sync.'}
              >
                {browserSyncLive
                  ? <><Link2 size={10} /> Live-sync to browser</>
                  : <><Link2Off size={10} /> Jar-only (no browser)</>}
              </span>
            </div>

            {editCookie && (
              <div className="session-edit-row">
                <input type="text" placeholder="Name" value={editCookie.name || ''} onChange={e => setEditCookie(p => ({ ...p!, name: e.target.value }))} />
                <input type="text" placeholder="Value" value={editCookie.value || ''} onChange={e => setEditCookie(p => ({ ...p!, value: e.target.value }))} />
                <input type="text" placeholder="Domain" value={editCookie.domain || ''} onChange={e => setEditCookie(p => ({ ...p!, domain: e.target.value }))} />
                <input type="text" placeholder="Path" value={editCookie.path || '/'} onChange={e => setEditCookie(p => ({ ...p!, path: e.target.value }))} />
                <label className="session-check"><input type="checkbox" checked={editCookie.secure || false} onChange={e => setEditCookie(p => ({ ...p!, secure: e.target.checked }))} /> Secure</label>
                <label className="session-check"><input type="checkbox" checked={editCookie.httponly || false} onChange={e => setEditCookie(p => ({ ...p!, httponly: e.target.checked }))} /> HttpOnly</label>
                <button className="session-action-btn accent" onClick={saveCookie}><Check size={9} /> Save</button>
                <button className="session-action-btn" onClick={() => setEditCookie(null)}><X size={9} /></button>
              </div>
            )}

            <div className="session-cookie-table">
              <table>
                <thead>
                  <tr>
                    <th>Name</th><th>Value</th><th>Domain</th><th>Path</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCookies.map((c, i) => (
                    <tr key={i}>
                      <td className="session-cookie-name">{c.name}</td>
                      <td className="session-cookie-value">{c.value}</td>
                      <td>{c.domain}</td>
                      <td className="session-dim">{c.path}</td>
                      <td>{c.secure ? <Check size={10} className="session-green" /> : ''}</td>
                      <td>{c.httponly ? <Check size={10} className="session-green" /> : ''}</td>
                      <td className="session-dim">{c.samesite || '—'}</td>
                      <td><button className="session-row-del" onClick={() => deleteCookie(c.name, c.domain)}><Trash2 size={9} /></button></td>
                    </tr>
                  ))}
                  {filteredCookies.length === 0 && (
                    <tr><td colSpan={8} className="session-empty-td">No cookies in jar</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Macros Tab */}
        {tab === 'macros' && (
          <div className="session-macro-panel">
            <div className="session-macro-sidebar">
              <button className="session-action-btn accent" style={{ width: '100%', justifyContent: 'center' }}
                onClick={() => setEditingMacro({ name: '', description: '', steps: [] })}><Plus size={9} /> New Macro</button>
              {macros.map(m => (
                <div key={m.id} className={`session-macro-item ${selectedMacro === m.id ? 'selected' : ''}`}
                  onClick={() => { setSelectedMacro(m.id); setMacroResult(null); }}>
                  <Zap size={10} />
                  <div className="session-macro-info">
                    <span className="session-macro-name">{m.name}</span>
                    <span className="session-dim">{m.steps.length} step{m.steps.length !== 1 ? 's' : ''}</span>
                  </div>
                  <button className="session-row-del" onClick={e => { e.stopPropagation(); deleteMacro(m.id); }}><Trash2 size={9} /></button>
                </div>
              ))}
            </div>

            <div className="session-macro-detail">
              {editingMacro ? (
                <div className="session-macro-editor">
                  <div className="session-macro-editor-header">
                    <input type="text" className="session-macro-name-input" placeholder="Macro name..."
                      value={editingMacro.name} onChange={e => setEditingMacro(p => p ? { ...p, name: e.target.value } : null)} />
                    <input type="text" className="session-macro-desc-input" placeholder="Description (optional)..."
                      value={editingMacro.description} onChange={e => setEditingMacro(p => p ? { ...p, description: e.target.value } : null)} />
                  </div>
                  <div className="session-macro-steps">
                    <span className="session-section-title">Steps</span>
                    {editingMacro.steps.map((step, i) => (
                      <div key={i} className="session-macro-step">
                        <span className="session-step-num">{i + 1}</span>
                        <select value={step.method} onChange={e => setEditingMacro(p => p ? {
                          ...p, steps: p.steps.map((s, j) => j === i ? { ...s, method: e.target.value } : s),
                        } : null)}>
                          <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option>
                        </select>
                        <input type="text" placeholder="URL..." value={step.url}
                          onChange={e => setEditingMacro(p => p ? {
                            ...p, steps: p.steps.map((s, j) => j === i ? { ...s, url: e.target.value } : s),
                          } : null)} />
                        <button className="session-row-del" onClick={() => setEditingMacro(p => p ? {
                          ...p, steps: p.steps.filter((_, j) => j !== i),
                        } : null)}><Trash2 size={9} /></button>
                      </div>
                    ))}
                    <button className="session-action-btn" onClick={addMacroStep}><Plus size={9} /> Add Step</button>
                  </div>
                  <div className="session-macro-editor-footer">
                    <button className="session-action-btn accent" onClick={createMacro}><Check size={9} /> Save Macro</button>
                    <button className="session-action-btn" onClick={() => setEditingMacro(null)}>Cancel</button>
                  </div>
                </div>
              ) : activeMacro ? (
                <div className="session-macro-view">
                  <div className="session-macro-view-header">
                    <span className="session-macro-view-name">{activeMacro.name}</span>
                    <span className="session-dim">{activeMacro.description}</span>
                    <button className="session-action-btn accent" onClick={() => runMacro(activeMacro.id)}><Play size={9} /> Run</button>
                  </div>
                  <div className="session-macro-steps">
                    <span className="session-section-title">Steps ({activeMacro.steps.length})</span>
                    {activeMacro.steps.map((step, i) => (
                      <div key={i} className="session-macro-step readonly">
                        <span className="session-step-num">{i + 1}</span>
                        <span className="session-step-method">{step.method}</span>
                        <span className="session-step-url">{step.url}</span>
                      </div>
                    ))}
                  </div>
                  {macroResult && (
                    <div className="session-macro-result">
                      <span className="session-section-title">Extracted Values</span>
                      {Object.entries(macroResult).map(([k, v]) => (
                        <div key={k} className="session-extract-row">
                          <span className="session-extract-key">{k}</span>
                          <span className="session-extract-val">{v}</span>
                        </div>
                      ))}
                      {Object.keys(macroResult).length === 0 && <span className="session-dim" style={{ fontSize: 10 }}>No values extracted</span>}
                    </div>
                  )}
                </div>
              ) : (
                <div className="session-macro-empty">
                  <Zap size={24} strokeWidth={1} />
                  <span>Select a macro or create a new one</span>
                  <span className="session-dim">Macros automate multi-step authentication flows</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Rules Tab */}
        {tab === 'rules' && (
          <div className="session-rules-panel">
            <div className="session-rules-header">
              <span className="session-section-title">Session Handling Rules</span>
              <span className="session-dim">Rules control how sessions are maintained across tools</span>
            </div>
            <div className="session-rules-list">
              {rules.map(r => (
                <div key={r.id} className="session-rule-item">
                  <button className="session-rule-toggle" onClick={() => toggleRule(r.id, !r.enabled)}>
                    {r.enabled ? <ToggleRight size={14} className="session-green" /> : <ToggleLeft size={14} />}
                  </button>
                  <div className="session-rule-info">
                    <span className="session-rule-name">{r.name}</span>
                    <span className="session-dim">{r.scope}</span>
                  </div>
                  <button className="session-row-del" onClick={() => deleteRule(r.id)}><Trash2 size={9} /></button>
                </div>
              ))}
              {rules.length === 0 && (
                <div className="session-macro-empty" style={{ padding: 20 }}>
                  <ListChecks size={24} strokeWidth={1} />
                  <span>No session rules configured</span>
                  <span className="session-dim">Rules can automatically use cookie jar, add headers, or run macros</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
