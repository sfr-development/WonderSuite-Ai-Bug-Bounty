import { useState, useEffect, useCallback } from 'react';
import {
  FolderPlus, FolderOpen, Clock, Trash2, ExternalLink, FileText,
  Zap, Shield, Search, Flag, Settings, ChevronRight, ChevronLeft,
  Globe, Lock, Radio, Copy, ArrowRight, AlertCircle, RefreshCw,
} from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import type { ProjectInfo, ProjectType, CreateProjectOpts } from '../../types';
import { useProjectStore } from '../../stores/projectStore';
import './ProjectLauncher.css';

interface Props {
  onOpen: (project: ProjectInfo) => void;
  onTempProject: () => void;
}

const PROJECT_TYPES: { id: ProjectType; label: string; icon: React.ReactNode; desc: string }[] = [
  { id: 'pentest', label: 'Pentest', icon: <Shield size={16} />, desc: 'Authorized security assessment' },
  { id: 'bounty', label: 'Bug Bounty', icon: <Zap size={16} />, desc: 'Bug bounty target testing' },
  { id: 'research', label: 'Research', icon: <Search size={16} />, desc: 'Security research & analysis' },
  { id: 'ctf', label: 'CTF', icon: <Flag size={16} />, desc: 'Capture the flag challenge' },
  { id: 'custom', label: 'Custom', icon: <Settings size={16} />, desc: 'Custom configuration' },
];

// v0.3.17: per-project folder view. Lists the files inside
// <projectDir> so the user knows what's on disk (config.json,
// traffic.json, ui_state.json, notes.md, ...), can right-click to
// reveal in their OS file manager, and refresh after closing the app.
interface ProjectFileEntry {
  name: string; path: string; size_bytes: number;
  modified_unix: number; kind: string;
}

function ProjectFolderView({ projectId, projectPath }: { projectId: string; projectPath: string }) {
  const [files, setFiles] = useState<ProjectFileEntry[]>([]);
  const [menu, setMenu] = useState<{ x: number; y: number; file: ProjectFileEntry } | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await invoke<ProjectFileEntry[]>('list_project_files', { id: projectId });
      setFiles(list);
    } catch (e) {
      console.warn('list_project_files failed:', e);
      setFiles([]);
    }
    setLoading(false);
  }, [projectId]);

  useEffect(() => { void load(); }, [load]);

  const reveal = async (path: string, select: boolean = true) => {
    try { await invoke('reveal_in_file_manager', { path, select }); }
    catch (e) { console.warn('reveal failed:', e); }
  };

  const fmtSize = (b: number) =>
    b < 1024 ? `${b} B` : b < 1024 * 1024 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1024 / 1024).toFixed(2)} MB`;

  const fmtDate = (u: number) => u ? new Date(u * 1000).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' }) : '—';

  // Close right-click menu on any outside click.
  useEffect(() => {
    if (!menu) return;
    const onClick = () => setMenu(null);
    document.addEventListener('click', onClick, { once: true });
    return () => document.removeEventListener('click', onClick);
  }, [menu]);

  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: 0.6 }}>
          Folder ({files.length} file{files.length === 1 ? '' : 's'})
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          <button
            className="launcher-detail-btn"
            style={{ fontSize: 10, padding: '2px 6px' }}
            onClick={() => reveal(projectPath, false)}
            title="Open the project folder in your file manager"
          >
            <FolderOpen size={11} /> Open Folder
          </button>
          <button
            className="launcher-detail-btn"
            style={{ fontSize: 10, padding: '2px 6px' }}
            onClick={() => void load()}
            disabled={loading}
            aria-label="Refresh file list"
          >
            <RefreshCw size={11} />
          </button>
        </div>
      </div>
      <div style={{ border: '1px solid var(--border-0)', borderRadius: 6, maxHeight: 200, overflowY: 'auto' }}>
        {files.length === 0 ? (
          <div style={{ padding: 12, textAlign: 'center', color: 'var(--text-3)', fontSize: 10 }}>
            {loading ? 'Loading…' : 'No files yet — the project directory is fresh.'}
          </div>
        ) : files.map(f => (
          <div
            key={f.path}
            onContextMenu={(e) => { e.preventDefault(); setMenu({ x: e.clientX, y: e.clientY, file: f }); }}
            onDoubleClick={() => reveal(f.path, true)}
            style={{
              display: 'grid',
              gridTemplateColumns: '70px 1fr 70px 100px',
              gap: 6,
              padding: '4px 8px',
              borderBottom: '1px solid var(--border-0)',
              fontSize: 10,
              cursor: 'context-menu',
              alignItems: 'center',
            }}
            title={f.path}
          >
            <span style={{ color: 'var(--text-3)', textTransform: 'uppercase', fontSize: 8 }}>{f.kind}</span>
            <span style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.name}</span>
            <span style={{ color: 'var(--text-3)', textAlign: 'right' }}>{fmtSize(f.size_bytes)}</span>
            <span style={{ color: 'var(--text-3)' }}>{fmtDate(f.modified_unix)}</span>
          </div>
        ))}
      </div>

      {menu && (
        <div
          style={{
            position: 'fixed', left: menu.x, top: menu.y, zIndex: 1000,
            background: 'var(--bg-1)', border: '1px solid var(--border-0)',
            borderRadius: 6, minWidth: 200, padding: 4,
            boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            className="launcher-detail-btn"
            style={{ width: '100%', justifyContent: 'flex-start', fontSize: 11, marginBottom: 2 }}
            onClick={() => { void reveal(menu.file.path, true); setMenu(null); }}
          >
            <FolderOpen size={11} /> Show in file manager
          </button>
          <button
            className="launcher-detail-btn"
            style={{ width: '100%', justifyContent: 'flex-start', fontSize: 11, marginBottom: 2 }}
            onClick={() => { void reveal(projectPath, false); setMenu(null); }}
          >
            <FolderOpen size={11} /> Open project folder
          </button>
          <button
            className="launcher-detail-btn"
            style={{ width: '100%', justifyContent: 'flex-start', fontSize: 11 }}
            onClick={() => {
              navigator.clipboard.writeText(menu.file.path).catch(() => {});
              setMenu(null);
            }}
          >
            <Copy size={11} /> Copy path
          </button>
        </div>
      )}
    </div>
  );
}

export function ProjectLauncher({ onOpen, onTempProject }: Props) {
  // v0.3.15: single source of truth for the project list. Previously the
  // launcher mirrored projects into local state and called invoke() directly,
  // which meant the rest of the app (which reads useProjectStore.projects)
  // saw a stale list until the next refresh.
  const projects = useProjectStore(s => s.projects);
  const loadProjects = useProjectStore(s => s.loadProjects);
  const createProjectInStore = useProjectStore(s => s.createProject);
  const deleteProjectInStore = useProjectStore(s => s.deleteProject);
  const duplicateProjectInStore = useProjectStore(s => s.duplicateProject);

  const [selected, setSelected] = useState<ProjectInfo | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [maxVisitedStep, setMaxVisitedStep] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');

  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newTarget, setNewTarget] = useState('');
  const [projectType, setProjectType] = useState<ProjectType>('pentest');
  const [isTemporary, setIsTemporary] = useState(false);
  const [tempTtl, setTempTtl] = useState<number>(4);
  const [clientName, setClientName] = useState('');
  const [tags, setTags] = useState('');
  const [proxyPort, setProxyPort] = useState(8080);
  const [autoStartProxy, setAutoStartProxy] = useState(false);
  const [autoLaunchBrowser, setAutoLaunchBrowser] = useState(false);
  const [interceptEnabled, setInterceptEnabled] = useState(false);
  const [scopeEntries, setScopeEntries] = useState<string[]>([]);
  const [newScopeEntry, setNewScopeEntry] = useState('');
  const [maxTraffic, setMaxTraffic] = useState(10000);
  const [appVersion, setAppVersion] = useState<string>('');

  useEffect(() => {
    void loadProjects();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Seed selection from the store once projects are loaded.
  useEffect(() => {
    if (!selected && projects.length > 0) setSelected(projects[0]);
  }, [projects, selected]);

  useEffect(() => {
    invoke<string>('current_version').then(setAppVersion).catch(() => {});
  }, []);

  useEffect(() => {
    if (newTarget) {
      try {
        const url = new URL(newTarget);
        const host = url.hostname;
        setScopeEntries([host, `*.${host}`]);
      } catch { /* invalid URL, keep current scope */ }
    }
  }, [newTarget]);

  const resetWizard = () => {
    setWizardStep(0);
    setMaxVisitedStep(0);
    setNewName(''); setNewDesc(''); setNewTarget('');
    setProjectType('pentest'); setIsTemporary(false); setTempTtl(4);
    setClientName(''); setTags('');
    setProxyPort(8080); setAutoStartProxy(false); setAutoLaunchBrowser(false);
    setInterceptEnabled(false); setScopeEntries([]); setNewScopeEntry('');
    setMaxTraffic(10000);
  };

  // ── Wizard input validation ─────────────────────────────────────────────
  // Used both to render inline errors and to gate Next / Create.
  const nameError = (() => {
    const trimmed = newName.trim();
    if (!trimmed) return 'Name is required';
    if (trimmed.length > 80) return 'Name must be 80 chars or fewer';
    return null;
  })();

  const targetError = (() => {
    if (!newTarget.trim()) return null; // optional
    try {
      const u = new URL(newTarget);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return 'Use http:// or https://';
      }
      return null;
    } catch {
      return 'Invalid URL';
    }
  })();

  const proxyPortError = (() => {
    if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
      return 'Port must be 1–65535';
    }
    return null;
  })();

  const maxTrafficError = (() => {
    if (!Number.isInteger(maxTraffic) || maxTraffic < 0) {
      return 'Must be 0 or positive';
    }
    return null;
  })();

  const step0Valid = !nameError && !targetError;
  const step1Valid = !proxyPortError;
  const step2Valid = !maxTrafficError;
  const allValid = step0Valid && step1Valid && step2Valid;

  const goToStep = (n: number) => {
    if (n <= maxVisitedStep) setWizardStep(n);
  };
  const advanceStep = () => {
    const next = wizardStep + 1;
    setWizardStep(next);
    if (next > maxVisitedStep) setMaxVisitedStep(next);
  };

  const handleCreate = async () => {
    if (!allValid) return;
    const opts: CreateProjectOpts = {
      name: newName.trim(),
      description: newDesc,
      target_url: newTarget,
      project_type: projectType,
      is_temporary: isTemporary,
      temp_ttl_hours: isTemporary ? tempTtl : undefined,
      proxy_port: proxyPort,
      auto_start_proxy: autoStartProxy,
      auto_launch_browser: autoLaunchBrowser,
      initial_scope: scopeEntries,
      intercept_enabled: interceptEnabled,
      client_name: clientName,
      tags: tags.split(',').map(t => t.trim()).filter(Boolean),
      max_traffic_entries: maxTraffic,
      notes_template: '',
    };
    try {
      const project = await createProjectInStore(opts);
      setShowCreate(false);
      resetWizard();
      onOpen(project);
    } catch (e) {
      console.error('Create failed:', e);
    }
  };

  // Just hand the selected project up — Shell goes through
  // projectStore.openProject() which loads config, applies auto-settings, etc.
  const handleOpen = useCallback(() => {
    if (!selected) return;
    onOpen(selected);
  }, [selected, onOpen]);

  const handleDelete = async () => {
    if (!selected) return;
    try {
      await deleteProjectInStore(selected.id);
      setSelected(null);
    } catch (e) {
      console.error('Delete failed:', e);
    }
  };

  const handleDuplicate = async () => {
    if (!selected) return;
    try {
      await duplicateProjectInStore(selected.id);
    } catch (e) {
      console.error('Duplicate failed:', e);
    }
  };

  const addScopeEntry = () => {
    if (newScopeEntry.trim() && !scopeEntries.includes(newScopeEntry.trim())) {
      setScopeEntries([...scopeEntries, newScopeEntry.trim()]);
      setNewScopeEntry('');
    }
  };

  const removeScopeEntry = (entry: string) => {
    setScopeEntries(scopeEntries.filter(e => e !== entry));
  };

  const formatDate = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' })
        + ' ' + d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    } catch { return iso; }
  };

  const getTypeBadgeClass = (type: string) => {
    switch (type) {
      case 'pentest': return 'badge-pentest';
      case 'bounty': return 'badge-bounty';
      case 'research': return 'badge-research';
      case 'ctf': return 'badge-ctf';
      default: return 'badge-custom';
    }
  };

  const filteredProjects = projects.filter(p =>
    !searchQuery || p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    p.target_url?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="launcher">
      <div className="titlebar" data-tauri-drag-region>
        <div className="titlebar-drag" data-tauri-drag-region>
          <span className="titlebar-title">WonderSuite – Project Launcher</span>
        </div>
      </div>

      <div className="launcher-body">
        <div className="launcher-sidebar">
          <div className="launcher-brand">
            <img src="/wondersuite_logo.png" alt="WonderSuite" style={{ width: 140, height: 'auto', objectFit: 'contain' }} className="launcher-brand-icon" />
            <span style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 4 }}>{appVersion ? `v${appVersion}` : ''} – Security Platform</span>
          </div>

          <div className="launcher-actions">
            <button className="launcher-action-btn primary" onClick={() => { resetWizard(); setShowCreate(true); }}>
              <FolderPlus size={14} /> New Project
            </button>
            <button className="launcher-action-btn" onClick={onTempProject}>
              <Zap size={14} /> Quick Session
            </button>
          </div>

          <div className="launcher-search">
            <input
              className="launcher-search-input"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search projects…"
            />
          </div>

          <div className="launcher-section-title">Recent Projects</div>
          <div className="launcher-projects">
            {filteredProjects.length === 0 && (
              <div style={{ fontSize: 11, color: 'var(--text-3)', padding: '8px 0' }}>No projects yet</div>
            )}
            {filteredProjects.map((p) => (
              <button
                key={p.id}
                className={`launcher-project ${selected?.id === p.id ? 'active' : ''}`}
                onClick={() => setSelected(p)}
                onDoubleClick={() => { setSelected(p); handleOpen(); }}
              >
                <div className="launcher-project-icon">
                  <FolderOpen size={14} />
                </div>
                <div className="launcher-project-info">
                  <div className="launcher-project-name">
                    {p.name}
                    {p.project_type && (
                      <span className={`launcher-type-badge ${getTypeBadgeClass(p.project_type)}`}>
                        {p.project_type}
                      </span>
                    )}
                    {p.is_temporary && (
                      <span className="launcher-temp-badge">TEMP</span>
                    )}
                  </div>
                  <div className="launcher-project-meta">{formatDate(p.last_opened)}</div>
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className={`launcher-main ${selected ? 'has-project' : ''}`}>
          {!selected ? (
            <div className="launcher-empty">
              <FileText size={48} className="launcher-empty-icon" />
              <h2>No Project Selected</h2>
              <p>Create a new project or select an existing one to get started with your security testing.</p>
            </div>
          ) : (
            <div className="launcher-detail">
              <div className="launcher-detail-header">
                <h2>{selected.name}</h2>
                {selected.project_type && (
                  <span className={`launcher-type-badge ${getTypeBadgeClass(selected.project_type)}`} style={{ marginLeft: 8 }}>
                    {selected.project_type}
                  </span>
                )}
                <p>{selected.description || 'No description'}</p>
              </div>
              <div className="launcher-detail-body">
                <div className="launcher-stat-row">
                  <div className="launcher-stat">
                    <div className="launcher-stat-value">{selected.request_count}</div>
                    <div className="launcher-stat-label">Requests</div>
                  </div>
                  <div className="launcher-stat">
                    <div className="launcher-stat-value">{selected.finding_count}</div>
                    <div className="launcher-stat-label">Findings</div>
                  </div>
                </div>

                <div className="launcher-stat-row">
                  <div className="launcher-stat">
                    <div className="launcher-stat-label" style={{ marginTop: 0 }}>Target</div>
                    <div style={{ fontSize: 12, color: 'var(--text-0)', fontFamily: 'monospace', marginTop: 4 }}>
                      {selected.target_url || '—'}
                    </div>
                  </div>
                </div>

                {selected.tags && selected.tags.length > 0 && (
                  <div className="launcher-stat-row">
                    <div className="launcher-stat">
                      <div className="launcher-stat-label" style={{ marginTop: 0 }}>Tags</div>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                        {selected.tags.map(t => (
                          <span key={t} className="launcher-tag">{t}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                <div className="launcher-stat-row">
                  <div className="launcher-stat">
                    <div className="launcher-stat-label" style={{ marginTop: 0 }}>Created</div>
                    <div style={{ fontSize: 11, color: 'var(--text-1)', marginTop: 4 }}>{formatDate(selected.created_at)}</div>
                  </div>
                  <div className="launcher-stat">
                    <div className="launcher-stat-label" style={{ marginTop: 0 }}>Last Opened</div>
                    <div style={{ fontSize: 11, color: 'var(--text-1)', marginTop: 4 }}>{formatDate(selected.last_opened)}</div>
                  </div>
                </div>

                {!selected.is_temporary && selected.path && (
                  <ProjectFolderView projectId={selected.id} projectPath={selected.path} />
                )}

                <div className="launcher-detail-actions">
                  <button className="launcher-detail-btn open" onClick={handleOpen}>
                    <ExternalLink size={13} /> Open Project
                  </button>
                  <button className="launcher-detail-btn" onClick={handleDuplicate} title="Duplicate project">
                    <Copy size={13} /> Duplicate
                  </button>
                  <button className="launcher-detail-btn danger" onClick={handleDelete}>
                    <Trash2 size={13} /> Delete
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Create Project Wizard ── */}
      {showCreate && (
        <div className="launcher-dialog-overlay" onClick={() => setShowCreate(false)}>
          <div className="launcher-dialog wizard-dialog" onClick={(e) => e.stopPropagation()}>
            {/* Wizard Header */}
            <div className="wizard-header">
              <h3>Create New Project</h3>
              <div className="wizard-steps">
                {['Basics', 'Proxy & Scope', 'Limits'].map((label, i) => {
                  const reachable = i <= maxVisitedStep;
                  return (
                    <button
                      key={label}
                      type="button"
                      disabled={!reachable}
                      onClick={() => goToStep(i)}
                      className={`wizard-step-indicator ${wizardStep === i ? 'active' : ''} ${wizardStep > i ? 'done' : ''}`}
                      style={{
                        background: 'transparent', border: 'none', padding: 0,
                        cursor: reachable ? 'pointer' : 'default',
                        opacity: reachable ? 1 : 0.5,
                      }}
                    >
                      <span className="wizard-step-num">{i + 1}</span>
                      <span className="wizard-step-label">{label}</span>
                      {i < 2 && <ArrowRight size={12} className="wizard-step-arrow" />}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Step 1: Basics */}
            {wizardStep === 0 && (
              <div className="wizard-body">
                <div className="launcher-form-group">
                  <label className="launcher-form-label">Project Name *</label>
                  <input
                    className="launcher-form-input"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="My Target Pentest"
                    autoFocus
                    aria-invalid={!!nameError && newName.length > 0}
                  />
                  {nameError && newName.length > 0 && (
                    <div className="wizard-field-error"><AlertCircle size={11} /> {nameError}</div>
                  )}
                </div>
                <div className="launcher-form-group">
                  <label className="launcher-form-label">Target URL</label>
                  <input
                    className="launcher-form-input"
                    value={newTarget}
                    onChange={(e) => setNewTarget(e.target.value)}
                    placeholder="https://example.com"
                    aria-invalid={!!targetError}
                  />
                  {targetError && (
                    <div className="wizard-field-error"><AlertCircle size={11} /> {targetError}</div>
                  )}
                </div>
                <div className="launcher-form-group">
                  <label className="launcher-form-label">Description</label>
                  <textarea className="launcher-form-textarea" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="Bug bounty scope, engagement notes..." />
                </div>

                <div className="launcher-form-group">
                  <label className="launcher-form-label">Project Type</label>
                  <div className="wizard-type-grid">
                    {PROJECT_TYPES.map(t => (
                      <button
                        key={t.id}
                        className={`wizard-type-card ${projectType === t.id ? 'selected' : ''}`}
                        onClick={() => setProjectType(t.id)}
                      >
                        <div className="wizard-type-icon">{t.icon}</div>
                        <div className="wizard-type-label">{t.label}</div>
                        <div className="wizard-type-desc">{t.desc}</div>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="launcher-form-group">
                  <label className="wizard-checkbox">
                    <input type="checkbox" checked={isTemporary} onChange={(e) => setIsTemporary(e.target.checked)} />
                    <Clock size={13} />
                    <span>Temporary Project (auto-cleanup)</span>
                  </label>
                  {isTemporary && (
                    <div className="wizard-sub-option">
                      <label className="launcher-form-label" style={{ fontSize: 11 }}>Auto-delete after</label>
                      <select className="launcher-form-input" value={tempTtl} onChange={(e) => setTempTtl(Number(e.target.value))} style={{ width: 160 }}>
                        <option value={1}>1 hour</option>
                        <option value={4}>4 hours</option>
                        <option value={8}>8 hours</option>
                        <option value={24}>24 hours</option>
                      </select>
                    </div>
                  )}
                </div>

                <div className="launcher-form-group">
                  <label className="launcher-form-label">Client / Organization</label>
                  <input className="launcher-form-input" value={clientName} onChange={(e) => setClientName(e.target.value)} placeholder="Optional" />
                </div>
                <div className="launcher-form-group">
                  <label className="launcher-form-label">Tags (comma-separated)</label>
                  <input className="launcher-form-input" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="webapp, api, mobile" />
                </div>
              </div>
            )}

            {/* Step 2: Proxy & Scope */}
            {wizardStep === 1 && (
              <div className="wizard-body">
                <div className="launcher-form-group">
                  <label className="launcher-form-label">Proxy Port</label>
                  <input
                    className="launcher-form-input"
                    type="number"
                    min={1}
                    max={65535}
                    value={proxyPort}
                    onChange={(e) => setProxyPort(Number(e.target.value))}
                    style={{ width: 120 }}
                    aria-invalid={!!proxyPortError}
                  />
                  {proxyPortError && (
                    <div className="wizard-field-error"><AlertCircle size={11} /> {proxyPortError}</div>
                  )}
                </div>

                <div className="launcher-form-group wizard-checkbox-group">
                  <label className="wizard-checkbox">
                    <input type="checkbox" checked={autoStartProxy} onChange={(e) => setAutoStartProxy(e.target.checked)} />
                    <Radio size={13} />
                    <span>Auto-start proxy when project opens</span>
                  </label>
                  <label className="wizard-checkbox">
                    <input type="checkbox" checked={autoLaunchBrowser} onChange={(e) => setAutoLaunchBrowser(e.target.checked)} />
                    <Globe size={13} />
                    <span>Auto-launch browser</span>
                  </label>
                  <label className="wizard-checkbox">
                    <input type="checkbox" checked={interceptEnabled} onChange={(e) => setInterceptEnabled(e.target.checked)} />
                    <Lock size={13} />
                    <span>Enable intercept by default</span>
                  </label>
                </div>

                <div className="launcher-form-group">
                  <label className="launcher-form-label">Target Scope {scopeEntries.length > 0 && `(${scopeEntries.length} entries)`}</label>
                  <div className="wizard-scope-list">
                    {scopeEntries.map(entry => (
                      <div key={entry} className="wizard-scope-entry">
                        <code>{entry}</code>
                        <button className="wizard-scope-remove" onClick={() => removeScopeEntry(entry)}>×</button>
                      </div>
                    ))}
                  </div>
                  <div className="wizard-scope-add">
                    <input
                      className="launcher-form-input"
                      value={newScopeEntry}
                      onChange={(e) => setNewScopeEntry(e.target.value)}
                      placeholder="*.example.com"
                      onKeyDown={(e) => e.key === 'Enter' && addScopeEntry()}
                    />
                    <button className="wizard-scope-add-btn" onClick={addScopeEntry}>+ Add</button>
                  </div>
                </div>
              </div>
            )}

            {/* Step 3: Limits */}
            {wizardStep === 2 && (
              <div className="wizard-body">
                <div className="launcher-form-group">
                  <label className="launcher-form-label">Max Traffic Entries</label>
                  <input
                    className="launcher-form-input"
                    type="number"
                    min={0}
                    value={maxTraffic}
                    onChange={(e) => setMaxTraffic(Number(e.target.value))}
                    style={{ width: 160 }}
                    aria-invalid={!!maxTrafficError}
                  />
                  <span className="wizard-hint">Oldest entries are evicted when limit is reached. 0 = unlimited.</span>
                  {maxTrafficError && (
                    <div className="wizard-field-error"><AlertCircle size={11} /> {maxTrafficError}</div>
                  )}
                </div>

                <div className="wizard-summary">
                  <h4>Project Summary</h4>
                  <div className="wizard-summary-grid">
                    <div className="wizard-summary-item"><span>Name</span><strong>{newName || '—'}</strong></div>
                    <div className="wizard-summary-item"><span>Type</span><strong>{projectType}</strong></div>
                    <div className="wizard-summary-item"><span>Target</span><strong style={{ fontFamily: 'monospace' }}>{newTarget || '—'}</strong></div>
                    <div className="wizard-summary-item"><span>Proxy</span><strong>:{proxyPort}</strong></div>
                    <div className="wizard-summary-item"><span>Temporary</span><strong>{isTemporary ? `Yes (${tempTtl}h)` : 'No'}</strong></div>
                    <div className="wizard-summary-item"><span>Scope</span><strong>{scopeEntries.length} entries</strong></div>
                    <div className="wizard-summary-item"><span>Traffic Limit</span><strong>{maxTraffic === 0 ? 'Unlimited' : maxTraffic.toLocaleString()}</strong></div>
                    {autoStartProxy && <div className="wizard-summary-item"><span>Auto-Proxy</span><strong>Yes</strong></div>}
                    {autoLaunchBrowser && <div className="wizard-summary-item"><span>Auto-Browser</span><strong>Yes</strong></div>}
                    {interceptEnabled && <div className="wizard-summary-item"><span>Intercept</span><strong>Enabled</strong></div>}
                  </div>
                </div>
              </div>
            )}

            {/* Wizard Navigation */}
            <div className="launcher-dialog-actions">
              <button className="launcher-detail-btn" onClick={() => setShowCreate(false)}>Cancel</button>
              <div style={{ flex: 1 }} />
              {wizardStep > 0 && (
                <button className="launcher-detail-btn" onClick={() => setWizardStep(s => s - 1)}>
                  <ChevronLeft size={13} /> Back
                </button>
              )}
              {wizardStep < 2 ? (
                <button
                  className="launcher-detail-btn open"
                  onClick={advanceStep}
                  disabled={(wizardStep === 0 && !step0Valid) || (wizardStep === 1 && !step1Valid)}
                >
                  Next <ChevronRight size={13} />
                </button>
              ) : (
                <button
                  className="launcher-detail-btn open"
                  onClick={handleCreate}
                  disabled={!allValid}
                >
                  <FolderPlus size={13} /> Create Project
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
