import { useState, useEffect, useCallback } from 'react';
import {
  FolderPlus, FolderOpen, Clock, Trash2, ExternalLink, FileText,
  Zap, Shield, Search, Flag, Settings, ChevronRight, ChevronLeft,
  Globe, Lock, Radio, Copy, ArrowRight,
} from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import type { ProjectInfo, ProjectType, CreateProjectOpts } from '../../types';
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

export function ProjectLauncher({ onOpen, onTempProject }: Props) {
  const [projects, setProjects] = useState<ProjectInfo[]>([]);
  const [selected, setSelected] = useState<ProjectInfo | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
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

  useEffect(() => { loadProjects(); }, []);

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

  const loadProjects = async () => {
    try {
      const list = await invoke<ProjectInfo[]>('list_projects');
      setProjects(list);
      if (list.length > 0 && !selected) setSelected(list[0]);
    } catch {
      setProjects([]);
    }
  };

  const resetWizard = () => {
    setWizardStep(0);
    setNewName(''); setNewDesc(''); setNewTarget('');
    setProjectType('pentest'); setIsTemporary(false); setTempTtl(4);
    setClientName(''); setTags('');
    setProxyPort(8080); setAutoStartProxy(false); setAutoLaunchBrowser(false);
    setInterceptEnabled(false); setScopeEntries([]); setNewScopeEntry('');
    setMaxTraffic(10000);
  };

  const handleCreate = async () => {
    if (!newName.trim()) return;
    try {
      const opts: CreateProjectOpts = {
        name: newName,
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
      const project = await invoke<ProjectInfo>('create_project', {
        name: opts.name,
        description: opts.description,
        targetUrl: opts.target_url,
        projectType: opts.project_type,
        isTemporary: opts.is_temporary,
        tempTtlHours: opts.temp_ttl_hours ?? null,
        proxyPort: opts.proxy_port,
        autoStartProxy: opts.auto_start_proxy,
        autoLaunchBrowser: opts.auto_launch_browser,
        initialScope: opts.initial_scope,
        interceptEnabled: opts.intercept_enabled,
        clientName: opts.client_name,
        tags: opts.tags,
        maxTrafficEntries: opts.max_traffic_entries,
        notesTemplate: null,
      });
      setShowCreate(false);
      resetWizard();
      await loadProjects();
      onOpen(project);
    } catch (e) {
      console.error('Create failed:', e);
    }
  };

  const handleOpen = useCallback(async () => {
    if (!selected) return;
    try {
      const project = await invoke<ProjectInfo>('open_project', { id: selected.id });
      onOpen(project);
    } catch (e) {
      console.error('Open failed:', e);
    }
  }, [selected, onOpen]);

  const handleDelete = async () => {
    if (!selected) return;
    try {
      await invoke('delete_project', { id: selected.id });
      setSelected(null);
      await loadProjects();
    } catch (e) {
      console.error('Delete failed:', e);
    }
  };

  const handleDuplicate = async () => {
    if (!selected) return;
    try {
      await invoke<ProjectInfo>('duplicate_project', { id: selected.id });
      await loadProjects();
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
          <img src="/wondersuite_logo.png" alt="WS" style={{ width: 16, height: 16, objectFit: 'contain' }} className="titlebar-icon" />
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
                {['Basics', 'Proxy & Scope', 'Limits'].map((label, i) => (
                  <div key={label} className={`wizard-step-indicator ${wizardStep === i ? 'active' : ''} ${wizardStep > i ? 'done' : ''}`}>
                    <span className="wizard-step-num">{i + 1}</span>
                    <span className="wizard-step-label">{label}</span>
                    {i < 2 && <ArrowRight size={12} className="wizard-step-arrow" />}
                  </div>
                ))}
              </div>
            </div>

            {/* Step 1: Basics */}
            {wizardStep === 0 && (
              <div className="wizard-body">
                <div className="launcher-form-group">
                  <label className="launcher-form-label">Project Name *</label>
                  <input className="launcher-form-input" value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="My Target Pentest" autoFocus />
                </div>
                <div className="launcher-form-group">
                  <label className="launcher-form-label">Target URL</label>
                  <input className="launcher-form-input" value={newTarget} onChange={(e) => setNewTarget(e.target.value)} placeholder="https://example.com" />
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
                  <input className="launcher-form-input" type="number" value={proxyPort} onChange={(e) => setProxyPort(Number(e.target.value))} style={{ width: 120 }} />
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
                  <input className="launcher-form-input" type="number" value={maxTraffic} onChange={(e) => setMaxTraffic(Number(e.target.value))} style={{ width: 160 }} />
                  <span className="wizard-hint">Oldest entries are evicted when limit is reached. 0 = unlimited.</span>
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
                <button className="launcher-detail-btn open" onClick={() => setWizardStep(s => s + 1)} disabled={!newName.trim()}>
                  Next <ChevronRight size={13} />
                </button>
              ) : (
                <button className="launcher-detail-btn open" onClick={handleCreate} disabled={!newName.trim()}>
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
