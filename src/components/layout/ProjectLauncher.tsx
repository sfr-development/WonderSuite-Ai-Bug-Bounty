import { useState, useEffect } from 'react';
import { FolderPlus, FolderOpen, Clock, Trash2, ExternalLink, FileText } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import './ProjectLauncher.css';

interface ProjectInfo {
  id: string;
  name: string;
  path: string;
  created_at: string;
  last_opened: string;
  description: string;
  target_url: string;
  request_count: number;
  finding_count: number;
}

interface Props {
  onOpen: (project: ProjectInfo) => void;
  onTempProject: () => void;
}

export function ProjectLauncher({ onOpen, onTempProject }: Props) {
  const [projects, setProjects] = useState<ProjectInfo[]>([]);
  const [selected, setSelected] = useState<ProjectInfo | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newTarget, setNewTarget] = useState('');

  useEffect(() => {
    loadProjects();
  }, []);

  const loadProjects = async () => {
    try {
      const list = await invoke<ProjectInfo[]>('list_projects');
      setProjects(list);
      if (list.length > 0 && !selected) setSelected(list[0]);
    } catch {
      setProjects([]);
    }
  };

  const handleCreate = async () => {
    if (!newName.trim()) return;
    try {
      const project = await invoke<ProjectInfo>('create_project', {
        name: newName,
        description: newDesc,
        targetUrl: newTarget,
      });
      setShowCreate(false);
      setNewName('');
      setNewDesc('');
      setNewTarget('');
      await loadProjects();
      setSelected(project);
    } catch (e) {
      console.error('Create failed:', e);
    }
  };

  const handleOpen = async () => {
    if (!selected) return;
    try {
      const project = await invoke<ProjectInfo>('open_project', { id: selected.id });
      onOpen(project);
    } catch (e) {
      console.error('Open failed:', e);
    }
  };

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

  const formatDate = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' })
        + ' ' + d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    } catch { return iso; }
  };

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
            <span style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 4 }}>v0.1.0 – Security Platform</span>
          </div>

          <div className="launcher-actions">
            <button className="launcher-action-btn primary" onClick={() => setShowCreate(true)}>
              <FolderPlus size={14} /> New Project
            </button>
            <button className="launcher-action-btn" onClick={onTempProject}>
              <Clock size={14} /> Temporary Project
            </button>
          </div>

          <div className="launcher-section-title">Recent Projects</div>
          <div className="launcher-projects">
            {projects.length === 0 && (
              <div style={{ fontSize: 11, color: 'var(--text-3)', padding: '8px 0' }}>No projects yet</div>
            )}
            {projects.map((p) => (
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
                  <div className="launcher-project-name">{p.name}</div>
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
                  <button className="launcher-detail-btn danger" onClick={handleDelete}>
                    <Trash2 size={13} /> Delete
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {showCreate && (
        <div className="launcher-dialog-overlay" onClick={() => setShowCreate(false)}>
          <div className="launcher-dialog" onClick={(e) => e.stopPropagation()}>
            <h3>New Project</h3>
            <div className="launcher-form-group">
              <label className="launcher-form-label">Project Name</label>
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
            <div className="launcher-dialog-actions">
              <button className="launcher-detail-btn" onClick={() => setShowCreate(false)}>Cancel</button>
              <button className="launcher-detail-btn open" onClick={handleCreate}>Create Project</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
