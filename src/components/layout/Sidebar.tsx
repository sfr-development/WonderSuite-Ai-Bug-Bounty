import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  Activity,
  Repeat,
  Crosshair,
  Radar,
  Network,
  KeyRound,
  Wrench,
  BookMarked,
  Settings,
  Bot,
  GitCompare,
  FileText,
  Bookmark,
  FileCode2,
  Package,
  Cookie,
  Cable,
  Radio,
  FolderSearch,
  Fingerprint,
  BookText,
  PanelLeftClose,
  PanelLeftOpen,
  ChevronRight,
  ExternalLink,
  Undo2,
} from 'lucide-react';
import { useAppStore } from '../../stores';
import { useDetachedStore } from '../../stores/detachedStore';
import type { ModuleId } from '../../types';
import './Sidebar.css';

interface NavGroup {
  title: string;
  items: { id: ModuleId; icon: typeof LayoutDashboard; label: string; shortcut: string }[];
}

const navGroups: NavGroup[] = [
  {
    title: 'Core',
    items: [
      { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard', shortcut: 'Ctrl+1' },
      { id: 'intercept', icon: ShieldAlert, label: 'Intercept', shortcut: 'Ctrl+2' },
      { id: 'traffic', icon: Activity, label: 'Traffic', shortcut: 'Ctrl+3' },
    ],
  },
  {
    title: 'Testing',
    items: [
      { id: 'replay', icon: Repeat, label: 'Repeater', shortcut: 'Ctrl+4' },
      { id: 'attack', icon: Crosshair, label: 'Intruder', shortcut: 'Ctrl+5' },
      { id: 'scan', icon: Radar, label: 'Scanner', shortcut: 'Ctrl+6' },
      { id: 'websocket', icon: Cable, label: 'WebSocket', shortcut: '' },
      { id: 'oast', icon: Radio, label: 'OAST', shortcut: '' },
    ],
  },
  {
    title: 'Recon',
    items: [
      { id: 'sitemap', icon: Network, label: 'Sitemap', shortcut: 'Ctrl+7' },
      { id: 'discovery', icon: FolderSearch, label: 'Discovery', shortcut: '' },
      { id: 'osint', icon: Fingerprint, label: 'OSINT', shortcut: '' },
    ],
  },
  {
    title: 'Analysis',
    items: [
      { id: 'tokens', icon: KeyRound, label: 'Sequencer', shortcut: 'Ctrl+8' },
      { id: 'comparer', icon: GitCompare, label: 'Comparer', shortcut: '' },
      { id: 'logger', icon: FileText, label: 'Logger', shortcut: '' },
      { id: 'templates', icon: FileCode2, label: 'Templates', shortcut: '' },
      { id: 'payloads', icon: Package, label: 'Payloads', shortcut: '' },
    ],
  },
  {
    title: 'Workflow',
    items: [
      { id: 'organizer', icon: Bookmark, label: 'Organizer', shortcut: '' },
      { id: 'session', icon: Cookie, label: 'Session', shortcut: '' },
      { id: 'agent', icon: Bot, label: 'Agent', shortcut: '' },
      { id: 'tools', icon: Wrench, label: 'Tools', shortcut: 'Ctrl+9' },
      { id: 'findings', icon: BookMarked, label: 'Findings', shortcut: 'Ctrl+0' },
    ],
  },
];

export function Sidebar() {
  const { activeModule, setActiveModule } = useAppStore();
  const { detached, detach, redock, focus } = useDetachedStore();
  const [expanded, setExpanded] = useState(false);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [popMenu, setPopMenu] = useState<{ x: number; y: number; moduleId: ModuleId } | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);

  const toggleGroup = (title: string) => {
    setCollapsedGroups(prev => {
      const next = new Set(prev);
      if (next.has(title)) next.delete(title);
      else next.add(title);
      return next;
    });
  };

  const activeGroup = navGroups.find(g => g.items.some(i => i.id === activeModule));

  const handleItemClick = (id: ModuleId) => {
    if (detached.has(id)) {
      focus(id);
      return;
    }
    setActiveModule(id);
  };

  const handleContextMenu = (e: React.MouseEvent, id: ModuleId) => {
    e.preventDefault();
    setPopMenu({ x: e.clientX, y: e.clientY, moduleId: id });
  };

  useEffect(() => {
    if (!popMenu) return;
    const close = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setPopMenu(null);
      }
    };
    const closeOnEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') setPopMenu(null); };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', closeOnEsc);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', closeOnEsc);
    };
  }, [popMenu]);

  return (
    <aside className={`sidebar ${expanded ? 'expanded' : ''}`}>
      {/* Logo + toggle */}
      <div className="sidebar-header">
        <div className="sidebar-logo">
          {expanded && (
            <img
              src="/wondersuite_logo.png"
              alt="WonderSuite"
              className="sidebar-logo-img"
            />
          )}
        </div>
        <button className="sidebar-toggle" onClick={() => setExpanded(!expanded)} title={expanded ? 'Collapse sidebar' : 'Expand sidebar'}>
          {expanded ? <PanelLeftClose size={14} /> : <PanelLeftOpen size={14} />}
        </button>
      </div>

      {/* Scrollable navigation */}
      <nav className="sidebar-nav">
        {navGroups.map((group) => {
          const isCollapsed = collapsedGroups.has(group.title);
          const hasActiveItem = activeGroup?.title === group.title;

          return (
            <div key={group.title} className="sidebar-group">
              {expanded && (
                <button
                  className={`sidebar-group-title ${isCollapsed ? 'collapsed' : ''} ${hasActiveItem ? 'has-active' : ''}`}
                  onClick={() => toggleGroup(group.title)}
                >
                  <ChevronRight size={10} className={`sidebar-group-chevron ${isCollapsed ? '' : 'open'}`} />
                  {group.title}
                  {isCollapsed && hasActiveItem && <span className="sidebar-group-dot" />}
                </button>
              )}
              {(!expanded || !isCollapsed) && group.items.map(({ id, icon: Icon, label, shortcut }) => {
                const isDetached = detached.has(id);
                return (
                  <button
                    key={id}
                    className={`sidebar-item ${activeModule === id ? 'active' : ''} ${isDetached ? 'is-detached' : ''}`}
                    onClick={() => handleItemClick(id)}
                    onContextMenu={(e) => handleContextMenu(e, id)}
                    data-tooltip={!expanded ? `${label}${isDetached ? '  (in window)' : ''}${shortcut ? `  (${shortcut})` : ''}` : undefined}
                    title={expanded ? `${label}${shortcut ? ` (${shortcut})` : ''}` : undefined}
                  >
                    <Icon size={16} strokeWidth={1.8} />
                    {expanded && <span className="sidebar-label">{label}</span>}
                    {expanded && isDetached && <span className="sidebar-detached-pill">window</span>}
                    {expanded && !isDetached && shortcut && <span className="sidebar-shortcut">{shortcut}</span>}
                    {!expanded && isDetached && <span className="sidebar-detached-dot" />}
                  </button>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Docs + Settings at bottom */}
      <div className="sidebar-bottom">
        <button
          className={`sidebar-item ${activeModule === 'docs' ? 'active' : ''} ${detached.has('docs') ? 'is-detached' : ''}`}
          onClick={() => handleItemClick('docs')}
          onContextMenu={(e) => handleContextMenu(e, 'docs')}
          data-tooltip={!expanded ? 'Documentation  (F1)' : undefined}
          title={expanded ? 'Documentation (F1)' : undefined}
        >
          <BookText size={16} strokeWidth={1.8} />
          {expanded && <span className="sidebar-label">Documentation</span>}
          {expanded && detached.has('docs') && <span className="sidebar-detached-pill">window</span>}
          {!expanded && detached.has('docs') && <span className="sidebar-detached-dot" />}
        </button>
        <button
          className={`sidebar-item ${activeModule === 'settings' ? 'active' : ''} ${detached.has('settings') ? 'is-detached' : ''}`}
          onClick={() => handleItemClick('settings')}
          onContextMenu={(e) => handleContextMenu(e, 'settings')}
          data-tooltip={!expanded ? 'Settings' : undefined}
        >
          <Settings size={16} strokeWidth={1.8} />
          {expanded && <span className="sidebar-label">Settings</span>}
          {expanded && detached.has('settings') && <span className="sidebar-detached-pill">window</span>}
          {!expanded && detached.has('settings') && <span className="sidebar-detached-dot" />}
        </button>
      </div>

      {popMenu && createPortal(
        <div
          ref={menuRef}
          className="sidebar-popmenu"
          style={{ top: popMenu.y, left: popMenu.x }}
          role="menu"
        >
          {detached.has(popMenu.moduleId) ? (
            <>
              <button
                className="sidebar-popmenu-item"
                onClick={() => { focus(popMenu.moduleId); setPopMenu(null); }}
              >
                <ExternalLink size={12} />
                <span>Focus window</span>
              </button>
              <button
                className="sidebar-popmenu-item accent"
                onClick={() => { redock(popMenu.moduleId); setPopMenu(null); }}
              >
                <Undo2 size={12} />
                <span>Re-dock here</span>
              </button>
            </>
          ) : (
            <button
              className="sidebar-popmenu-item"
              onClick={() => { detach(popMenu.moduleId); setPopMenu(null); }}
            >
              <ExternalLink size={12} />
              <span>Pop out to window</span>
            </button>
          )}
        </div>,
        document.body
      )}
    </aside>
  );
}
