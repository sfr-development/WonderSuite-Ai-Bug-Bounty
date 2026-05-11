import { useState } from 'react';
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
  PanelLeftClose,
  PanelLeftOpen,
  ChevronRight,
} from 'lucide-react';
import { useAppStore } from '../../stores';
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
  const [expanded, setExpanded] = useState(false);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());

  const toggleGroup = (title: string) => {
    setCollapsedGroups(prev => {
      const next = new Set(prev);
      if (next.has(title)) next.delete(title);
      else next.add(title);
      return next;
    });
  };

  const activeGroup = navGroups.find(g => g.items.some(i => i.id === activeModule));

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
              {(!expanded || !isCollapsed) && group.items.map(({ id, icon: Icon, label, shortcut }) => (
                <button
                  key={id}
                  className={`sidebar-item ${activeModule === id ? 'active' : ''}`}
                  onClick={() => setActiveModule(id)}
                  data-tooltip={!expanded ? `${label}${shortcut ? `  (${shortcut})` : ''}` : undefined}
                  title={expanded ? `${label}${shortcut ? ` (${shortcut})` : ''}` : undefined}
                >
                  <Icon size={16} strokeWidth={1.8} />
                  {expanded && <span className="sidebar-label">{label}</span>}
                  {expanded && shortcut && <span className="sidebar-shortcut">{shortcut}</span>}
                </button>
              ))}
            </div>
          );
        })}
      </nav>

      {/* Settings at bottom */}
      <div className="sidebar-bottom">
        <button
          className={`sidebar-item ${activeModule === 'settings' ? 'active' : ''}`}
          onClick={() => setActiveModule('settings')}
          data-tooltip={!expanded ? 'Settings' : undefined}
        >
          <Settings size={16} strokeWidth={1.8} />
          {expanded && <span className="sidebar-label">Settings</span>}
        </button>
      </div>
    </aside>
  );
}
