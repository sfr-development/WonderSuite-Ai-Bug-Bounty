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
  Cookie,
  Cable,
  Radio,
  FolderSearch,
  Fingerprint,
  PanelLeftClose,
  PanelLeftOpen,
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

  return (
    <aside className={`sidebar ${expanded ? 'expanded' : ''}`}>
      {/* Logo + toggle */}
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <img src="/wondersuite_logo.png" alt="WS" style={{ width: 22, height: 22, objectFit: 'contain' }} />
          {expanded && <span className="sidebar-brand">WonderSuite</span>}
        </div>
        <button className="sidebar-toggle" onClick={() => setExpanded(!expanded)} title={expanded ? 'Collapse sidebar' : 'Expand sidebar'}>
          {expanded ? <PanelLeftClose size={14} /> : <PanelLeftOpen size={14} />}
        </button>
      </div>

      {/* Scrollable navigation */}
      <nav className="sidebar-nav">
        {navGroups.map((group) => (
          <div key={group.title} className="sidebar-group">
            {expanded && <div className="sidebar-group-title">{group.title}</div>}
            {group.items.map(({ id, icon: Icon, label, shortcut }) => (
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
        ))}
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
