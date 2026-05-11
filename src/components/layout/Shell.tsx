import { useState, useCallback, useEffect, useRef, lazy, Suspense } from 'react';
import { Titlebar } from './Titlebar';
import { Sidebar } from './Sidebar';
import { StatusBar } from './StatusBar';
import { Splash } from './Splash';
import { ProjectLauncher } from './ProjectLauncher';
import { useAppStore } from '../../stores';
import { useProjectStore } from '../../stores/projectStore';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';
import { ContextMenu } from '../shared/ContextMenu';
import { Loader2 } from 'lucide-react';
import './Shell.css';

const moduleMap: Record<string, React.LazyExoticComponent<React.ComponentType>> = {
  dashboard:  lazy(() => import('../../modules/dashboard/Dashboard').then(m => ({ default: m.Dashboard }))),
  intercept:  lazy(() => import('../../modules/intercept/Intercept').then(m => ({ default: m.Intercept }))),
  traffic:    lazy(() => import('../../modules/traffic/Traffic').then(m => ({ default: m.Traffic }))),
  replay:     lazy(() => import('../../modules/replay/Replay').then(m => ({ default: m.Replay }))),
  attack:     lazy(() => import('../../modules/attack/Attack').then(m => ({ default: m.Attack }))),
  scan:       lazy(() => import('../../modules/scan/Scan').then(m => ({ default: m.Scan }))),
  sitemap:    lazy(() => import('../../modules/sitemap/Sitemap').then(m => ({ default: m.Sitemap }))),
  tokens:     lazy(() => import('../../modules/tokens/Tokens').then(m => ({ default: m.Tokens }))),
  tools:      lazy(() => import('../../modules/tools/Tools').then(m => ({ default: m.Tools }))),
  findings:   lazy(() => import('../../modules/findings/Findings').then(m => ({ default: m.Findings }))),
  comparer:   lazy(() => import('../../modules/comparer/Comparer').then(m => ({ default: m.Comparer }))),
  logger:     lazy(() => import('../../modules/logger/Logger').then(m => ({ default: m.Logger }))),
  organizer:  lazy(() => import('../../modules/organizer/Organizer').then(m => ({ default: m.Organizer }))),
  agent:      lazy(() => import('../../modules/agent/Agent').then(m => ({ default: m.Agent }))),
  templates:  lazy(() => import('../../modules/templates/Templates').then(m => ({ default: m.Templates }))),
  payloads:   lazy(() => import('../../modules/payloads/Payloads').then(m => ({ default: m.Payloads }))),
  session:    lazy(() => import('../../modules/session/Session').then(m => ({ default: m.Session }))),
  websocket:  lazy(() => import('../../modules/websocket/WebSocket').then(m => ({ default: m.WebSocket }))),
  oast:       lazy(() => import('../../modules/oast/Oast').then(m => ({ default: m.Oast }))),
  discovery:  lazy(() => import('../../modules/discovery/Discovery').then(m => ({ default: m.Discovery }))),
  osint:      lazy(() => import('../../modules/osint/Osint').then(m => ({ default: m.Osint }))),
  settings:   lazy(() => import('../../modules/settings/Settings').then(m => ({ default: m.Settings }))),
};

function ModuleSkeleton() {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      flex: 1, color: 'var(--text-3)', gap: 8,
    }}>
      <Loader2 size={18} className="spin-animation" style={{ animation: 'spin 1s linear infinite' }} />
      <span style={{ fontSize: 12 }}>Loading module…</span>
    </div>
  );
}

export function Shell() {
  const [splashDone, setSplashDone] = useState(false);
  const { activeProject, closeProject, setActiveProject } = useProjectStore();
  const { activeModule, appearance, toasts, removeToast } = useAppStore();
  const handleSplashFinish = useCallback(() => setSplashDone(true), []);
  useKeyboardShortcuts();
  // IMPORTANT: this ref MUST be declared before any early returns below so the
  // hook order stays stable across (splash → launcher → main) transitions.
  // Otherwise React crashes after the user opens a project (blank screen).
  const visitedRef = useRef<Set<string>>(new Set());
  if (activeProject && !visitedRef.current.has(activeModule)) {
    visitedRef.current.add(activeModule);
  }

  useEffect(() => {
    const root = document.documentElement;
    root.className = `theme-${appearance.theme} ${appearance.compactMode ? 'compact-mode' : ''}`;
    if (appearance.accentColor) {
      root.style.setProperty('--accent', appearance.accentColor);
      root.style.setProperty('--accent-hover', appearance.accentColor);
      const hex = appearance.accentColor.replace('#', '');
      if (hex.length === 6) {
        const r = parseInt(hex.substring(0, 2), 16);
        const g = parseInt(hex.substring(2, 4), 16);
        const b = parseInt(hex.substring(4, 6), 16);
        root.style.setProperty('--accent-muted', `rgba(${r}, ${g}, ${b}, 0.12)`);
        root.style.setProperty('--accent-border', `rgba(${r}, ${g}, ${b}, 0.3)`);
      }
    }
    if (appearance.uiScale) {
      root.style.setProperty('--ui-scale', (appearance.uiScale / 100).toString());
    }
  }, [appearance]);

  if (!splashDone) {
    return (
      <div className="shell">
        <Splash onFinish={handleSplashFinish} />
      </div>
    );
  }

  if (!activeProject) {
    return (
      <ProjectLauncher
        onOpen={(project) => setActiveProject(project)}
        onTempProject={() => setActiveProject({
          id: `temp-${Date.now()}`,
          name: 'Quick Session',
          path: '',
          created_at: new Date().toISOString(),
          last_opened: new Date().toISOString(),
          description: 'Temporary in-memory session — data will not be saved',
          target_url: '',
          request_count: 0,
          finding_count: 0,
          project_type: 'research',
          is_temporary: true,
          tags: [],
        })}
      />
    );
  }

  const visited = Array.from(visitedRef.current);

  return (
    <div className="shell">
      <Titlebar />
      <div className="shell-body">
        <Sidebar />
        <div className="shell-main">
          <div className="shell-content-container">
            {/* Modules stay mounted once visited (display:none when inactive)
                so timers, polling, and in-flight scans keep running and the
                user does not lose state when switching tabs. Modules are
                still lazy-loaded on first visit so unvisited ones cost nothing. */}
            <div className="shell-content" style={{ display: 'flex' }}>
              {visited.map((modId) => {
                const Mod = moduleMap[modId];
                if (!Mod) return null;
                const isActive = modId === activeModule;
                return (
                  <div
                    key={modId}
                    style={{
                      display: isActive ? 'flex' : 'none',
                      flex: 1,
                      flexDirection: 'column',
                      minHeight: 0,
                      width: '100%',
                    }}
                  >
                    <Suspense fallback={<ModuleSkeleton />}>
                      <Mod />
                    </Suspense>
                  </div>
                );
              })}
            </div>
          </div>
          <StatusBar
            projectName={activeProject?.name}
            isTemporary={activeProject?.is_temporary}
            onCloseProject={closeProject}
          />
          <ContextMenu />
        </div>
      </div>
      
      {/* Toast Container */}
      <div className="shell-toast-container">
        {toasts.map((toast) => (
          <div key={toast.id} className={`shell-toast shell-toast-${toast.type}`}>
            <div className="shell-toast-content">
              {toast.title && <div className="shell-toast-title">{toast.title}</div>}
              {toast.message && <div className="shell-toast-message">{toast.message}</div>}
            </div>
            <button className="shell-toast-close" onClick={() => removeToast(toast.id)}>×</button>
          </div>
        ))}
      </div>
    </div>
  );
}
