import { useState, useCallback, useEffect, useRef, Suspense } from 'react';
import { Titlebar } from './Titlebar';
import { Sidebar } from './Sidebar';
import { StatusBar } from './StatusBar';
import { Splash } from './Splash';
import { ProjectLauncher } from './ProjectLauncher';
import { useAppStore } from '../../stores';
import { useDetachedStore } from '../../stores/detachedStore';
import { useProjectStore } from '../../stores/projectStore';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';
import { ContextMenu } from '../shared/ContextMenu';
import { moduleMap, ModuleSkeleton } from './moduleMap';
import './Shell.css';

export function Shell() {
  const [splashDone, setSplashDone] = useState(false);
  const { activeProject, closeProject, setActiveProject } = useProjectStore();
  const { activeModule, appearance, toasts, removeToast } = useAppStore();
  const { detached, syncFromBackend, restoreLayout, onWindowEvent } = useDetachedStore();
  const handleSplashFinish = useCallback(() => setSplashDone(true), []);
  useKeyboardShortcuts();
  // IMPORTANT: this ref MUST be declared before any early returns below so the
  // hook order stays stable across (splash → launcher → main) transitions.
  // Otherwise React crashes after the user opens a project (blank screen).
  const visitedRef = useRef<Set<string>>(new Set());
  if (activeProject && !visitedRef.current.has(activeModule)) {
    visitedRef.current.add(activeModule);
  }

  // Bootstrap detached-window state: sync from backend (restart-safe) and
  // restore the persisted layout once a project is open.
  useEffect(() => {
    if (!activeProject) return;
    syncFromBackend();
    restoreLayout();
    const unlistenP = onWindowEvent();
    return () => { unlistenP.then(u => u()); };
  }, [activeProject, syncFromBackend, restoreLayout, onWindowEvent]);

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
                // Detached modules render in their own window. Hide here so we
                // don't double-mount and burn extra state-syncing cycles.
                if (detached.has(modId)) return null;
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
              {detached.has(activeModule) && (
                <div className="shell-detached-placeholder">
                  <div className="shell-detached-placeholder-inner">
                    <div className="shell-detached-placeholder-title">
                      This module is open in a separate window.
                    </div>
                    <div className="shell-detached-placeholder-actions">
                      <button
                        className="shell-detached-btn"
                        onClick={() => useDetachedStore.getState().focus(activeModule)}
                      >
                        Focus window
                      </button>
                      <button
                        className="shell-detached-btn accent"
                        onClick={() => useDetachedStore.getState().redock(activeModule)}
                      >
                        Re-dock here
                      </button>
                    </div>
                  </div>
                </div>
              )}
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
