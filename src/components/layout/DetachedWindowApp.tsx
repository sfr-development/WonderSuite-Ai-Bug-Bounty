import { Suspense, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { Minus, Square, X, Undo2 } from 'lucide-react';
import { moduleMap, moduleLabels, ModuleSkeleton } from './moduleMap';
import { useAppStore } from '../../stores';
import { useDetachedStore } from '../../stores/detachedStore';
import './DetachedWindowApp.css';

interface DetachedWindowAppProps {
  moduleId: string;
}

export function DetachedWindowApp({ moduleId }: DetachedWindowAppProps) {
  const Mod = moduleMap[moduleId];
  const label = moduleLabels[moduleId] || moduleId;
  const [closing, setClosing] = useState(false);
  const { appearance } = useAppStore();

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

  // Persist this window's geometry whenever the user resizes / moves the
  // native frame, so layout-restore on next launch lands at the same spot.
  useEffect(() => {
    const win = getCurrentWindow();
    let mounted = true;

    const persist = async () => {
      try {
        const pos = await win.outerPosition();
        const size = await win.innerSize();
        const scale = await win.scaleFactor();
        if (!mounted) return;
        useDetachedStore.getState().saveGeometry(moduleId, {
          x: pos.x / scale,
          y: pos.y / scale,
          width: size.width / scale,
          height: size.height / scale,
        });
      } catch { /* window already gone */ }
    };

    const unlistenMove = win.onMoved(() => persist());
    const unlistenResize = win.onResized(() => persist());
    persist();

    return () => {
      mounted = false;
      unlistenMove.then(u => u()).catch(() => {});
      unlistenResize.then(u => u()).catch(() => {});
    };
  }, [moduleId]);

  // The main shell can request us to close (re-dock by another path).
  useEffect(() => {
    const p = listen<string>('window:redock-requested', (e) => {
      if (e.payload === moduleId) {
        setClosing(true);
        setTimeout(() => getCurrentWindow().close(), 240);
      }
    });
    return () => { p.then(u => u()).catch(() => {}); };
  }, [moduleId]);

  const handleRedock = async () => {
    setClosing(true);
    setTimeout(async () => {
      try { await invoke('window_redock_module', { moduleId }); }
      catch { await getCurrentWindow().close(); }
    }, 240);
  };

  const win = getCurrentWindow();

  if (!Mod) {
    return (
      <div className="detached-shell">
        <div className="detached-titlebar" data-tauri-drag-region>
          <span className="detached-title">Unknown module: {moduleId}</span>
          <button className="detached-btn close" onClick={() => win.close()}><X size={14} /></button>
        </div>
      </div>
    );
  }

  return (
    <div className={`detached-shell ${closing ? 'redocking' : 'pop-in'}`}>
      <div className="detached-titlebar" data-tauri-drag-region>
        <div className="detached-title-group">
          <img src="/wondersuite_logo.png" alt="WS" className="detached-logo" />
          <span className="detached-title">{label}</span>
          <span className="detached-badge">Detached</span>
        </div>
        <div className="detached-controls">
          <button
            className="detached-btn redock"
            onClick={handleRedock}
            title="Re-dock to main window"
          >
            <Undo2 size={12} />
            <span>Re-dock</span>
          </button>
          <button className="detached-btn" onClick={() => win.minimize()} title="Minimize">
            <Minus size={14} />
          </button>
          <button className="detached-btn" onClick={() => win.toggleMaximize()} title="Maximize">
            <Square size={11} />
          </button>
          <button className="detached-btn close" onClick={handleRedock} title="Close (re-dock)">
            <X size={15} />
          </button>
        </div>
      </div>
      <div className="detached-body">
        <Suspense fallback={<ModuleSkeleton />}>
          <Mod />
        </Suspense>
      </div>
    </div>
  );
}
