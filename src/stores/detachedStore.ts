import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export interface DetachedLayout {
  x: number;
  y: number;
  width: number;
  height: number;
}

const LAYOUT_KEY = 'ws_detached_layout_v1';

function loadLayouts(): Record<string, DetachedLayout> {
  try {
    return JSON.parse(localStorage.getItem(LAYOUT_KEY) || '{}');
  } catch { return {}; }
}

function saveLayouts(layouts: Record<string, DetachedLayout>) {
  localStorage.setItem(LAYOUT_KEY, JSON.stringify(layouts));
}

interface DetachedState {
  // Set of module ids currently detached.
  detached: Set<string>;
  // Persisted geometry per module (used on app restart to spawn at the same spot).
  layouts: Record<string, DetachedLayout>;

  detach: (moduleId: string) => Promise<void>;
  redock: (moduleId: string) => Promise<void>;
  focus: (moduleId: string) => Promise<void>;
  syncFromBackend: () => Promise<void>;
  restoreLayout: () => Promise<void>;
  saveGeometry: (moduleId: string, layout: DetachedLayout) => void;
  onWindowEvent: () => Promise<UnlistenFn>;
}

export const useDetachedStore = create<DetachedState>((set, get) => ({
  detached: new Set(),
  layouts: loadLayouts(),

  detach: async (moduleId) => {
    if (get().detached.has(moduleId)) {
      await get().focus(moduleId);
      return;
    }
    const layout = get().layouts[moduleId];
    try {
      await invoke<string>('window_detach_module', {
        moduleId,
        x: layout?.x,
        y: layout?.y,
        width: layout?.width,
        height: layout?.height,
      });
      set((s) => {
        const next = new Set(s.detached);
        next.add(moduleId);
        return { detached: next };
      });
    } catch (e) {
      console.error('[detach] failed', moduleId, e);
    }
  },

  redock: async (moduleId) => {
    try {
      await invoke('window_redock_module', { moduleId });
    } catch (e) {
      console.error('[redock] failed', moduleId, e);
    }
    // The window:redocked event will clean up the set; do it here too for snappy UI.
    set((s) => {
      const next = new Set(s.detached);
      next.delete(moduleId);
      return { detached: next };
    });
  },

  focus: async (moduleId) => {
    try { await invoke('window_focus_detached', { moduleId }); }
    catch (e) { console.error('[focus] failed', moduleId, e); }
  },

  syncFromBackend: async () => {
    try {
      const list = await invoke<{ module_id: string }[]>('window_list_detached');
      set({ detached: new Set(list.map((d) => d.module_id)) });
    } catch (e) {
      console.error('[syncFromBackend] failed', e);
    }
  },

  restoreLayout: async () => {
    const layouts = get().layouts;
    for (const [moduleId, geom] of Object.entries(layouts)) {
      if (get().detached.has(moduleId)) continue;
      try {
        await invoke('window_detach_module', {
          moduleId,
          x: geom.x,
          y: geom.y,
          width: geom.width,
          height: geom.height,
        });
        set((s) => {
          const next = new Set(s.detached);
          next.add(moduleId);
          return { detached: next };
        });
      } catch (e) {
        console.warn('[restoreLayout] could not restore', moduleId, e);
      }
    }
  },

  saveGeometry: (moduleId, layout) => {
    set((s) => {
      const layouts = { ...s.layouts, [moduleId]: layout };
      saveLayouts(layouts);
      return { layouts };
    });
  },

  onWindowEvent: async () => {
    const unlistenRedock = await listen<string>('window:redocked', (e) => {
      const moduleId = e.payload;
      set((s) => {
        const next = new Set(s.detached);
        next.delete(moduleId);
        return { detached: next };
      });
    });
    const unlistenDetach = await listen<string>('window:detached', (e) => {
      const moduleId = e.payload;
      set((s) => {
        const next = new Set(s.detached);
        next.add(moduleId);
        return { detached: next };
      });
    });
    return () => { unlistenRedock(); unlistenDetach(); };
  },
}));
