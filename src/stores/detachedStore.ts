import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export interface DetachedLayout {
  x: number;
  y: number;
  width: number;
  height: number;
}

// Geometry cache: remember the last x/y/w/h of every module the user has
// popped out — so the next pop-out spawns at the same spot. NOT a list of
// modules that should auto-spawn on app start.
const LAYOUT_KEY = 'ws_detached_layout_v1';
// Currently-detached set: which modules are popped out RIGHT NOW. This is
// what we use on app boot to decide which windows to re-spawn. Without this
// separation we'd auto-pop every module the user has ever detached, even
// after they re-docked it and closed the app.
const ACTIVE_KEY = 'ws_detached_active_v1';

function loadLayouts(): Record<string, DetachedLayout> {
  try {
    return JSON.parse(localStorage.getItem(LAYOUT_KEY) || '{}');
  } catch { return {}; }
}

function saveLayouts(layouts: Record<string, DetachedLayout>) {
  localStorage.setItem(LAYOUT_KEY, JSON.stringify(layouts));
}

function loadActive(): string[] {
  try { return JSON.parse(localStorage.getItem(ACTIVE_KEY) || '[]'); }
  catch { return []; }
}

function saveActive(active: Set<string>) {
  localStorage.setItem(ACTIVE_KEY, JSON.stringify([...active]));
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
        saveActive(next);
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
      saveActive(next);
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
    // Only re-spawn modules that were actually detached at last app close.
    // Earlier versions re-spawned every module that had a geometry entry,
    // which meant any module the user had ever popped out would re-pop on
    // every app launch — even after they re-docked it.
    const active = loadActive();
    const layouts = get().layouts;
    for (const moduleId of active) {
      if (get().detached.has(moduleId)) continue;
      const geom = layouts[moduleId];
      try {
        await invoke('window_detach_module', {
          moduleId,
          x: geom?.x,
          y: geom?.y,
          width: geom?.width,
          height: geom?.height,
        });
        set((s) => {
          const next = new Set(s.detached);
          next.add(moduleId);
          // (no saveActive — we're already iterating the saved active set)
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
        saveActive(next);
        return { detached: next };
      });
    });
    const unlistenDetach = await listen<string>('window:detached', (e) => {
      const moduleId = e.payload;
      set((s) => {
        const next = new Set(s.detached);
        next.add(moduleId);
        saveActive(next);
        return { detached: next };
      });
    });
    return () => { unlistenRedock(); unlistenDetach(); };
  },
}));
