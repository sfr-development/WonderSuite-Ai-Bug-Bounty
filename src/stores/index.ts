import { create } from 'zustand';
import type { ModuleId, ReplayTab } from '../types';
import { broadcastAction, subscribeAction } from './crossWindowSync';

export interface ToastConfig {
  id: string;
  title: string;
  message?: string;
  type: 'success' | 'error' | 'info' | 'warning';
}

interface AppState {
  activeModule: ModuleId;
  setActiveModule: (id: ModuleId) => void;
  pendingSendTo: { tool: string; method: string; url: string; requestRaw: string; responseRaw?: string; target?: 'left' | 'right' } | null;
  sendTo: (tool: string, method: string, url: string, requestRaw: string, responseRaw?: string, target?: 'left' | 'right') => void;
  clearSendTo: () => void;
  globalScope: string[];
  addScope: (pattern: string) => void;
  removeScope: (pattern: string) => void;
  isInScope: (url: string) => boolean;
  contextMenu: { isOpen: boolean; x: number; y: number; data: { method: string; url: string; requestRaw: string; responseRaw?: string; source?: string; onDelete?: () => void } | null };
  openContextMenu: (x: number, y: number, data: { method: string; url: string; requestRaw: string; responseRaw?: string; source?: string; onDelete?: () => void }) => void;
  closeContextMenu: () => void;
  toasts: ToastConfig[];
  addToast: (toast: Omit<ToastConfig, 'id'>) => void;
  removeToast: (id: string) => void;
  appearance: { theme: string; accentColor: string; uiScale: number; compactMode: boolean };
  updateAppearance: (updates: Partial<{ theme: string; accentColor: string; uiScale: number; compactMode: boolean }>) => void;
  pendingDeleteUrl: string | null;
  deleteSitemapNode: (url: string) => void;
  clearDeleteUrl: () => void;
  sitemapBlacklist: Set<string>;
  addToBlacklist: (patterns: string[]) => void;
  removeFromBlacklist: (pattern: string) => void;
  clearBlacklist: () => void;
  isBlacklisted: (url: string) => boolean;
}

export const useAppStore = create<AppState>((set, get) => ({
  activeModule: 'dashboard',
  setActiveModule: (id) => set({ activeModule: id }),
  pendingSendTo: null,
  sendTo: (tool, method, url, requestRaw, responseRaw, target) => {
    const moduleMap: Record<string, ModuleId> = {
      repeater: 'replay', intruder: 'attack', sequencer: 'tokens',
      comparer: 'comparer', organizer: 'organizer', tools: 'tools',
      scan: 'scan', sitemap: 'sitemap', discovery: 'discovery',
    };
    const activeModule = moduleMap[tool] || tool as ModuleId;
    set({ activeModule, pendingSendTo: { tool, method, url, requestRaw, responseRaw, target } });
    void broadcastAction({ kind: 'sendTo', tool, method, url, requestRaw, responseRaw, target });
  },
  clearSendTo: () => set({ pendingSendTo: null }),
  
  // v0.3.10: persisted across launches. Previously the user's in-scope
  // rules vanished on every app close. Backwards-compatible: invalid JSON
  // / first launch falls back to an empty list.
  globalScope: (() => {
    try {
      const raw = localStorage.getItem('ws_global_scope_v1');
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter((s) => typeof s === 'string') : [];
    } catch { return []; }
  })(),
  addScope: (pattern) => set((s) => {
    const next = s.globalScope.includes(pattern) ? s.globalScope : [...s.globalScope, pattern];
    try { localStorage.setItem('ws_global_scope_v1', JSON.stringify(next)); } catch {}
    return { globalScope: next };
  }),
  removeScope: (pattern) => set((s) => {
    const next = s.globalScope.filter((p) => p !== pattern);
    try { localStorage.setItem('ws_global_scope_v1', JSON.stringify(next)); } catch {}
    return { globalScope: next };
  }),
  isInScope: (testUrl) => {
    const scope = get().globalScope;
    if (scope.length === 0) return true; // if no scope defined, everything is in-scope
    try {
      const urlObj = new URL(testUrl);
      return scope.some((p) => {
        if (p.startsWith('*.')) return urlObj.hostname.endsWith(p.slice(2));
        return urlObj.hostname === p || urlObj.href.includes(p);
      });
    } catch {
      return false;
    }
  },

  contextMenu: { isOpen: false, x: 0, y: 0, data: null },
  openContextMenu: (x, y, data) => set({ contextMenu: { isOpen: true, x, y, data } }),
  closeContextMenu: () => set((s) => ({ contextMenu: { ...s.contextMenu, isOpen: false } })),

  toasts: [],
  addToast: (toast) => {
    const id = Math.random().toString(36).substring(2, 9);
    set((s) => ({ toasts: [...s.toasts, { ...toast, id }] }));
    setTimeout(() => get().removeToast(id), 4000);
  },
  removeToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  appearance: JSON.parse(localStorage.getItem('ws_appearance') || '{"theme":"dark","accentColor":"#e8a145","uiScale":100,"compactMode":false}'),
  updateAppearance: (updates) => set((s) => {
    const newApp = { ...s.appearance, ...updates };
    localStorage.setItem('ws_appearance', JSON.stringify(newApp));
    return { appearance: newApp };
  }),

  pendingDeleteUrl: null,
  deleteSitemapNode: (url) => {
    set({ pendingDeleteUrl: url });
    void broadcastAction({ kind: 'deleteSitemapNode', url });
  },
  clearDeleteUrl: () => set({ pendingDeleteUrl: null }),

  sitemapBlacklist: new Set(JSON.parse(localStorage.getItem('ws_sitemap_blacklist') || '[]')),
  addToBlacklist: (patterns) => set((s) => {
    const next = new Set(s.sitemapBlacklist);
    patterns.forEach(p => next.add(p));
    localStorage.setItem('ws_sitemap_blacklist', JSON.stringify([...next]));
    return { sitemapBlacklist: next };
  }),
  removeFromBlacklist: (pattern) => set((s) => {
    const next = new Set(s.sitemapBlacklist);
    next.delete(pattern);
    localStorage.setItem('ws_sitemap_blacklist', JSON.stringify([...next]));
    return { sitemapBlacklist: next };
  }),
  clearBlacklist: () => {
    localStorage.removeItem('ws_sitemap_blacklist');
    set({ sitemapBlacklist: new Set() });
  },
  isBlacklisted: (url) => {
    const bl = get().sitemapBlacklist;
    return [...bl].some(p => {
      if (p.includes('*')) {
        const regex = new RegExp('^' + p.replace(/\*/g, '.*') + '$');
        return regex.test(url);
      }
      return url.includes(p);
    });
  },
}));

// Mirror cross-module actions broadcast from other windows. Applied as a
// local `set` so we do not re-broadcast (would loop).
void subscribeAction((action) => {
  const moduleMap: Record<string, ModuleId> = {
    repeater: 'replay', intruder: 'attack', sequencer: 'tokens',
    comparer: 'comparer', organizer: 'organizer', tools: 'tools',
    scan: 'scan', sitemap: 'sitemap', discovery: 'discovery',
  };
  if (action.kind === 'sendTo') {
    const activeModule = moduleMap[action.tool] || (action.tool as ModuleId);
    useAppStore.setState({
      activeModule,
      pendingSendTo: {
        tool: action.tool,
        method: action.method,
        url: action.url,
        requestRaw: action.requestRaw,
        responseRaw: action.responseRaw,
        target: action.target,
      },
    });
  } else if (action.kind === 'deleteSitemapNode') {
    useAppStore.setState({ pendingDeleteUrl: action.url });
  } else if (action.kind === 'setActiveModule') {
    useAppStore.setState({ activeModule: action.moduleId });
  }
});

interface ReplayState {
  tabs: ReplayTab[];
  activeTabId: string | null;
  addTab: (tab: ReplayTab) => void;
  removeTab: (id: string) => void;
  setActiveTab: (id: string) => void;
  updateTab: (id: string, updates: Partial<ReplayTab>) => void;
}

const defaultTab: ReplayTab = {
  id: 'tab-1',
  name: 'New Request',
  method: 'GET',
  url: 'https://httpbin.org/get',
  requestRaw: 'GET /get HTTP/1.1\nHost: httpbin.org\nAccept: */*\nUser-Agent: WonderSuite/0.1',
  responseRaw: '',
  statusCode: null,
  responseTimeMs: null,
  responseSize: null,
  isLoading: false,
};

// v0.3.10: Repeater tabs persist across launches. Previously a long-running
// Repeater session with N drafted tabs was lost on every restart — high
// friction for chained-engagement testing. We persist tabs + activeTabId
// only; isLoading / responseRaw / response metadata get reset on rehydrate
// because they're transient.
const REPLAY_KEY = 'ws_replay_tabs_v1';

function loadReplay(): { tabs: ReplayTab[]; activeTabId: string | null } {
  try {
    const raw = localStorage.getItem(REPLAY_KEY);
    if (!raw) return { tabs: [defaultTab], activeTabId: 'tab-1' };
    const parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.tabs) || parsed.tabs.length === 0) {
      return { tabs: [defaultTab], activeTabId: 'tab-1' };
    }
    const tabs: ReplayTab[] = parsed.tabs.map((t: any) => ({
      id: String(t.id ?? `tab-${Math.random().toString(36).slice(2, 8)}`),
      name: String(t.name ?? 'Restored Tab'),
      method: String(t.method ?? 'GET'),
      url: String(t.url ?? ''),
      requestRaw: String(t.requestRaw ?? ''),
      responseRaw: '',          // transient
      statusCode: null,         // transient
      responseTimeMs: null,     // transient
      responseSize: null,       // transient
      isLoading: false,         // transient
    }));
    const activeTabId =
      typeof parsed.activeTabId === 'string' && tabs.some((t) => t.id === parsed.activeTabId)
        ? parsed.activeTabId
        : tabs[0].id;
    return { tabs, activeTabId };
  } catch {
    return { tabs: [defaultTab], activeTabId: 'tab-1' };
  }
}

function saveReplay(tabs: ReplayTab[], activeTabId: string | null) {
  try {
    const sanitized = tabs.map((t) => ({
      id: t.id, name: t.name, method: t.method, url: t.url, requestRaw: t.requestRaw,
    }));
    localStorage.setItem(REPLAY_KEY, JSON.stringify({ tabs: sanitized, activeTabId }));
  } catch {}
}

const initialReplay = loadReplay();

export const useReplayStore = create<ReplayState>((set, get) => ({
  tabs: initialReplay.tabs,
  activeTabId: initialReplay.activeTabId,
  addTab: (tab) => set((s) => {
    const next = { tabs: [...s.tabs, tab], activeTabId: tab.id };
    saveReplay(next.tabs, next.activeTabId);
    return next;
  }),
  removeTab: (id) =>
    set((s) => {
      const tabs = s.tabs.filter((t) => t.id !== id);
      const activeTabId =
        s.activeTabId === id ? (tabs[tabs.length - 1]?.id ?? null) : s.activeTabId;
      saveReplay(tabs, activeTabId);
      return { tabs, activeTabId };
    }),
  setActiveTab: (id) => set(() => {
    const s = get();
    saveReplay(s.tabs, id);
    return { activeTabId: id };
  }),
  updateTab: (id, updates) =>
    set((s) => {
      const tabs = s.tabs.map((t) => (t.id === id ? { ...t, ...updates } : t));
      // Don't write to disk on every keystroke or transient response update.
      // We only persist when one of the durable fields changed.
      const updatesNeedSave = ['name', 'method', 'url', 'requestRaw'].some(
        (k) => k in updates,
      );
      if (updatesNeedSave) saveReplay(tabs, s.activeTabId);
      return { tabs };
    }),
}));
