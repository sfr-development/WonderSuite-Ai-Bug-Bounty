import { create } from 'zustand';
import type { ModuleId, ReplayTab } from '../types';

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
  },
  clearSendTo: () => set({ pendingSendTo: null }),
  
  globalScope: [],
  addScope: (pattern) => set((s) => ({ globalScope: s.globalScope.includes(pattern) ? s.globalScope : [...s.globalScope, pattern] })),
  removeScope: (pattern) => set((s) => ({ globalScope: s.globalScope.filter((p) => p !== pattern) })),
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
  deleteSitemapNode: (url) => set({ pendingDeleteUrl: url }),
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

export const useReplayStore = create<ReplayState>((set) => ({
  tabs: [defaultTab],
  activeTabId: 'tab-1',
  addTab: (tab) => set((s) => ({ tabs: [...s.tabs, tab], activeTabId: tab.id })),
  removeTab: (id) =>
    set((s) => {
      const tabs = s.tabs.filter((t) => t.id !== id);
      const activeTabId =
        s.activeTabId === id ? (tabs[tabs.length - 1]?.id ?? null) : s.activeTabId;
      return { tabs, activeTabId };
    }),
  setActiveTab: (id) => set({ activeTabId: id }),
  updateTab: (id, updates) =>
    set((s) => ({
      tabs: s.tabs.map((t) => (t.id === id ? { ...t, ...updates } : t)),
    })),
}));
