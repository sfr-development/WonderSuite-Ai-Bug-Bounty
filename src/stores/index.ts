import { create } from 'zustand';
import type { ModuleId, ReplayTab } from '../types';

interface AppState {
  activeModule: ModuleId;
  setActiveModule: (id: ModuleId) => void;
  // Send to bridge
  pendingSendTo: { tool: string; method: string; url: string; requestRaw: string } | null;
  sendTo: (tool: string, method: string, url: string, requestRaw: string) => void;
  clearSendTo: () => void;
}

export const useAppStore = create<AppState>((set) => ({
  activeModule: 'dashboard',
  setActiveModule: (id) => set({ activeModule: id }),
  pendingSendTo: null,
  sendTo: (tool, method, url, requestRaw) => set({ 
    activeModule: tool === 'repeater' ? 'replay' : tool === 'intruder' ? 'attack' : tool as ModuleId,
    pendingSendTo: { tool, method, url, requestRaw },
  }),
  clearSendTo: () => set({ pendingSendTo: null }),
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
