// Global state for the Ports module. Lives outside the React component tree
// so that detaching the module into a separate Tauri window (or just navigating
// away) does NOT lose the running scan or its accumulated results.
//
// Tauri-event listeners are attached once at first store consumption and stay
// alive for the lifetime of the renderer process. The store routes incoming
// events to all React subscribers without re-mounting the listener.

import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { desktopNotify } from '../lib/desktopNotify';

export type ScanMode = 'connect' | 'syn' | 'udp';
export type Timing = 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5' | 'T6';
export type PortStateName = 'open' | 'closed' | 'filtered' | 'openfiltered' | 'open|filtered';

export interface ServiceInfo {
  name: string;
  product?: string;
  version?: string;
  banner?: string;
  tls_cn?: string;
  tls_san?: string[];
  tls?: boolean;
}

export interface ScanResult {
  host: string;
  ip: string;
  port: number;
  proto: string;
  state: PortStateName;
  service?: ServiceInfo;
  rtt_ms: number;
  ts: number;
}

export interface ScanProgress {
  scan_id: string;
  status: string;
  total_probes: number;
  completed: number;
  open_count: number;
  filtered_count: number;
  pps: number;
  rtt_p50_ms: number;
  permits: number;
  elapsed_ms: number;
}

export interface ScanStartReply {
  scan_id: string;
  total_probes: number;
  targets_resolved: number;
  ports_count: number;
}

export interface ScanRequest {
  targets: string[];
  ports: string;
  mode: ScanMode;
  timing: Timing;
  service_detect: boolean;
  probe_intensity: number;
  exclude_cdn: boolean;
  adaptive: boolean;
  idle_mode: boolean;
  max_hosts: number | null;
}

interface ConfigPanelState {
  targetInput: string;
  portsInput: string;
  mode: ScanMode;
  timing: Timing;
  serviceDetect: boolean;
  intensity: number;
  adaptive: boolean;
  idleMode: boolean;
  excludeCdn: boolean;
}

interface PortsState extends ConfigPanelState {
  scanId: string | null;
  startReply: ScanStartReply | null;
  results: ScanResult[];
  progress: ScanProgress | null;
  running: boolean;
  finishedAt: number | null;     // unix ms when scan ended, null while running/idle
  errorMsg: string | null;       // set on portscan:error events
  ppsHistory: { ts: number; pps: number }[];  // for sparkline

  // setters for the form fields
  setTargetInput: (v: string) => void;
  setPortsInput: (v: string) => void;
  setMode: (v: ScanMode) => void;
  setTiming: (v: Timing) => void;
  setServiceDetect: (v: boolean) => void;
  setIntensity: (v: number) => void;
  setAdaptive: (v: boolean) => void;
  setIdleMode: (v: boolean) => void;
  setExcludeCdn: (v: boolean) => void;

  // lifecycle
  start: () => Promise<void>;
  stop: () => Promise<void>;
  reset: () => void;
  exportAs: (format: 'jsonl' | 'csv' | 'xml' | 'gnmap' | 'plain') => Promise<string>;
}

let listenersAttached = false;
let unlistens: UnlistenFn[] = [];

async function attachListeners() {
  if (listenersAttached) return;
  listenersAttached = true;

  unlistens.push(
    await listen<[string, ScanResult]>('portscan:result', (e) => {
      const [sid, r] = e.payload;
      if (sid !== usePortscanStore.getState().scanId) return;
      usePortscanStore.setState((s) => ({ results: [...s.results, r] }));
    }),
  );

  unlistens.push(
    await listen<[string, ScanProgress]>('portscan:progress', (e) => {
      const [sid, p] = e.payload;
      if (sid !== usePortscanStore.getState().scanId) return;
      usePortscanStore.setState((s) => {
        const next = [...s.ppsHistory, { ts: Date.now(), pps: p.pps }];
        // keep last 120 samples (~60s at 500ms tick)
        if (next.length > 120) next.splice(0, next.length - 120);
        return { progress: p, ppsHistory: next };
      });
    }),
  );

  unlistens.push(
    await listen<[string, number]>('portscan:done', (e) => {
      const [sid, elapsedMs] = e.payload;
      if (sid !== usePortscanStore.getState().scanId) return;
      const s = usePortscanStore.getState();
      const open = s.results.filter((r) => r.state === 'open').length;
      usePortscanStore.setState({ running: false, finishedAt: Date.now() });
      void desktopNotify({
        title: 'Port scan complete',
        body: `${open} open · ${s.results.length} probed · ${Math.round(elapsedMs / 100) / 10}s`,
        group: 'portscan',
      });
    }),
  );

  unlistens.push(
    await listen<[string, string]>('portscan:error', (e) => {
      const [sid, msg] = e.payload;
      if (sid !== usePortscanStore.getState().scanId) return;
      usePortscanStore.setState({ running: false, finishedAt: Date.now(), errorMsg: msg });
    }),
  );
}

// Config is persisted to localStorage so detached / re-opened windows pick
// up the user's last target / mode / timing instead of resetting to default.
const CONFIG_KEY = 'ws_portscan_config_v1';
interface PersistedConfig {
  targetInput: string;
  portsInput: string;
  mode: ScanMode;
  timing: Timing;
  serviceDetect: boolean;
  intensity: number;
  adaptive: boolean;
  idleMode: boolean;
  excludeCdn: boolean;
}
function loadConfig(): Partial<PersistedConfig> {
  try { return JSON.parse(localStorage.getItem(CONFIG_KEY) || '{}'); }
  catch { return {}; }
}
function saveConfig(c: PersistedConfig) {
  try { localStorage.setItem(CONFIG_KEY, JSON.stringify(c)); }
  catch {/* quota etc. */}
}

// Per-window scan results / progress are intentionally NOT persisted —
// each window subscribes to backend Tauri events directly.

const _persisted = loadConfig();

export const usePortscanStore = create<PortsState>((set, get) => ({
  // Config — load persisted values, fall back to defaults
  targetInput: _persisted.targetInput ?? '127.0.0.1',
  portsInput: _persisted.portsInput ?? 'top-100',
  mode: _persisted.mode ?? 'connect',
  timing: _persisted.timing ?? 'T3',
  serviceDetect: _persisted.serviceDetect ?? true,
  intensity: _persisted.intensity ?? 5,
  adaptive: _persisted.adaptive ?? true,
  idleMode: _persisted.idleMode ?? false,
  excludeCdn: _persisted.excludeCdn ?? false,

  scanId: null,
  startReply: null,
  results: [],
  progress: null,
  running: false,
  finishedAt: null,
  errorMsg: null,
  ppsHistory: [],

  setTargetInput: (v) => { set({ targetInput: v }); _persist(get); },
  setPortsInput: (v) => { set({ portsInput: v }); _persist(get); },
  setMode: (v) => { set({ mode: v }); _persist(get); },
  setTiming: (v) => { set({ timing: v }); _persist(get); },
  setServiceDetect: (v) => { set({ serviceDetect: v }); _persist(get); },
  setIntensity: (v) => { set({ intensity: v }); _persist(get); },
  setAdaptive: (v) => { set({ adaptive: v }); _persist(get); },
  setIdleMode: (v) => { set({ idleMode: v }); _persist(get); },
  setExcludeCdn: (v) => { set({ excludeCdn: v }); _persist(get); },

  start: async () => {
    await attachListeners();
    const s = get();
    if (s.running) return;
    const targets = s.targetInput.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
    if (targets.length === 0) throw new Error('No targets');

    set({
      results: [],
      progress: null,
      ppsHistory: [],
      finishedAt: null,
      errorMsg: null,
      running: true,
      scanId: null,
      startReply: null,
    });

    const req: ScanRequest = {
      targets,
      ports: s.portsInput,
      mode: s.mode,
      timing: s.timing,
      service_detect: s.serviceDetect,
      probe_intensity: s.intensity,
      exclude_cdn: s.excludeCdn,
      adaptive: s.adaptive,
      idle_mode: s.idleMode,
      max_hosts: null,
    };
    const reply = await invoke<ScanStartReply>('portscan_start', { req });
    set({ scanId: reply.scan_id, startReply: reply });
    void broadcastScanId(reply.scan_id);
  },

  stop: async () => {
    const sid = get().scanId;
    if (!sid) return;
    try {
      await invoke('portscan_stop', { scanId: sid });
    } finally {
      set({ running: false, finishedAt: Date.now() });
    }
  },

  reset: () => {
    set({
      scanId: null,
      startReply: null,
      results: [],
      progress: null,
      running: false,
      finishedAt: null,
      ppsHistory: [],
    });
  },

  exportAs: async (format) => {
    const sid = get().scanId;
    if (!sid) throw new Error('No scan to export');
    return invoke<string>('portscan_export', { scanId: sid, format });
  },
}));

function _persist(get: () => PortsState) {
  const s = get();
  saveConfig({
    targetInput: s.targetInput,
    portsInput: s.portsInput,
    mode: s.mode,
    timing: s.timing,
    serviceDetect: s.serviceDetect,
    intensity: s.intensity,
    adaptive: s.adaptive,
    idleMode: s.idleMode,
    excludeCdn: s.excludeCdn,
  });
}

// Eagerly attach listeners on first store import so events buffered during a
// detached-window remount aren't lost. Safe to call repeatedly — guarded by
// listenersAttached flag.
void attachListeners();

// When this window starts a new scan, broadcast the scan_id to other windows
// so detached views can attach their listeners to the same scan.
let scanIdBroadcastUnlisten: UnlistenFn | null = null;
async function setupScanIdSync() {
  if (scanIdBroadcastUnlisten) return;
  scanIdBroadcastUnlisten = await listen<string | null>('portscan:scan-id-sync', (e) => {
    const cur = usePortscanStore.getState().scanId;
    if (e.payload && e.payload !== cur) {
      // Adopt the broadcast scan_id — our listeners will start matching.
      usePortscanStore.setState({ scanId: e.payload, running: true });
    }
  });
}
void setupScanIdSync();
async function broadcastScanId(id: string | null) {
  try {
    const { emit } = await import('@tauri-apps/api/event');
    await emit('portscan:scan-id-sync', id);
  } catch {/* ignore */}
}
