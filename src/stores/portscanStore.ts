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
  // v0.3.20: source-level filter for Closed / Filtered / OpenFiltered.
  // When false the orchestrator drops them before storing/emitting,
  // saving RAM and event-bus bandwidth on big scans. Default true
  // keeps backward compat. Frontend binds this to the "Show
  // closed/filtered" toggle at scan-start time.
  emit_closed_filtered: boolean;
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
  start: (opts?: { emitClosedFiltered?: boolean }) => Promise<void>;
  stop: () => Promise<void>;
  reset: () => void;
  exportAs: (format: 'jsonl' | 'csv' | 'xml' | 'gnmap' | 'plain') => Promise<string>;
}

let listenersAttached = false;
let unlistens: UnlistenFn[] = [];

// v0.3.20: results buffer + smart cap so massive scans (65535 ports across
// multiple hosts with "Show closed/filtered" on) don't pin the renderer.
// We batch new ScanResult events for 50 ms before pushing to the store —
// turns 65535 individual setState calls (O(N²) array realloc + 65535
// React commits) into ~20 batched setStates.
// When the merged list exceeds FRONTEND_CAP, we evict the oldest non-Open
// entries first (Closed → Filtered → OpenFiltered), only dropping Open as
// a last resort. Scanning never stops; we just lose the cheapest history.
const FRONTEND_CAP = 20_000;
const FLUSH_INTERVAL_MS = 50;
let resultsBuffer: ScanResult[] = [];
let flushTimer: ReturnType<typeof setTimeout> | null = null;

function smartCapMerge(prev: ScanResult[], add: ScanResult[]): ScanResult[] {
  const merged = prev.concat(add);
  if (merged.length <= FRONTEND_CAP) return merged;
  let toDrop = merged.length - FRONTEND_CAP;
  // First pass: drop oldest non-Open. retain ordering by walking front-to-back.
  const kept: ScanResult[] = new Array(merged.length);
  let k = 0;
  for (const r of merged) {
    if (toDrop > 0 && r.state !== 'open') { toDrop--; continue; }
    kept[k++] = r;
  }
  kept.length = k;
  // If we are still over (all-Open surplus), drain oldest of those too.
  if (kept.length > FRONTEND_CAP) {
    return kept.slice(kept.length - FRONTEND_CAP);
  }
  return kept;
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    if (resultsBuffer.length === 0) return;
    const batch = resultsBuffer;
    resultsBuffer = [];
    usePortscanStore.setState((s) => ({ results: smartCapMerge(s.results, batch) }));
  }, FLUSH_INTERVAL_MS);
}

async function attachListeners() {
  if (listenersAttached) return;
  listenersAttached = true;

  unlistens.push(
    await listen<[string, ScanResult]>('portscan:result', (e) => {
      const [sid, r] = e.payload;
      if (sid !== usePortscanStore.getState().scanId) return;
      resultsBuffer.push(r);
      scheduleFlush();
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
      // v0.3.20: drain the result buffer synchronously so the
      // "complete" toast reflects the actual final count instead of
      // racing the next 50 ms flush tick.
      if (resultsBuffer.length > 0) {
        const batch = resultsBuffer;
        resultsBuffer = [];
        if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
        usePortscanStore.setState((s) => ({ results: smartCapMerge(s.results, batch) }));
      }
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

  start: async (opts) => {
    await attachListeners();
    const s = get();
    if (s.running) return;
    const targets = s.targetInput.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
    if (targets.length === 0) throw new Error('No targets');

    // v0.3.20: clear any leftover buffered results from a previous scan
    // so they don't bleed into the new scan's state.
    resultsBuffer = [];
    if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }

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
      // Default true keeps the previous behavior; UI passes false when
      // the "Show closed/filtered" checkbox is unticked at scan start.
      emit_closed_filtered: opts?.emitClosedFiltered ?? true,
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
