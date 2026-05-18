// v0.3.16: per-project UI state — shuttled between zustand stores and
// <projectDir>/ui_state.json by projectStore.openProject/closeProject.
// Without this, Repeater tabs and Port-scan config bleed across projects
// because the underlying localStorage keys are global.
import { useReplayStore, useAppStore } from '../stores';
import { usePortscanStore } from '../stores/portscanStore';
import type { ReplayTab } from '../types';

export interface ProjectUiState {
  v: number; // schema version
  replay?: { tabs: ReplayTab[]; activeTabId: string | null };
  portscan?: {
    targetInput: string; portsInput: string; mode: string; timing: string;
    serviceDetect: boolean; intensity: number; adaptive: boolean;
    idleMode: boolean; excludeCdn: boolean;
  };
  scope?: string[];
}

const SCHEMA_VERSION = 1;

export function gatherProjectState(): ProjectUiState {
  const replay = useReplayStore.getState();
  const ports = usePortscanStore.getState();
  const app = useAppStore.getState();
  return {
    v: SCHEMA_VERSION,
    replay: {
      tabs: replay.tabs.map((t) => ({
        ...t,
        responseRaw: '',          // transient — don't persist response bodies
        statusCode: null,
        responseTimeMs: null,
        responseSize: null,
        isLoading: false,
      })),
      activeTabId: replay.activeTabId,
    },
    portscan: {
      targetInput: ports.targetInput,
      portsInput: ports.portsInput,
      mode: ports.mode,
      timing: ports.timing,
      serviceDetect: ports.serviceDetect,
      intensity: ports.intensity,
      adaptive: ports.adaptive,
      idleMode: ports.idleMode,
      excludeCdn: ports.excludeCdn,
    },
    scope: [...app.globalScope],
  };
}

export function applyProjectState(state: ProjectUiState | null): void {
  if (!state || typeof state !== 'object') return;
  // Forward-compatible: ignore future schema versions instead of crashing.
  if (typeof state.v === 'number' && state.v > SCHEMA_VERSION) return;

  if (state.replay && Array.isArray(state.replay.tabs) && state.replay.tabs.length > 0) {
    useReplayStore.setState({
      tabs: state.replay.tabs,
      activeTabId: state.replay.activeTabId ?? state.replay.tabs[0].id,
    });
  }
  if (state.portscan) {
    const p = state.portscan;
    usePortscanStore.setState({
      targetInput: p.targetInput,
      portsInput: p.portsInput,
      mode: p.mode as any,
      timing: p.timing as any,
      serviceDetect: p.serviceDetect,
      intensity: p.intensity,
      adaptive: p.adaptive,
      idleMode: p.idleMode,
      excludeCdn: p.excludeCdn,
    });
  }
  if (Array.isArray(state.scope)) {
    useAppStore.setState({ globalScope: [...state.scope] });
  }
}

export function parseProjectStateBlob(blob: string | null | undefined): ProjectUiState | null {
  if (!blob) return null;
  try { return JSON.parse(blob) as ProjectUiState; } catch { return null; }
}
