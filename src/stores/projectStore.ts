import { create } from 'zustand';
import type { ProjectInfo, ProjectConfig, CreateProjectOpts, MemoryStats } from '../types';
import { useAppStore, useReplayStore } from './index';
import { gatherProjectState, applyProjectState, parseProjectStateBlob } from '../utils/projectState';

const LAST_PROJECT_KEY = 'ws_last_active_project_id';
const EXPLICIT_CLOSE_KEY = 'ws_project_explicitly_closed';

interface ProjectState {
  activeProject: ProjectInfo | null;
  projectConfig: ProjectConfig | null;
  projects: ProjectInfo[];
  memoryStats: MemoryStats | null;
  /** Set when openProject fails to parse config.json — UI can show a banner. */
  configCorrupted: boolean;

  loadProjects: () => Promise<void>;
  openProject: (id: string) => Promise<void>;
  closeProject: () => Promise<void>;
  createProject: (opts: CreateProjectOpts) => Promise<ProjectInfo>;
  createTempProject: (targetUrl: string) => Promise<ProjectInfo>;
  deleteProject: (id: string) => Promise<void>;
  duplicateProject: (id: string) => Promise<ProjectInfo>;
  updateConfig: (patch: Partial<ProjectConfig>) => Promise<void>;
  refreshMemoryStats: () => Promise<void>;
  setActiveProject: (project: ProjectInfo | null) => void;
}

// ── Helpers to reset cross-project state on switch ────────────────────────
// Without these, opening a fresh project shows the previous project's
// Repeater tabs, scope rules, and proxy traffic (cross-project leak).
async function applyProjectConfig(config: ProjectConfig | null) {
  if (!config) return;
  try {
    const { invoke } = await import('@tauri-apps/api/core');

    // 1. Scope — sync zustand globalScope from project config.
    if (Array.isArray(config.initial_scope)) {
      useAppStore.setState({ globalScope: [...config.initial_scope] });
      try {
        localStorage.setItem('ws_global_scope_v1', JSON.stringify(config.initial_scope));
      } catch {}
    }

    // 1a. v0.3.16: push the project's traffic-buffer cap into the live
    // ProxyState ring. Previously the wizard wrote this to config.json
    // and nothing ever read it.
    if (typeof config.max_traffic_entries === 'number') {
      try {
        await invoke('proxy_set_max_traffic_entries', { max: config.max_traffic_entries });
      } catch (e) {
        console.warn('[project] proxy_set_max_traffic_entries failed:', e);
      }
    }

    // 2. Auto-start proxy on the project's configured port.
    if (config.auto_start_proxy) {
      try {
        await invoke('proxy_start', { port: config.proxy_port || 8080 });
      } catch (e) {
        console.warn('[project] auto_start_proxy failed:', e);
      }
    }

    // 3. Auto-enable intercept (only meaningful if the proxy is running —
    // start proxy first, then toggle).
    if (config.intercept_enabled) {
      try {
        await invoke('proxy_toggle_intercept', { enabled: true });
      } catch (e) {
        console.warn('[project] intercept_enabled failed:', e);
      }
    }

    // 4. Auto-launch the bundled browser.
    if (config.auto_launch_browser) {
      try {
        await invoke('browser_open', {});
      } catch (e) {
        console.warn('[project] auto_launch_browser failed:', e);
      }
    }
  } catch (e) {
    console.warn('[project] applyProjectConfig error:', e);
  }
}

async function clearCrossProjectState() {
  // Reset Repeater tabs to the default single-tab state.
  try {
    const defaultTab = {
      id: 'tab-1', name: 'New Request', method: 'GET',
      url: 'https://httpbin.org/get',
      requestRaw: 'GET /get HTTP/1.1\nHost: httpbin.org\nAccept: */*\nUser-Agent: WonderSuite/0.1',
      responseRaw: '', statusCode: null, responseTimeMs: null,
      responseSize: null, isLoading: false,
    };
    useReplayStore.setState({ tabs: [defaultTab], activeTabId: 'tab-1' });
    try {
      localStorage.removeItem('ws_replay_tabs_v1');
    } catch {}
  } catch {}

  // Reset the in-scope rules.
  try {
    useAppStore.setState({ globalScope: [] });
    localStorage.removeItem('ws_global_scope_v1');
  } catch {}

  // Clear proxy traffic + intercept on the Rust side.
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('proxy_clear_traffic').catch(() => {});
    await invoke('proxy_toggle_intercept', { enabled: false }).catch(() => {});
  } catch {}
}

// ── Auto-save loop ─────────────────────────────────────────────────────────
// Snapshots proxy traffic to <projectDir>/traffic.json every 30 s while a
// non-temp project is active. Cancelled when the project closes.
let autoSaveTimer: ReturnType<typeof setInterval> | null = null;

function startAutoSave(projectId: string) {
  stopAutoSave();
  // v0.3.16: read the user-configurable autosave interval from the
  // app-settings store (default 30 s). Lazy import to avoid a cycle.
  let intervalMs = 30000;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { useAppSettings } = require('./appSettingsStore');
    intervalMs = Math.max(5, Math.min(3600, useAppSettings.getState().autosaveIntervalSec)) * 1000;
  } catch {}
  autoSaveTimer = setInterval(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('project_save_state', { id: projectId }).catch((e: unknown) => {
        console.warn('[project] auto-save failed:', e);
      });
      // v0.3.16: also snapshot the UI state (Repeater tabs, port-scan config,
      // scope) so a crash doesn't lose tab drafts.
      try {
        const blob = JSON.stringify(gatherProjectState());
        await invoke('project_save_state_blob', { id: projectId, blob });
      } catch (e) {
        console.warn('[project] ui-state auto-save failed:', e);
      }
    } catch {}
  }, intervalMs);
}

function stopAutoSave() {
  if (autoSaveTimer) {
    clearInterval(autoSaveTimer);
    autoSaveTimer = null;
  }
}

export const useProjectStore = create<ProjectState>((set, get) => ({
  activeProject: null,
  projectConfig: null,
  projects: [],
  memoryStats: null,
  configCorrupted: false,

  setActiveProject: (project) => set({ activeProject: project }),

  loadProjects: async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const projects = await invoke<ProjectInfo[]>('list_projects');
      set({ projects });
    } catch {
      set({ projects: [] });
    }
  },

  openProject: async (id: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const project = await invoke<ProjectInfo>('open_project', { id });

      // Try to load the project's config.json. Silent fallback to defaults
      // hides corruption; we report it explicitly so the UI can warn.
      let config: ProjectConfig | null = null;
      let corrupted = false;
      try {
        config = await invoke<ProjectConfig>('get_project_config', { id });
      } catch (e) {
        console.warn('[project] config.json missing or corrupted:', e);
        corrupted = true;
      }

      // Restore disk-persisted traffic / findings if the backend supports it.
      // Best-effort — older builds don't have the command.
      try {
        await invoke('project_load_state', { id });
      } catch (e) {
        console.debug('[project] project_load_state unavailable:', e);
      }

      // v0.3.16: restore per-project UI state (Repeater tabs, port-scan
      // config, scope). MUST happen before set() so the modules don't
      // briefly render the previous project's tabs.
      try {
        const blob = await invoke<string | null>('project_load_state_blob', { id });
        applyProjectState(parseProjectStateBlob(blob));
      } catch (e) {
        console.debug('[project] ui-state load skipped:', e);
      }

      set({ activeProject: project, projectConfig: config, configCorrupted: corrupted });

      // Remember which project to resume on next launch.
      try {
        localStorage.setItem(LAST_PROJECT_KEY, id);
        sessionStorage.removeItem(EXPLICIT_CLOSE_KEY);
      } catch {}

      // Apply auto-start settings (proxy port, intercept, browser, scope).
      // Done after state is set so listening components see the new project
      // before the proxy comes up.
      void applyProjectConfig(config);

      // Auto-save loop for non-temp projects.
      if (!project.is_temporary) {
        startAutoSave(id);
      }
    } catch (err) {
      console.error('Failed to open project:', err);
    }
  },

  closeProject: async () => {
    const current = get().activeProject;

    // Snapshot one last time before clearing, so the user's last 30 s aren't
    // lost. Best-effort.
    if (current && !current.is_temporary) {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        await invoke('project_save_state', { id: current.id }).catch(() => {});
        // v0.3.16: also snapshot the UI state blob so Repeater tabs survive
        // the close → reopen round-trip.
        try {
          const blob = JSON.stringify(gatherProjectState());
          await invoke('project_save_state_blob', { id: current.id, blob });
        } catch {}
      } catch {}
    }

    stopAutoSave();

    // Mark this close as explicit so the auto-resume on next launch is
    // suppressed (user wanted to land on the launcher, not the project).
    try {
      sessionStorage.setItem(EXPLICIT_CLOSE_KEY, '1');
      localStorage.removeItem(LAST_PROJECT_KEY);
    } catch {}

    set({ activeProject: null, projectConfig: null, configCorrupted: false });

    // Clear cross-project state: Repeater tabs, scope, proxy traffic, intercept.
    // Without this, project B inherits project A's residue.
    void clearCrossProjectState();
  },

  createProject: async (opts: CreateProjectOpts) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const project = await invoke<ProjectInfo>('create_project', {
        name: opts.name,
        description: opts.description,
        targetUrl: opts.target_url,
        projectType: opts.project_type,
        isTemporary: opts.is_temporary,
        tempTtlHours: opts.temp_ttl_hours ?? null,
        proxyPort: opts.proxy_port,
        autoStartProxy: opts.auto_start_proxy,
        autoLaunchBrowser: opts.auto_launch_browser,
        initialScope: opts.initial_scope,
        interceptEnabled: opts.intercept_enabled,
        clientName: opts.client_name,
        tags: opts.tags,
        maxTrafficEntries: opts.max_traffic_entries,
        notesTemplate: opts.notes_template,
      });
      await get().loadProjects();
      return project;
    } catch (err) {
      console.error('Failed to create project:', err);
      throw err;
    }
  },

  createTempProject: async (targetUrl: string) => {
    const tempProject: ProjectInfo = {
      id: `temp-${Date.now()}`,
      name: 'Quick Session',
      path: '',
      created_at: new Date().toISOString(),
      last_opened: new Date().toISOString(),
      description: 'Temporary in-memory session — data will not be saved',
      target_url: targetUrl,
      request_count: 0,
      finding_count: 0,
      project_type: 'research',
      is_temporary: true,
      tags: [],
    };
    set({ activeProject: tempProject });
    return tempProject;
  },

  deleteProject: async (id: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('delete_project', { id });
      await get().loadProjects();
    } catch (err) {
      console.error('Failed to delete project:', err);
    }
  },

  duplicateProject: async (id: string) => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const project = await invoke<ProjectInfo>('duplicate_project', { id });
      await get().loadProjects();
      return project;
    } catch (err) {
      console.error('Failed to duplicate project:', err);
      throw err;
    }
  },

  updateConfig: async (patch: Partial<ProjectConfig>) => {
    const current = get().projectConfig;
    if (!current || !get().activeProject) return;
    const updated = { ...current, ...patch };
    set({ projectConfig: updated });
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('update_project_config', {
        id: get().activeProject!.id,
        config: updated,
      });
    } catch (err) {
      console.error('Failed to update config:', err);
    }
  },

  refreshMemoryStats: async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const stats = await invoke<MemoryStats>('get_memory_stats');
      set({ memoryStats: stats });
    } catch {
    }
  },
}));
