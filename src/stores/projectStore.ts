import { create } from 'zustand';
import type { ProjectInfo, ProjectConfig, CreateProjectOpts, MemoryStats } from '../types';

interface ProjectState {
  activeProject: ProjectInfo | null;
  projectConfig: ProjectConfig | null;
  projects: ProjectInfo[];
  memoryStats: MemoryStats | null;

  loadProjects: () => Promise<void>;
  openProject: (id: string) => Promise<void>;
  closeProject: () => void;
  createProject: (opts: CreateProjectOpts) => Promise<ProjectInfo>;
  createTempProject: (targetUrl: string) => Promise<ProjectInfo>;
  deleteProject: (id: string) => Promise<void>;
  duplicateProject: (id: string) => Promise<ProjectInfo>;
  updateConfig: (patch: Partial<ProjectConfig>) => Promise<void>;
  refreshMemoryStats: () => Promise<void>;
  setActiveProject: (project: ProjectInfo | null) => void;
}

export const useProjectStore = create<ProjectState>((set, get) => ({
  activeProject: null,
  projectConfig: null,
  projects: [],
  memoryStats: null,

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
      let config: ProjectConfig | null = null;
      try {
        config = await invoke<ProjectConfig>('get_project_config', { id });
      } catch { /* config may not exist for old projects */ }
      set({ activeProject: project, projectConfig: config });
    } catch (err) {
      console.error('Failed to open project:', err);
    }
  },

  closeProject: () => {
    set({ activeProject: null, projectConfig: null });
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
