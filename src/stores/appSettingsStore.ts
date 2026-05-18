// v0.3.16: persisted app-wide settings (not project-scoped) — request
// timeouts, autosave cadence, debug verbosity, etc. Lives separately from
// the project config because these are user preferences that apply across
// every project the user opens.
import { create } from 'zustand';

const KEY = 'ws_app_settings_v1';

export interface AppSettings {
  autosaveIntervalSec: number;        // 5..3600, default 30
  requestTimeoutSec: number;          // 1..300, default 30
  cookieJarTtlDays: number;           // 0..3650 (0 = session-only), default 30
  responseSizeLimitMb: number;        // 1..1024, default 10
  followRedirects: boolean;
  debugVerbosity: 'silent' | 'error' | 'warn' | 'info' | 'debug';
  highlightSearchMatches: boolean;
  enableThrottling: boolean;
  throttleRequestsPerSec: number;     // 1..10000
}

export const DEFAULT_SETTINGS: AppSettings = {
  autosaveIntervalSec: 30,
  requestTimeoutSec: 30,
  cookieJarTtlDays: 30,
  responseSizeLimitMb: 10,
  followRedirects: true,
  debugVerbosity: 'warn',
  highlightSearchMatches: true,
  enableThrottling: false,
  throttleRequestsPerSec: 50,
};

function load(): AppSettings {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<AppSettings>;
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

function persist(s: AppSettings) {
  try { localStorage.setItem(KEY, JSON.stringify(s)); } catch {}
}

interface AppSettingsState extends AppSettings {
  set: <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => void;
  resetDefaults: () => void;
}

export const useAppSettings = create<AppSettingsState>((setState, get) => ({
  ...load(),
  set: (key, value) => {
    setState({ [key]: value } as any);
    const { set: _, resetDefaults: __, ...rest } = get();
    persist(rest as AppSettings);
  },
  resetDefaults: () => {
    setState({ ...DEFAULT_SETTINGS });
    persist({ ...DEFAULT_SETTINGS });
  },
}));
