import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';

export interface UpdateAsset {
  name: string;
  url: string;
  size: number;
  platform: 'windows' | 'macos' | 'linux' | 'other';
}

export interface UpdateInfo {
  current: string;
  latest: string;
  available: boolean;
  url: string;
  body: string;
  published_at: string;
  assets: UpdateAsset[];
}

const DISMISS_KEY = 'ws_update_dismissed_version';

export function useUpdater() {
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState<boolean>(false);

  const check = useCallback(async (silent: boolean = false) => {
    setChecking(true); setError(null);
    try {
      const r = await invoke<UpdateInfo>('check_for_update');
      setInfo(r);
      if (silent) {
        const last = localStorage.getItem(DISMISS_KEY);
        if (last === r.latest) setDismissed(true); else setDismissed(false);
      } else {
        setDismissed(false);
      }
    } catch (e: any) {
      setError(String(e));
      setInfo(null);
    } finally {
      setChecking(false);
    }
  }, []);

  const dismiss = useCallback(() => {
    if (info) localStorage.setItem(DISMISS_KEY, info.latest);
    setDismissed(true);
  }, [info]);

  // Check on mount, then once an hour while the app is open.
  useEffect(() => {
    check(true);
    const id = setInterval(() => check(true), 60 * 60 * 1000);
    return () => clearInterval(id);
  }, [check]);

  return { info, checking, error, dismissed, check, dismiss };
}
