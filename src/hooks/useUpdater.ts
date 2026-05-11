import { useState, useEffect, useCallback, useRef } from 'react';
import { check as pluginCheck, Update } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';

export type UpdateStage =
  | 'idle'
  | 'checking'
  | 'available'
  | 'downloading'
  | 'installing'
  | 'ready'
  | 'error';

export interface UpdateProgress {
  downloaded: number;
  total: number;
}

const DISMISS_KEY = 'ws_update_dismissed_version';

export function useUpdater() {
  const [stage, setStage] = useState<UpdateStage>('idle');
  const [version, setVersion] = useState<string | null>(null);
  const [body, setBody] = useState<string>('');
  const [progress, setProgress] = useState<UpdateProgress>({ downloaded: 0, total: 0 });
  const [error, setError] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const updateRef = useRef<Update | null>(null);

  const check = useCallback(async (silent: boolean = false) => {
    setStage('checking');
    setError(null);
    try {
      const update = await pluginCheck();
      if (update) {
        updateRef.current = update;
        setVersion(update.version);
        setBody(update.body || '');
        setStage('available');
        if (silent) {
          const last = localStorage.getItem(DISMISS_KEY);
          setDismissed(last === update.version);
        } else {
          setDismissed(false);
        }
      } else {
        updateRef.current = null;
        setVersion(null);
        setBody('');
        setStage('idle');
      }
    } catch (e: any) {
      setError(String(e?.message || e));
      setStage('error');
    }
  }, []);

  const install = useCallback(async () => {
    const update = updateRef.current;
    if (!update) return;
    setError(null);
    setProgress({ downloaded: 0, total: 0 });
    setStage('downloading');
    try {
      let total = 0;
      let downloaded = 0;
      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case 'Started':
            total = event.data.contentLength || 0;
            setProgress({ downloaded: 0, total });
            break;
          case 'Progress':
            downloaded += event.data.chunkLength;
            setProgress({ downloaded, total });
            break;
          case 'Finished':
            setStage('installing');
            break;
        }
      });
      setStage('ready');
    } catch (e: any) {
      setError(String(e?.message || e));
      setStage('error');
    }
  }, []);

  const restart = useCallback(async () => {
    try {
      await relaunch();
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  }, []);

  const dismiss = useCallback(() => {
    if (version) localStorage.setItem(DISMISS_KEY, version);
    setDismissed(true);
  }, [version]);

  useEffect(() => {
    check(true);
    const id = setInterval(() => check(true), 60 * 60 * 1000);
    return () => clearInterval(id);
  }, [check]);

  return {
    stage,
    version,
    body,
    progress,
    error,
    dismissed,
    available: stage === 'available' || stage === 'downloading' || stage === 'installing' || stage === 'ready',
    check,
    install,
    restart,
    dismiss,
  };
}
