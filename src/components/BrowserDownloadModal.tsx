import { useEffect, useState } from 'react';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import { Download, RefreshCw, CheckCircle, AlertTriangle, Globe, X } from 'lucide-react';
import './BrowserDownloadModal.css';

type Phase = 'download' | 'verify' | 'extract' | 'ready' | 'error';

interface Progress {
  phase: Phase;
  downloaded: number;
  total: number;
  version: string;
}

function formatSize(b: number): string {
  if (!b) return '—';
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}

const PHASE_LABEL: Record<Phase, string> = {
  download: 'Downloading WonderBrowser',
  verify: 'Verifying integrity',
  extract: 'Extracting',
  ready: 'Ready',
  error: 'Failed',
};

export function BrowserDownloadModal() {
  const [progress, setProgress] = useState<Progress | null>(null);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    (async () => {
      try {
        unlisten = await listen<Progress>('chromium:progress', (event) => {
          setProgress(event.payload);
          setOpen(true);
          if (event.payload.phase === 'ready') {
            // auto-dismiss after 1.5s on success
            setTimeout(() => setOpen(false), 1500);
          }
        });
      } catch (e: any) {
        console.error('[BrowserDownloadModal] listen failed:', e);
      }
    })();
    return () => {
      unlisten?.();
    };
  }, []);

  if (!open || !progress) return null;

  const percent =
    progress.total > 0 && progress.phase === 'download'
      ? Math.min(100, Math.round((progress.downloaded / progress.total) * 100))
      : progress.phase === 'extract' || progress.phase === 'verify'
        ? null
        : 100;

  const close = () => {
    if (progress.phase === 'ready' || progress.phase === 'error') {
      setOpen(false);
    }
    // Active download: ignore close click to prevent half-finished cache.
  };

  const retry = async () => {
    setError(null);
    setProgress({ phase: 'download', downloaded: 0, total: 0, version: progress.version });
    try {
      await invoke<string>('chromium_ensure');
    } catch (e: any) {
      setError(String(e?.message || e));
      setProgress({ phase: 'error', downloaded: 0, total: 0, version: progress.version });
    }
  };

  return (
    <div className="bdl-overlay" onClick={close}>
      <div className="bdl-modal" onClick={(e) => e.stopPropagation()}>
        <header className="bdl-head">
          <div className="bdl-head-icon"><Globe size={16} /></div>
          <div className="bdl-head-text">
            <span className="bdl-tag">WONDERBROWSER</span>
            <span className="bdl-title">Chromium {progress.version}</span>
            <span className="bdl-sub">{PHASE_LABEL[progress.phase]}</span>
          </div>
          {(progress.phase === 'ready' || progress.phase === 'error') && (
            <button className="bdl-close" onClick={close} title="Close">
              <X size={14} />
            </button>
          )}
        </header>

        <div className="bdl-body">
          {progress.phase === 'download' && (
            <>
              <div className="bdl-bar">
                <div className="bdl-bar-fill" style={{ width: `${percent || 0}%` }} />
              </div>
              <div className="bdl-meta">
                <span>{formatSize(progress.downloaded)} / {formatSize(progress.total)}</span>
                <span>{percent ?? 0}%</span>
              </div>
              <p className="bdl-hint">
                Downloading WonderSuite's bundled browser — this happens once.
                The binary is verified against a pinned SHA-256.
              </p>
            </>
          )}
          {progress.phase === 'verify' && (
            <div className="bdl-spinner">
              <RefreshCw size={18} className="bdl-spin" />
              <span>Verifying SHA-256…</span>
            </div>
          )}
          {progress.phase === 'extract' && (
            <div className="bdl-spinner">
              <RefreshCw size={18} className="bdl-spin" />
              <span>Extracting…</span>
            </div>
          )}
          {progress.phase === 'ready' && (
            <div className="bdl-ready">
              <CheckCircle size={32} style={{ color: '#2ed573' }} />
              <span className="bdl-ready-title">Ready</span>
              <span className="bdl-ready-sub">WonderBrowser is installed.</span>
            </div>
          )}
          {progress.phase === 'error' && (
            <div className="bdl-error">
              <AlertTriangle size={18} style={{ color: '#ff6b35' }} />
              <div className="bdl-error-text">
                <span>{error || 'Download failed.'}</span>
                <span className="bdl-error-hint">
                  Check your network. WonderSuite will fall back to a detected system
                  Chrome / Edge / Brave if available.
                </span>
              </div>
            </div>
          )}
        </div>

        <footer className="bdl-foot">
          {progress.phase === 'error' ? (
            <>
              <span className="bdl-foot-spacer" />
              <button className="bdl-btn-secondary" onClick={close}>Close</button>
              <button className="bdl-btn-primary" onClick={retry}>
                <Download size={12} /> Retry
              </button>
            </>
          ) : progress.phase === 'ready' ? (
            <>
              <span className="bdl-foot-spacer" />
              <button className="bdl-btn-primary" onClick={close}>Done</button>
            </>
          ) : (
            <>
              <span className="bdl-foot-spacer" />
              <span className="bdl-foot-note">Please don't close WonderSuite during the download.</span>
            </>
          )}
        </footer>
      </div>
    </div>
  );
}
