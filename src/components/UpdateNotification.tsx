import { useEffect, useState } from 'react';
import { X, Sparkles, Download, RefreshCw, CheckCircle, AlertTriangle } from 'lucide-react';
import { useUpdater } from '../hooks/useUpdater';
import './UpdateNotification.css';

function formatSize(bytes: number): string {
  if (!bytes) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function UpdateNotification() {
  const { stage, version, body, progress, error, dismissed, available, install, restart, dismiss } = useUpdater();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (available && !dismissed) setOpen(true);
  }, [available, dismissed]);

  if (!open || !available) return null;

  const close = () => { setOpen(false); };
  const skipVersion = () => { dismiss(); setOpen(false); };

  const percent = progress.total > 0
    ? Math.min(100, Math.round((progress.downloaded / progress.total) * 100))
    : 0;

  return (
    <div className="updater-overlay" onClick={stage === 'available' ? close : undefined}>
      <div className="updater-modal" onClick={e => e.stopPropagation()}>
        <header className="updater-head">
          <div className="updater-head-icon"><Sparkles size={16} /></div>
          <div className="updater-head-text">
            <span className="updater-tag">UPDATE AVAILABLE</span>
            <span className="updater-title">WonderSuite v{version}</span>
          </div>
          {stage === 'available' && (
            <button className="updater-close" onClick={close} title="Close"><X size={14} /></button>
          )}
        </header>

        {body && stage === 'available' && (
          <div className="updater-notes">
            <div className="updater-notes-label">Release notes</div>
            <pre className="updater-notes-body">{body.slice(0, 1800)}{body.length > 1800 ? '\n…' : ''}</pre>
          </div>
        )}

        {(stage === 'downloading' || stage === 'installing') && (
          <div className="updater-progress-wrap">
            <div className="updater-progress-label">
              {stage === 'downloading' ? (
                <><Download size={12} /> Downloading update… {percent}%</>
              ) : (
                <><RefreshCw size={12} className="updater-spin" /> Installing…</>
              )}
            </div>
            <div className="updater-progress-bar">
              <div className="updater-progress-fill" style={{ width: `${stage === 'installing' ? 100 : percent}%` }} />
            </div>
            <div className="updater-progress-meta">
              {formatSize(progress.downloaded)} / {formatSize(progress.total)}
            </div>
          </div>
        )}

        {stage === 'ready' && (
          <div className="updater-ready">
            <CheckCircle size={28} style={{ color: '#2ed573' }} />
            <span className="updater-ready-title">Update installed</span>
            <span className="updater-ready-sub">Restart WonderSuite to finish applying v{version}.</span>
          </div>
        )}

        {stage === 'error' && error && (
          <div className="updater-error">
            <AlertTriangle size={18} style={{ color: '#ff6b35' }} />
            <span>{error}</span>
          </div>
        )}

        <footer className="updater-foot">
          {stage === 'available' && (
            <>
              <div className="updater-foot-spacer" />
              <button className="updater-btn-secondary" onClick={skipVersion}>Skip this version</button>
              <button className="updater-btn-secondary" onClick={close}>Later</button>
              <button className="updater-btn-primary" onClick={install}>
                <Download size={12} /> Install now
              </button>
            </>
          )}
          {(stage === 'downloading' || stage === 'installing') && (
            <>
              <div className="updater-foot-spacer" />
              <button className="updater-btn-secondary" disabled>Working…</button>
            </>
          )}
          {stage === 'ready' && (
            <>
              <div className="updater-foot-spacer" />
              <button className="updater-btn-secondary" onClick={close}>Later</button>
              <button className="updater-btn-primary" onClick={restart}>
                <RefreshCw size={12} /> Restart now
              </button>
            </>
          )}
          {stage === 'error' && (
            <>
              <div className="updater-foot-spacer" />
              <button className="updater-btn-secondary" onClick={close}>Close</button>
              <button className="updater-btn-primary" onClick={install}>Retry</button>
            </>
          )}
        </footer>
      </div>
    </div>
  );
}
