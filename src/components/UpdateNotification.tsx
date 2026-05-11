import { useEffect, useState } from 'react';
import { openUrl } from '@tauri-apps/plugin-opener';
import { Download, X, Sparkles, ExternalLink, FileDown } from 'lucide-react';
import { useUpdater, type UpdateAsset } from '../hooks/useUpdater';
import './UpdateNotification.css';

function detectPlatform(): 'windows' | 'macos' | 'linux' | 'other' {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('win')) return 'windows';
  if (ua.includes('mac')) return 'macos';
  if (ua.includes('linux')) return 'linux';
  return 'other';
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function UpdateNotification() {
  const { info, dismissed, dismiss } = useUpdater();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (info?.available && !dismissed) setOpen(true);
  }, [info, dismissed]);

  if (!info || !info.available || !open) return null;

  const platform = detectPlatform();
  const platformAssets = info.assets.filter(a => a.platform === platform);
  const otherAssets = info.assets.filter(a => a.platform !== platform && a.platform !== 'other');

  const download = async (asset: UpdateAsset) => {
    try { await openUrl(asset.url); } catch { window.open(asset.url, '_blank'); }
  };

  const openReleasePage = async () => {
    try { await openUrl(info.url); } catch { window.open(info.url, '_blank'); }
  };

  const close = () => { setOpen(false); };
  const skipVersion = () => { dismiss(); setOpen(false); };

  return (
    <div className="updater-overlay" onClick={close}>
      <div className="updater-modal" onClick={e => e.stopPropagation()}>
        <header className="updater-head">
          <div className="updater-head-icon"><Sparkles size={16} /></div>
          <div className="updater-head-text">
            <span className="updater-tag">UPDATE AVAILABLE</span>
            <span className="updater-title">WonderSuite v{info.latest}</span>
            <span className="updater-sub">You're on v{info.current}</span>
          </div>
          <button className="updater-close" onClick={close} title="Close"><X size={14} /></button>
        </header>

        {info.body && (
          <div className="updater-notes">
            <div className="updater-notes-label">Release notes</div>
            <pre className="updater-notes-body">{info.body.slice(0, 1800)}{info.body.length > 1800 ? '\n…' : ''}</pre>
          </div>
        )}

        <div className="updater-downloads">
          <div className="updater-downloads-label">
            <Download size={11} /> Direct download for your system ({platform})
          </div>
          {platformAssets.length === 0 ? (
            <div className="updater-no-asset">
              No installer for <b>{platform}</b> in this release. Use the GitHub releases page.
            </div>
          ) : (
            <div className="updater-asset-list">
              {platformAssets.map(a => (
                <button key={a.name} className="updater-asset primary" onClick={() => download(a)}>
                  <FileDown size={12} />
                  <span className="updater-asset-name">{a.name}</span>
                  <span className="updater-asset-size">{formatSize(a.size)}</span>
                </button>
              ))}
            </div>
          )}

          {otherAssets.length > 0 && (
            <details className="updater-other-assets">
              <summary>Other platforms ({otherAssets.length})</summary>
              {otherAssets.map(a => (
                <button key={a.name} className="updater-asset" onClick={() => download(a)}>
                  <FileDown size={11} />
                  <span className="updater-asset-name">{a.name}</span>
                  <span className="updater-asset-platform">{a.platform}</span>
                  <span className="updater-asset-size">{formatSize(a.size)}</span>
                </button>
              ))}
            </details>
          )}
        </div>

        <footer className="updater-foot">
          <button className="updater-btn-link" onClick={openReleasePage}>
            <ExternalLink size={11} /> View on GitHub
          </button>
          <div className="updater-foot-spacer" />
          <button className="updater-btn-secondary" onClick={skipVersion}>Skip this version</button>
          <button className="updater-btn-secondary" onClick={close}>Later</button>
        </footer>
      </div>
    </div>
  );
}
