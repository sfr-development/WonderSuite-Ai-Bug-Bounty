import { useEffect, useState } from 'react';
import { Minus, Square, X } from 'lucide-react';
import './Titlebar.css';

export function Titlebar() {
  const [appWindow, setAppWindow] = useState<any>(null);

  useEffect(() => {
    import('@tauri-apps/api/window').then((mod) => {
      setAppWindow(mod.getCurrentWindow());
    }).catch(() => {});
  }, []);

  return (
    <div className="titlebar">
      <div className="titlebar-drag" data-tauri-drag-region>
        <img src="/wondersuite_logo.png" alt="WS" style={{ width: 16, height: 16, objectFit: 'contain' }} className="titlebar-icon" />
        <span className="titlebar-title">WonderSuite</span>
      </div>
      <div className="titlebar-controls">
        <button className="titlebar-btn" onClick={() => appWindow?.minimize()}>
          <Minus size={14} />
        </button>
        <button className="titlebar-btn" onClick={() => appWindow?.toggleMaximize()}>
          <Square size={11} />
        </button>
        <button className="titlebar-btn close" onClick={() => appWindow?.close()}>
          <X size={15} />
        </button>
      </div>
    </div>
  );
}
