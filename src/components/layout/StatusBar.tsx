import { useState, useEffect } from 'react';
import { FolderOpen, Cpu } from 'lucide-react';
import './StatusBar.css';

interface Props {
  projectName?: string;
}

export function StatusBar({ projectName }: Props) {
  const [proxyInfo, setProxyInfo] = useState({ running: false, totalRequests: 0, intercepted: 0 });
  const [arch, setArch] = useState('');

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let requestCount = 0;
    let interceptCount = 0;

    (async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen<any>('proxy-event', (event) => {
          const data = event.payload;
          if (data.type === 'traffic') {
            requestCount++;
            setProxyInfo((p) => ({ ...p, totalRequests: requestCount }));
          } else if (data.type === 'intercept') {
            interceptCount++;
            setProxyInfo((p) => ({ ...p, intercepted: interceptCount }));
          }
        });
      } catch {}
    })();

    // Check initial status + arch
    const check = async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const [status, sysInfo] = await Promise.all([
          invoke<any>('proxy_status'),
          invoke<any>('get_system_info'),
        ]);
        setProxyInfo({
          running: status.running,
          totalRequests: status.total_requests,
          intercepted: status.pending_intercepts,
        });
        requestCount = status.total_requests;
        interceptCount = status.pending_intercepts;
        if (sysInfo?.arch_display) setArch(sysInfo.arch_display);
      } catch {}
    };
    check();
    const interval = setInterval(async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const status = await invoke<any>('proxy_status');
        setProxyInfo({
          running: status.running,
          totalRequests: status.total_requests,
          intercepted: status.pending_intercepts,
        });
      } catch {}
    }, 5000);

    return () => {
      unlisten?.();
      clearInterval(interval);
    };
  }, []);

  return (
    <footer className="statusbar">
      <div className="statusbar-item">
        <span className={`statusbar-dot ${proxyInfo.running ? 'running' : ''}`} />
        <span>{proxyInfo.running ? 'Proxy Active' : 'Ready'}</span>
      </div>
      {projectName && (
        <div className="statusbar-item statusbar-project">
          <FolderOpen size={10} />
          <span>{projectName}</span>
        </div>
      )}
      <div className="statusbar-item">Requests: {proxyInfo.totalRequests}</div>
      <div className="statusbar-item">Intercepted: {proxyInfo.intercepted}</div>
      <div className="statusbar-spacer" />
      {arch && (
        <div className="statusbar-item statusbar-arch">
          <Cpu size={9} />
          <span>{arch}</span>
        </div>
      )}
      <div className="statusbar-version">WonderSuite v0.1.0</div>
    </footer>
  );
}
