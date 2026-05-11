import { useState, useEffect, useCallback } from 'react';
import { FolderOpen, Cpu, Timer, HardDrive, X } from 'lucide-react';
import { useVisibilityAwareInterval } from '../../hooks/useVisibilityAwareInterval';
import './StatusBar.css';

interface Props {
  projectName?: string;
  isTemporary?: boolean;
  onCloseProject?: () => void;
}

export function StatusBar({ projectName, isTemporary, onCloseProject }: Props) {
  const [proxyInfo, setProxyInfo] = useState({ running: false, totalRequests: 0, intercepted: 0 });
  const [arch, setArch] = useState('');
  const [memoryMb, setMemoryMb] = useState<number | null>(null);
  const [version, setVersion] = useState<string>('');

  useEffect(() => {
    (async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const v = await invoke<string>('current_version');
        setVersion(v);
      } catch { /* not in tauri env */ }
    })();
  }, []);

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

    return () => { unlisten?.(); };
  }, []);

  const pollStatus = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const status = await invoke<any>('proxy_status');
      setProxyInfo({
        running: status.running,
        totalRequests: status.total_requests,
        intercepted: status.pending_intercepts,
      });
    } catch {}
  }, []);

  useVisibilityAwareInterval(pollStatus, 5000);

  const pollMemory = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const stats = await invoke<any>('get_memory_stats');
      if (stats?.process_rss_mb) setMemoryMb(Math.round(stats.process_rss_mb));
    } catch {
    }
  }, []);

  useVisibilityAwareInterval(pollMemory, 10000);

  return (
    <footer className="statusbar">
      <div className="statusbar-item">
        <span className={`statusbar-dot ${proxyInfo.running ? 'running' : ''}`} />
        <span>{proxyInfo.running ? 'Proxy Active' : 'Ready'}</span>
      </div>
      {projectName && (
        <div className="statusbar-item statusbar-project" title={isTemporary ? 'Temporary project — data will not be saved' : projectName}>
          <FolderOpen size={10} />
          <span>{projectName}</span>
          {isTemporary && (
            <span className="statusbar-temp-badge">
              <Timer size={8} /> TEMP
            </span>
          )}
          {onCloseProject && (
            <button className="statusbar-close-project" onClick={onCloseProject} title="Close project">
              <X size={9} />
            </button>
          )}
        </div>
      )}
      <div className="statusbar-item">Requests: {proxyInfo.totalRequests}</div>
      <div className="statusbar-item">Intercepted: {proxyInfo.intercepted}</div>
      <div className="statusbar-spacer" />
      {memoryMb !== null && (
        <div className="statusbar-item statusbar-memory" title="Process memory usage">
          <HardDrive size={9} />
          <span>{memoryMb} MB</span>
        </div>
      )}
      {arch && (
        <div className="statusbar-item statusbar-arch">
          <Cpu size={9} />
          <span>{arch}</span>
        </div>
      )}
      <div className="statusbar-version">WonderSuite{version ? ` v${version}` : ''}</div>
    </footer>
  );
}
