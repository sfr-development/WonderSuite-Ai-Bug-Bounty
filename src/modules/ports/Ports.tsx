import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Play,
  Square,
  Download,
  Copy,
  // (icons used by ElevationModal)
  ExternalLink,
  ShieldAlert,
  Loader2,
  Server,
  Network,
  Zap,
  Globe,
  HelpCircle,
  RotateCcw,
} from 'lucide-react';
import { useAppStore } from '../../stores';
import { usePortscanStore, type ScanResult, type Timing, type ScanMode } from '../../stores/portscanStore';
import './Ports.css';

const PORT_PRESETS: { label: string; value: string }[] = [
  { label: 'Top 100', value: 'top-100' },
  { label: 'Top 1000', value: 'top-1000' },
  { label: 'Web (80,443,8080,8443)', value: '80,443,8080,8443' },
  { label: 'Dev (3000,5000,5173,8000-8090)', value: '3000,5000,5173,8000-8090' },
  { label: 'DB (1433,3306,5432,6379,9200,27017)', value: '1433,3306,5432,6379,9200,27017' },
  { label: 'All (1-65535)', value: 'all' },
];

const TIMING_LABELS: Record<Timing, string> = {
  T0: 'Paranoid',
  T1: 'Sneaky',
  T2: 'Polite',
  T3: 'Normal',
  T4: 'Aggressive',
  T5: 'Insane',
  T6: 'Ludicrous',
};

export function Ports() {
  const addToast = useAppStore((s) => s.addToast);
  const sendTo = useAppStore((s) => s.sendTo);

  // Store-backed state survives unmount (multi-window pop-out, tab switches)
  const {
    targetInput, setTargetInput,
    portsInput, setPortsInput,
    mode, setMode,
    timing, setTiming,
    serviceDetect, setServiceDetect,
    intensity, setIntensity,
    adaptive, setAdaptive,
    idleMode, setIdleMode,
    excludeCdn, setExcludeCdn,
    scanId, results, progress, running, finishedAt, ppsHistory, startReply,
    start, stop, reset, exportAs,
  } = usePortscanStore();

  const [elevModal, setElevModal] = useState<ScanMode | null>(null);
  const [filterText, setFilterText] = useState('');
  const [showAllStates, setShowAllStates] = useState(false);

  const startScan = useCallback(async () => {
    if (running) return;
    // v0.3.20: pass the "Show closed/filtered" checkbox state down so the
    // backend drops noise at-source instead of storing 65535 entries per
    // host. The toggle still works as a display filter for the current
    // scan; it just also controls whether the data even arrives.
    const startOpts = { emitClosedFiltered: showAllStates };
    if (mode === 'connect' || mode === 'udp') {
      // No admin needed for connect or basic UDP — start immediately.
      try { await start(startOpts); }
      catch (e) { addToast({ type: 'error', title: 'Scan failed', message: String(e) }); }
      return;
    }
    // SYN: show the elevation hint modal once. After confirmation we let
    // the orchestrator run — it currently transparently falls back to the
    // TCP connect engine until the raw SYN engine ships in v0.3.8, so the
    // scan does actually execute.
    setElevModal(mode);
  }, [mode, running, start, addToast, showAllStates]);

  const proceedAfterElevation = useCallback(async () => {
    setElevModal(null);
    try { await start({ emitClosedFiltered: showAllStates }); }
    catch (e) { addToast({ type: 'error', title: 'Scan failed', message: String(e) }); }
  }, [start, addToast, showAllStates]);

  const stopScan = useCallback(async () => {
    try { await stop(); }
    catch (e) { addToast({ type: 'error', title: 'Stop failed', message: String(e) }); }
  }, [stop, addToast]);

  const doExport = useCallback(
    async (format: 'jsonl' | 'csv' | 'xml' | 'gnmap' | 'plain') => {
      if (!scanId) return;
      try {
        const out = await exportAs(format);
        await navigator.clipboard.writeText(out);
        addToast({ type: 'success', title: `Exported as ${format.toUpperCase()}`, message: 'Copied to clipboard' });
      } catch (e) {
        addToast({ type: 'error', title: 'Export failed', message: String(e) });
      }
    },
    [scanId, exportAs, addToast],
  );

  const filteredResults = useMemo(() => {
    const lower = filterText.trim().toLowerCase();
    return results.filter((r) => {
      if (!showAllStates && r.state !== 'open') return false;
      if (lower) {
        const hay = `${r.ip} ${r.port} ${r.service?.name ?? ''} ${r.service?.product ?? ''} ${r.service?.banner ?? ''}`.toLowerCase();
        if (!hay.includes(lower)) return false;
      }
      return true;
    });
  }, [results, filterText, showAllStates]);

  const pct = progress ? Math.min(100, (progress.completed / Math.max(progress.total_probes, 1)) * 100) : 0;

  // Last 8 results for the live ticker (only newest, scrolls up).
  const tickerEntries = useMemo(() => results.slice(-8).reverse(), [results]);

  const scanCompleted = !running && finishedAt != null && results.length > 0;

  return (
    <div className="ports-module">
      <div className="ports-toolbar">
        <div className="ports-row">
          <div className="ports-field grow">
            <label>Target</label>
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="10.0.0.0/24, example.com, 192.168.1.1-50"
              disabled={running}
              spellCheck={false}
            />
          </div>
          <div className="ports-field">
            <label>Ports</label>
            <input
              type="text"
              value={portsInput}
              onChange={(e) => setPortsInput(e.target.value)}
              placeholder="top-100 | 80,443 | 1-1024"
              disabled={running}
              spellCheck={false}
            />
          </div>
          <div className="ports-actions">
            {!running ? (
              <button className="ports-btn primary" onClick={startScan}>
                <Play size={14} />
                <span>{scanCompleted ? 'Re-scan' : 'Start'}</span>
              </button>
            ) : (
              <button className="ports-btn danger" onClick={stopScan}>
                <Square size={14} />
                <span>Stop</span>
              </button>
            )}
            {scanCompleted && !running && (
              <button className="ports-btn ghost" onClick={reset} title="Clear results">
                <RotateCcw size={13} />
              </button>
            )}
          </div>
        </div>

        <div className="ports-presets">
          {PORT_PRESETS.map((p) => (
            <button
              key={p.value}
              className={`ports-preset-chip ${portsInput === p.value ? 'active' : ''}`}
              onClick={() => setPortsInput(p.value)}
              disabled={running}
            >
              {p.label}
            </button>
          ))}
        </div>

        <div className="ports-row ports-options">
          <div className="ports-mode">
            <span className="ports-block-label">Mode</span>
            <div className="ports-mode-cards">
              {(['connect', 'syn', 'udp'] as ScanMode[]).map((m) => {
                const Icon = m === 'connect' ? Network : m === 'syn' ? Zap : Globe;
                const adminReq = m !== 'connect';
                return (
                  <button
                    key={m}
                    className={`ports-mode-card ${mode === m ? 'active' : ''} ${adminReq ? 'admin' : ''}`}
                    onClick={() => setMode(m)}
                    disabled={running}
                  >
                    <Icon size={14} />
                    <span className="ports-mode-name">
                      {m === 'connect' ? 'TCP Connect' : m === 'syn' ? 'TCP SYN' : 'UDP'}
                    </span>
                    {adminReq && <span className="ports-admin-pill">admin</span>}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="ports-timing">
            <span className="ports-block-label">Timing</span>
            <div className="ports-timing-chips">
              {(['T0', 'T1', 'T2', 'T3', 'T4', 'T5', 'T6'] as Timing[]).map((t) => (
                <button
                  key={t}
                  className={`ports-timing-chip ${timing === t ? 'active' : ''}`}
                  onClick={() => setTiming(t)}
                  disabled={running}
                  title={TIMING_LABELS[t]}
                >
                  {t}
                </button>
              ))}
            </div>
            <div className="ports-timing-name">{TIMING_LABELS[timing]}</div>
          </div>

          <div className="ports-flags">
            <ModernCheckbox checked={serviceDetect} onChange={setServiceDetect} disabled={running} label="Service detection" />
            <ModernCheckbox checked={adaptive} onChange={setAdaptive} disabled={running} label="Adaptive concurrency" />
            <ModernCheckbox checked={idleMode} onChange={setIdleMode} disabled={running} label="Idle mode (~100 pps)" />
            <ModernCheckbox checked={excludeCdn} onChange={setExcludeCdn} disabled={running} label="Exclude CDN ranges" />
            <div className="ports-intensity-row">
              <span className="ports-intensity-label">Probe intensity</span>
              <ModernSlider min={0} max={9} value={intensity} onChange={setIntensity} disabled={running} />
              <span className="ports-intensity-value">{intensity}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="ports-livebar">
        <div className="ports-progressbar">
          <div className="ports-progress-rail">
            <div className={`ports-progress-fill ${running ? 'running' : ''}`} style={{ width: `${pct}%` }} />
          </div>
        </div>
        <div className="ports-live-stats">
          {progress ? (
            <>
              <span className="ports-stat">
                <strong>{Math.round(pct)}%</strong>
                <em>{progress.completed.toLocaleString()} / {progress.total_probes.toLocaleString()}</em>
              </span>
              <span className="ports-stat">
                <strong>{Math.round(progress.pps).toLocaleString()}</strong>
                <em>pps</em>
              </span>
              <span className="ports-stat">
                <strong>{progress.rtt_p50_ms}</strong>
                <em>ms RTT μ</em>
              </span>
              <span className="ports-stat">
                <strong>{progress.permits}</strong>
                <em>permits</em>
              </span>
              <span className="ports-stat ports-stat-open">
                <strong>{progress.open_count}</strong>
                <em>open</em>
              </span>
              {progress.filtered_count > 0 && (
                <span className="ports-stat ports-stat-filtered">
                  <strong>{progress.filtered_count}</strong>
                  <em>filtered</em>
                </span>
              )}
            </>
          ) : (
            <span className="ports-stat-idle">
              {running ? 'Starting…' : startReply ? `Ready · ${startReply.total_probes.toLocaleString()} probes queued` : 'Idle'}
            </span>
          )}
          {running && <Loader2 size={12} className="ports-spin" />}
        </div>
        <PpsSparkline history={ppsHistory} running={running} />
      </div>

      {(running || tickerEntries.length > 0) && (
        <div className="ports-ticker">
          <span className="ports-ticker-label">{running ? 'LIVE' : 'LAST'}</span>
          <div className="ports-ticker-stream">
            {tickerEntries.map((r, i) => (
              <span key={`${r.ip}:${r.port}:${r.ts}`} className={`ports-ticker-pill state-${r.state.replace(/\|/g, '-')}`} style={{ opacity: 1 - i * 0.1 }}>
                <strong>{r.ip}</strong>:{r.port}
                {r.service?.name && <em> · {r.service.name}</em>}
              </span>
            ))}
            {running && tickerEntries.length === 0 && <span className="ports-ticker-waiting">probing…</span>}
          </div>
        </div>
      )}

      {scanCompleted && <ScanSummary results={results} progress={progress} />}

      <div className="ports-results-toolbar">
        <input
          className="ports-filter"
          type="text"
          placeholder="Filter results (host, service, banner…)"
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
        />
        <label className="ports-modern-check ports-toggle-states">
          <input type="checkbox" checked={showAllStates} onChange={(e) => setShowAllStates(e.target.checked)} />
          <span className="ports-check-box" />
          <span className="ports-check-label">Show closed/filtered</span>
        </label>
        <span className="ports-result-count">
          {filteredResults.length.toLocaleString()} / {results.length.toLocaleString()} results
        </span>
        <div className="ports-export-group">
          <button className="ports-btn ghost" onClick={() => doExport('jsonl')} disabled={!scanId}>
            <Download size={12} /> JSONL
          </button>
          <button className="ports-btn ghost" onClick={() => doExport('csv')} disabled={!scanId}>
            <Download size={12} /> CSV
          </button>
          <button className="ports-btn ghost" onClick={() => doExport('xml')} disabled={!scanId}>
            <Download size={12} /> Nmap XML
          </button>
          <button className="ports-btn ghost" onClick={() => doExport('plain')} disabled={!scanId}>
            <Download size={12} /> ip:port
          </button>
        </div>
      </div>

      <div className="ports-results-table">
        <div className="ports-row-head">
          <div className="cell host">Host</div>
          <div className="cell port">Port</div>
          <div className="cell state">State</div>
          <div className="cell svc">Service</div>
          <div className="cell product">Product</div>
          <div className="cell version">Version</div>
          <div className="cell banner">Banner</div>
          <div className="cell rtt">RTT</div>
          <div className="cell actions"></div>
        </div>
        <div className="ports-rows">
          {filteredResults.length === 0 ? (
            <div className="ports-empty">
              <Server size={32} strokeWidth={1.4} />
              <p>{running ? 'Scanning…' : 'No results yet. Pick a target and hit Start.'}</p>
            </div>
          ) : (
            filteredResults.slice(-500).map((r, i) => <Row key={`${r.ip}:${r.port}:${i}`} r={r} sendTo={sendTo} />)
          )}
        </div>
      </div>

      {elevModal && (
        <ElevationModal
          mode={elevModal}
          onClose={() => setElevModal(null)}
          onProceed={proceedAfterElevation}
          onFallback={() => {
            setMode('connect');
            setElevModal(null);
          }}
        />
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────

type SendToFn = (tool: string, method: string, url: string, requestRaw: string, responseRaw?: string, target?: 'left' | 'right') => void;

function Row({ r, sendTo }: { r: ScanResult; sendTo: SendToFn }) {
  const isOpen = r.state === 'open';
  const noService = isOpen && !r.service;
  const isHttp = r.service?.name === 'http' || r.service?.name === 'https' || r.port === 80 || r.port === 443 || r.port === 8080 || r.port === 8443;
  return (
    <div className={`ports-row-result state-${r.state.replace(/\|/g, '-')}`}>
      <div className="cell host">{r.ip}</div>
      <div className="cell port">{r.port}</div>
      <div className="cell state">
        <span className={`ports-state-pill ${r.state.replace(/\|/g, '-')}`}>{r.state}</span>
        {noService && (
          <span className="ports-unverified-pill" title="Open but no service banner / probe match — verify manually">
            <HelpCircle size={9} />
            <span>?</span>
          </span>
        )}
      </div>
      <div className="cell svc">{r.service?.name ?? '—'}</div>
      <div className="cell product">{r.service?.product ?? '—'}</div>
      <div className="cell version">{r.service?.version ?? '—'}</div>
      <div className="cell banner" title={r.service?.banner ?? ''}>
        {r.service?.banner ?? (r.service?.tls_cn ? `CN=${r.service.tls_cn}` : '—')}
      </div>
      <div className="cell rtt">{r.rtt_ms}ms</div>
      <div className="cell actions">
        {isHttp && isOpen && (
          <button
            className="ports-row-btn"
            title="Send to Scanner"
            onClick={() => {
              const scheme = r.port === 443 || r.port === 8443 ? 'https' : 'http';
              const url = `${scheme}://${r.ip}:${r.port}/`;
              sendTo('scan', 'GET', url, `GET / HTTP/1.1\nHost: ${r.ip}\n\n`);
            }}
          >
            <ExternalLink size={11} />
          </button>
        )}
        <button
          className="ports-row-btn"
          title="Copy ip:port"
          onClick={() => navigator.clipboard.writeText(`${r.ip}:${r.port}`)}
        >
          <Copy size={11} />
        </button>
      </div>
    </div>
  );
}

// ── PPS sparkline ─────────────────────────────────────────────────────────
function PpsSparkline({ history, running }: { history: { ts: number; pps: number }[]; running: boolean }) {
  const ref = useRef<SVGSVGElement | null>(null);
  if (history.length < 2) {
    return (
      <div className="ports-sparkline">
        <span className="ports-sparkline-empty">{running ? 'measuring…' : ''}</span>
      </div>
    );
  }
  const max = Math.max(...history.map((h) => h.pps), 1);
  const w = 160;
  const h = 32;
  const step = w / (history.length - 1);
  const points = history.map((p, i) => `${(i * step).toFixed(2)},${(h - (p.pps / max) * h).toFixed(2)}`).join(' ');
  return (
    <div className="ports-sparkline">
      <svg ref={ref} width={w} height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id="pps-grad" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.45" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <polygon
          points={`0,${h} ${points} ${w},${h}`}
          fill="url(#pps-grad)"
        />
        <polyline
          points={points}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.3"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span className="ports-sparkline-max">peak {Math.round(max).toLocaleString()} pps</span>
    </div>
  );
}

// ── Summary breakdown after scan completion ───────────────────────────────
function ScanSummary({ results, progress }: { results: ScanResult[]; progress: { pps: number; elapsed_ms: number; total_probes: number; rtt_p50_ms: number; permits: number } | null }) {
  const openResults = results.filter((r) => r.state === 'open');
  const byService = useMemo(() => {
    const map = new Map<string, number>();
    for (const r of openResults) {
      const k = r.service?.name ?? 'unverified';
      map.set(k, (map.get(k) ?? 0) + 1);
    }
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [openResults]);

  const total = openResults.length;
  if (total === 0) return null;

  // Donut math
  const radius = 36;
  const circ = 2 * Math.PI * radius;
  let acc = 0;
  const palette = ['#e8a145', '#4ade80', '#60a5fa', '#a78bfa', '#f87171', '#fb923c', '#22d3ee', '#fbbf24', '#34d399', '#f472b6'];

  return (
    <div className="ports-summary">
      <div className="ports-summary-head">
        <span className="ports-summary-title">Scan complete</span>
        <span className="ports-summary-meta">
          {total} open · {results.length} probed · {progress ? `${Math.round((progress.elapsed_ms / 1000) * 10) / 10}s` : ''}
        </span>
      </div>
      <div className="ports-summary-body">
        <svg className="ports-donut" width="120" height="120" viewBox="-60 -60 120 120">
          <circle r={radius} fill="none" stroke="var(--bg-3)" strokeWidth="14" />
          {byService.map(([name, count], i) => {
            const frac = count / total;
            const dash = circ * frac;
            const offset = circ * acc;
            acc += frac;
            const color = palette[i % palette.length];
            return (
              <circle
                key={name}
                r={radius}
                fill="none"
                stroke={color}
                strokeWidth="14"
                strokeDasharray={`${dash} ${circ - dash}`}
                strokeDashoffset={-offset}
                transform="rotate(-90)"
              />
            );
          })}
          <text x="0" y="-2" textAnchor="middle" className="ports-donut-num">{total}</text>
          <text x="0" y="14" textAnchor="middle" className="ports-donut-label">open</text>
        </svg>
        <div className="ports-summary-legend">
          {byService.slice(0, 12).map(([name, count], i) => (
            <div key={name} className="ports-legend-row">
              <span className="ports-legend-dot" style={{ background: palette[i % palette.length] }} />
              <span className="ports-legend-name">{name}</span>
              <span className="ports-legend-bar">
                <span className="ports-legend-bar-fill" style={{ width: `${(count / byService[0][1]) * 100}%`, background: palette[i % palette.length] }} />
              </span>
              <span className="ports-legend-count">{count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Modern form controls ──────────────────────────────────────────────────
function ModernCheckbox({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <label className={`ports-modern-check ${disabled ? 'disabled' : ''}`}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} disabled={disabled} />
      <span className="ports-check-box" />
      <span className="ports-check-label">{label}</span>
    </label>
  );
}

function ModernSlider({ min, max, value, onChange, disabled }: { min: number; max: number; value: number; onChange: (v: number) => void; disabled?: boolean }) {
  const pct = ((value - min) / (max - min)) * 100;
  return (
    <div className={`ports-modern-slider ${disabled ? 'disabled' : ''}`}>
      <div className="ports-slider-rail">
        <div className="ports-slider-fill" style={{ width: `${pct}%` }} />
      </div>
      <input
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        disabled={disabled}
      />
    </div>
  );
}

// ── Elevation modal ───────────────────────────────────────────────────────
interface CapabilityCheck {
  mode: string;
  available: boolean;
  missing: string[];
  note: string | null;
}

interface DriverStatus {
  installed: boolean;
  service_running: boolean;
  hvci_enabled: boolean;
  bundled_version: string;
  message: string;
}

function ElevationModal({
  mode,
  onClose,
  onProceed,
  onFallback,
}: {
  mode: ScanMode;
  onClose: () => void;
  onProceed: () => void;
  onFallback: () => void;
}) {
  const addToast = useAppStore((s) => s.addToast);
  const [cap, setCap] = useState<CapabilityCheck | null>(null);
  const [driver, setDriver] = useState<DriverStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const isWin = typeof navigator !== 'undefined' && navigator.userAgent.toLowerCase().includes('win');

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const c = await invoke<CapabilityCheck>('portscan_capability_check', { mode });
      setCap(c);
      if (isWin && mode === 'syn') {
        const d = await invoke<DriverStatus>('portscan_driver_status');
        setDriver(d);
      }
    } catch {/* ignore */} finally {
      setLoading(false);
    }
  }, [mode, isWin]);

  useEffect(() => { void refresh(); }, [refresh]);

  const installDriver = useCallback(async () => {
    setInstalling(true);
    try {
      const d = await invoke<DriverStatus>('portscan_driver_install');
      setDriver(d);
      if (d.service_running) {
        addToast({ type: 'success', title: 'Network driver installed', message: 'SYN scanning ready.' });
      } else if (d.hvci_enabled) {
        addToast({ type: 'warning', title: 'HVCI prevents driver', message: 'Disable Memory Integrity in Windows Security.' });
      } else {
        addToast({ type: 'info', title: 'Driver install incomplete', message: 'Check the UAC prompt or retry.' });
      }
    } catch (e) {
      addToast({ type: 'error', title: 'Driver install failed', message: String(e) });
    } finally {
      setInstalling(false);
    }
  }, [addToast]);

  const isSyn = mode === 'syn';
  const ready = cap?.available === true;
  const needsDriver = isWin && isSyn && driver && !driver.service_running && !driver.hvci_enabled;
  const blockedHvci = isWin && isSyn && driver?.hvci_enabled === true;

  return (
    <div className="ports-elev-backdrop" onClick={onClose}>
      <div className="ports-elev-modal" onClick={(e) => e.stopPropagation()}>
        <div className="ports-elev-head">
          <ShieldAlert size={16} />
          <span>{isSyn ? 'TCP SYN scan' : 'UDP scan'}</span>
        </div>
        <div className="ports-elev-body">
          {loading ? (
            <p>Checking capabilities…</p>
          ) : (
            <>
              <p>
                {isSyn
                  ? 'Administrator rights will be requested for raw TCP SYN packets.'
                  : 'UDP scans run unprivileged — closed-port detection is approximate without raw ICMP.'}
              </p>
              {cap?.note && (
                <div className="ports-elev-status">
                  <ShieldAlert size={14} />
                  <span>{cap.note}</span>
                </div>
              )}
              {needsDriver && (
                <div className="ports-elev-npcap">
                  <div className="ports-elev-npcap-head">
                    <strong>WonderSuite network driver not installed</strong>
                    <span>Bundled WinDivert {driver?.bundled_version} — single UAC prompt for life</span>
                  </div>
                  <button className="ports-btn primary" onClick={installDriver} disabled={installing}>
                    <Download size={12} />
                    <span>{installing ? 'Installing…' : 'Install network driver'}</span>
                  </button>
                  <button className="ports-btn ghost" onClick={refresh}>
                    Re-check
                  </button>
                </div>
              )}
              {blockedHvci && (
                <div className="ports-elev-status">
                  <ShieldAlert size={14} />
                  <span>
                    Memory Integrity (HVCI) is on — Windows blocks third-party kernel drivers
                    from loading. Disable Core Isolation → Memory Integrity in Windows Security
                    to enable raw SYN, or use TCP connect mode.
                  </span>
                </div>
              )}
              {isWin && isSyn && driver?.service_running && (
                <div className="ports-elev-status ports-elev-ok">
                  <ShieldAlert size={14} />
                  <span>Network driver running (WinDivert {driver.bundled_version}). Raw SYN engine ready.</span>
                </div>
              )}
            </>
          )}
        </div>
        <div className="ports-elev-actions">
          <button className="ports-btn primary" onClick={onProceed} disabled={loading || installing}>
            <ExternalLink size={12} />
            <span>{ready ? 'Proceed' : isSyn ? 'Proceed (TCP-connect fallback)' : 'Proceed'}</span>
          </button>
          <button className="ports-btn ghost" onClick={onFallback}>
            Use TCP connect instead
          </button>
          <button className="ports-btn ghost" onClick={onClose}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
