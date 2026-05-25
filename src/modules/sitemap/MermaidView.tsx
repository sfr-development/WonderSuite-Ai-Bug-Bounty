import React, { useState, useMemo, useRef, useCallback, useEffect } from 'react';
import { Copy, Download, Check, ZoomIn, ZoomOut, Maximize2, Code, Eye, Image } from 'lucide-react';
import mermaid from 'mermaid';
import { TreeNode } from './Sitemap';

interface MermaidViewProps { tree: TreeNode[]; }

function truncate(s: string, max: number): string { return s.length <= max ? s : s.slice(0, max - 3) + '...'; }
function sanitize(s: string): string { return s.replace(/"/g, "'").replace(/[[\](){}|<>#&]/g, '_'); }
function nodeId(prefix: string, index: number): string { return `${prefix}${index}`; }

function methodStyle(method?: string): string {
  switch (method?.toUpperCase()) {
    case 'GET': return 'fill:#1a3a2a,stroke:#4ec58a,color:#4ec58a';
    case 'POST': return 'fill:#1a2a3a,stroke:#5b9fd6,color:#5b9fd6';
    case 'PUT': return 'fill:#2a2a1a,stroke:#e8873c,color:#e8873c';
    case 'DELETE': return 'fill:#2a1a1a,stroke:#d95757,color:#d95757';
    case 'PATCH': return 'fill:#2a1a2a,stroke:#a78bda,color:#a78bda';
    default: return 'fill:#292929,stroke:#505050,color:#a0a0a0';
  }
}

function generateMermaid(tree: TreeNode[]): string {
  if (tree.length === 0) return 'graph LR\n    empty["No sites discovered"]';
  const lines: string[] = ['graph LR'];
  const styles: string[] = [];
  let idCounter = 0;

  for (const host of tree) {
    const hostId = nodeId('H', idCounter++);
    const hostLabel = truncate(sanitize(host.name), 45);
    lines.push(`    ${hostId}["${hostLabel}"]`);
    styles.push(`    style ${hostId} fill:#1a1a2e,stroke:#e8a145,stroke-width:2px,color:#e8a145`);

    if (host.children && host.children.length > 0) {
      const dirGroups = new Map<string, TreeNode[]>();
      const rootFiles: TreeNode[] = [];
      for (const child of host.children) {
        const parts = child.name.split('/').filter(Boolean);
        if (parts.length > 1) {
          const dir = '/' + parts[0];
          if (!dirGroups.has(dir)) dirGroups.set(dir, []);
          dirGroups.get(dir)!.push(child);
        } else { rootFiles.push(child); }
      }

      for (const file of rootFiles) {
        const fId = nodeId('N', idCounter++);
        const label = truncate(sanitize(file.name || '/'), 35);
        const method = file.method || 'GET';
        const status = file.status || 200;
        lines.push(`    ${hostId} -->|"${method}"| ${fId}["${label} ${status}"]`);
        styles.push(`    style ${fId} ${methodStyle(method)}`);
      }

      for (const [dir, files] of dirGroups) {
        const dId = nodeId('D', idCounter++);
        const dirLabel = truncate(sanitize(dir), 25);
        lines.push(`    ${hostId} --> ${dId}["${dirLabel} ${files.length}f"]`);
        styles.push(`    style ${dId} fill:#252525,stroke:#6e6e6e,color:#a0a0a0`);

        for (const file of files) {
          const fId = nodeId('N', idCounter++);
          const parts = file.name.split('/').filter(Boolean);
          const shortName = parts.slice(1).join('/');
          const label = truncate(sanitize(shortName || file.name), 30);
          const method = file.method || 'GET';
          const status = file.status || 200;
          lines.push(`    ${dId} -->|"${method}"| ${fId}["${label} ${status}"]`);
          styles.push(`    style ${fId} ${methodStyle(method)}`);
        }
      }
    }
  }
  lines.push('');
  lines.push(...styles);
  return lines.join('\n');
}

mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  themeVariables: {
    darkMode: true,
    background: '#0d0d0d',
    primaryColor: '#1a1a2e',
    primaryTextColor: '#e0e0e0',
    primaryBorderColor: '#e8a145',
    lineColor: '#505050',
    secondaryColor: '#252525',
    tertiaryColor: '#1a3a2a',
    fontSize: '11px',
    fontFamily: "'JetBrains Mono', monospace",
  },
  flowchart: { curve: 'basis', padding: 16, nodeSpacing: 20, rankSpacing: 60, htmlLabels: true, wrappingWidth: 200 },
  securityLevel: 'loose',
});

export function MermaidView({ tree }: MermaidViewProps) {
  const [copied, setCopied] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [viewMode, setViewMode] = useState<'diagram' | 'code'>('diagram');
  const [svgHtml, setSvgHtml] = useState<string>('');
  const [renderError, setRenderError] = useState<string>('');
  const svgContainerRef = useRef<HTMLDivElement>(null);
  const [isPanning, setIsPanning] = useState(false);
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  const panStart = useRef({ x: 0, y: 0, ox: 0, oy: 0 });

  const mermaidCode = useMemo(() => generateMermaid(tree), [tree]);

  useEffect(() => {
    if (viewMode !== 'diagram') return;
    let cancelled = false;
    const timeout = setTimeout(async () => {
      try {
        const id = `mermaid-${Date.now()}`;
        const { svg } = await mermaid.render(id, mermaidCode);
        if (!cancelled) { setSvgHtml(svg); setRenderError(''); }
        const orphan = document.getElementById(id);
        if (orphan?.parentElement?.tagName === 'BODY') orphan.parentElement.removeChild(orphan);
      } catch (err: any) {
        if (!cancelled) { setRenderError(String(err?.message || err)); setSvgHtml(''); }
      }
    }, 300);
    return () => { cancelled = true; clearTimeout(timeout); };
  }, [mermaidCode, viewMode]);

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(mermaidCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [mermaidCode]);

  const handleExport = useCallback(async (format: 'md' | 'mmd' | 'svg' | 'png') => {
    try {
      const { save } = await import('@tauri-apps/plugin-dialog');
      const { invoke } = await import('@tauri-apps/api/core');
      const filterMap: Record<string, { name: string; extensions: string[] }[]> = {
        md: [{ name: 'Markdown', extensions: ['md'] }],
        mmd: [{ name: 'Mermaid', extensions: ['mmd'] }],
        svg: [{ name: 'SVG Image', extensions: ['svg'] }],
        png: [{ name: 'PNG Image', extensions: ['png'] }],
      };
      const filePath = await save({ title: `Export Sitemap as .${format}`, defaultPath: `sitemap-export.${format}`, filters: filterMap[format] });
      if (!filePath) return; // User cancelled

      if (format === 'svg' && svgHtml) {
        await invoke('save_file_text', { path: filePath, content: svgHtml });
      } else if (format === 'png' && svgContainerRef.current) {
        const svgEl = svgContainerRef.current.querySelector('svg');
        if (!svgEl) return;
        const canvas = document.createElement('canvas');
        const rect = svgEl.getBoundingClientRect();
        canvas.width = rect.width * 2; canvas.height = rect.height * 2;
        const ctx = canvas.getContext('2d')!;
        ctx.scale(2, 2);
        const serialized = new XMLSerializer().serializeToString(svgEl);
        const img = new window.Image();
        await new Promise<void>((resolve, reject) => {
          img.onload = () => { ctx.drawImage(img, 0, 0); resolve(); };
          img.onerror = reject;
          img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(serialized)));
        });
        const dataUrl = canvas.toDataURL('image/png');
        const base64 = dataUrl.split(',')[1];
        await invoke('save_file_bytes', { path: filePath, dataBase64: base64 });
      } else {
        const content = format === 'md' ? `\`\`\`mermaid\n${mermaidCode}\n\`\`\`` : mermaidCode;
        await invoke('save_file_text', { path: filePath, content });
      }
    } catch (err) {
      console.error('Export failed:', err);
    }
  }, [mermaidCode, svgHtml]);

  const handleZoomIn = () => setZoom(z => Math.min(z + 0.2, 3));
  const handleZoomOut = () => setZoom(z => Math.max(z - 0.2, 0.3));
  const handleZoomReset = () => { setZoom(1); setPanOffset({ x: 0, y: 0 }); };

  const onMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsPanning(true);
    panStart.current = { x: e.clientX, y: e.clientY, ox: panOffset.x, oy: panOffset.y };
  };
  const onMouseMove = (e: React.MouseEvent) => {
    if (!isPanning) return;
    setPanOffset({ x: panStart.current.ox + (e.clientX - panStart.current.x), y: panStart.current.oy + (e.clientY - panStart.current.y) });
  };
  const onMouseUp = () => setIsPanning(false);

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    setZoom(z => Math.max(0.3, Math.min(3, z + (e.deltaY > 0 ? -0.1 : 0.1))));
  };

  const hostCount = tree.length;
  const endpointCount = tree.reduce((sum, h) => sum + (h.children?.length || 0), 0);

  return (
    <div className="mermaid-view">
      {/* Stats + toolbar */}
      <div className="mermaid-toolbar">
        <div className="mermaid-stats">
          <div className="mermaid-stat"><span className="mermaid-stat-value">{hostCount}</span><span className="mermaid-stat-label">Hosts</span></div>
          <div className="mermaid-stat"><span className="mermaid-stat-value">{endpointCount}</span><span className="mermaid-stat-label">Endpoints</span></div>
          <div className="mermaid-stat"><span className="mermaid-stat-value">{mermaidCode.split('\n').length}</span><span className="mermaid-stat-label">Lines</span></div>
        </div>
        <div style={{ flex: 1 }} />

        {/* View toggle */}
        <div className="mermaid-view-toggle">
          <button className={viewMode === 'diagram' ? 'active' : ''} onClick={() => setViewMode('diagram')}><Eye size={11} /> Diagram</button>
          <button className={viewMode === 'code' ? 'active' : ''} onClick={() => setViewMode('code')}><Code size={11} /> Source</button>
        </div>

        <div className="mermaid-sep" />

        {/* Zoom */}
        <button className="mermaid-action-btn" onClick={handleZoomOut}><ZoomOut size={11} /></button>
        <span className="mermaid-zoom-level">{Math.round(zoom * 100)}%</span>
        <button className="mermaid-action-btn" onClick={handleZoomIn}><ZoomIn size={11} /></button>
        <button className="mermaid-action-btn" onClick={handleZoomReset}><Maximize2 size={11} /></button>

        <div className="mermaid-sep" />

        {/* Actions */}
        <button className="mermaid-action-btn" onClick={handleCopy}>{copied ? <Check size={11} /> : <Copy size={11} />}{copied ? 'Copied!' : 'Copy'}</button>
        <button className="mermaid-action-btn" onClick={() => handleExport('svg')}><Download size={11} /> SVG</button>
        <button className="mermaid-action-btn" onClick={() => handleExport('png')}><Image size={11} /> PNG</button>
        <button className="mermaid-action-btn" onClick={() => handleExport('mmd')}><Download size={11} /> .mmd</button>
      </div>

      {/* Content area */}
      <div className="mermaid-content">
        {viewMode === 'diagram' ? (
          <div className="mermaid-diagram-wrap" onMouseDown={onMouseDown} onMouseMove={onMouseMove} onMouseUp={onMouseUp} onMouseLeave={onMouseUp} onWheel={onWheel} style={{ cursor: isPanning ? 'grabbing' : 'grab' }}>
            {renderError ? (
              <div className="mermaid-error">
                <span>Render Error</span>
                <pre>{renderError}</pre>
              </div>
            ) : svgHtml ? (
              <div ref={svgContainerRef} className="mermaid-svg-container" style={{ transform: `translate(${panOffset.x}px, ${panOffset.y}px) scale(${zoom})`, transformOrigin: 'center center' }} dangerouslySetInnerHTML={{ __html: svgHtml }} />
            ) : (
              <div className="mermaid-loading">Rendering diagram...</div>
            )}
          </div>
        ) : (
          <div className="mermaid-code-scroll" style={{ fontSize: `${11 * zoom}px` }}>
            <pre className="mermaid-code">
              {mermaidCode.split('\n').map((line, i) => (
                <div key={i} className="mermaid-code-line">
                  <span className="mermaid-line-num">{i + 1}</span>
                  <span className="mermaid-line-content">{highlightMermaid(line)}</span>
                </div>
              ))}
            </pre>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="mermaid-legend">
        <span className="mermaid-legend-title">Legend</span>
        <div className="mermaid-legend-items">
          {[['#e8a145','Host'],['#4ec58a','GET'],['#5b9fd6','POST'],['#e8873c','PUT'],['#d95757','DELETE'],['#a78bda','PATCH']].map(([c,l]) => (
            <div key={l} className="mermaid-legend-item"><span className="mermaid-legend-dot" style={{ background: c }} /><span>{l}</span></div>
          ))}
        </div>
      </div>
    </div>
  );
}

function highlightMermaid(line: string): React.ReactElement {
  if (/^\s*(graph|subgraph|end|style|classDef|class)\b/.test(line)) {
    const match = line.match(/^(\s*)(graph|subgraph|end|style|classDef|class)(.*)$/);
    if (match) return <><span>{match[1]}</span><span className="mermaid-kw">{match[2]}</span><span className="mermaid-rest">{match[3]}</span></>;
  }
  if (line.includes('-->')) {
    // String-based parser for Mermaid arrows (`A-->B` or `A-->|label|B`).
    // Intentionally not a regex: a literal `-->` pattern triggers the
    // CodeQL `js/bad-tag-filter` HTML-comment-stripping heuristic, even
    // though this code never parses HTML. The output below is identical
    // to the previous `line.split(/(-->(?:\|[^|]*\|)?)/)`-based version.
    const ARROW = '-->';
    const out: React.ReactElement[] = [];
    let start = 0;
    let key = 0;
    while (start <= line.length) {
      const idx = line.indexOf(ARROW, start);
      if (idx < 0) {
        if (start < line.length) {
          out.push(<span key={key++} className="mermaid-node-ref">{line.slice(start)}</span>);
        }
        break;
      }
      if (idx > start) {
        out.push(<span key={key++} className="mermaid-node-ref">{line.slice(start, idx)}</span>);
      }
      let arrowEnd = idx + ARROW.length;
      if (line[arrowEnd] === '|') {
        const closing = line.indexOf('|', arrowEnd + 1);
        if (closing > arrowEnd) arrowEnd = closing + 1;
      }
      out.push(<span key={key++} className="mermaid-arrow">{line.slice(idx, arrowEnd)}</span>);
      start = arrowEnd;
    }
    return <>{out}</>;
  }
  if (/^\s*style\s/.test(line)) return <span className="mermaid-style-line">{line}</span>;
  return <span>{line}</span>;
}
