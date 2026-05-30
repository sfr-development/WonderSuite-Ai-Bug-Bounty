import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import ReactDOM from 'react-dom';
import {
  ChevronRight, ChevronDown, Globe, Folder, FileCode, Palette, FileText,
  Image, Type, Zap, Film, Link, Key, ShieldOff, MessageSquare,
  Terminal, Download, Copy, Check, Settings, X, FileJson, AlignLeft, Network, Archive,
} from 'lucide-react';
import { highlight, detectHighlightLang, initHighlighter } from '../../lib/highlighter';
import { beautify, canBeautify } from '../../lib/beautify';
import type { TreeNode } from './Sitemap';
import type { AuditAsset, AuditFinding, AuditSettings, AssetType, FindingType, Severity } from './audit.types';
import { DEFAULT_SETTINGS, computeStats } from './audit.types';
import { runFinders } from './finders';
import {
  exportResultJson, exportFindingsCsv, exportApiEndpointsTxt,
  exportLinksTxt, exportAssetTree, exportHtmlReport, exportAll, saveFile,
  exportSourceConcat, exportScopedFindings, exportScopedHtml, exportDomainZip,
} from './auditExport';
import './Audit.css';

// ── Helpers ────────────────────────────────────────────────────────────

function formatSize(b: number): string {
  if (b >= 1048576) return `${(b / 1048576).toFixed(1)}M`;
  if (b >= 1024) return `${(b / 1024).toFixed(1)}K`;
  return `${b}B`;
}

const ASSET_META: Record<string, { icon: React.ReactNode; label: string; color: string }> = {
  js:    { icon: <FileCode     size={12}/>, label: 'JS',     color: '#e8a145' },
  css:   { icon: <Palette      size={12}/>, label: 'CSS',    color: '#5b9fd6' },
  html:  { icon: <FileText     size={12}/>, label: 'HTML',   color: '#e06c75' },
  image: { icon: <Image        size={12}/>, label: 'Images', color: '#4ec58a' },
  font:  { icon: <Type         size={12}/>, label: 'Fonts',  color: '#a78bda' },
  api:   { icon: <Zap          size={12}/>, label: 'API',    color: '#f7c948' },
  media: { icon: <Film         size={12}/>, label: 'Media',  color: '#56c5c5' },
  other: { icon: <FileText     size={12}/>, label: 'Other',  color: '#666'    },
};

const SEV_COLOR: Record<Severity, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#60a5fa', info: '#9ca3af',
};

const FINDING_SECTIONS: { type: FindingType; label: string; icon: React.ReactNode }[] = [
  { type: 'secret',       label: 'Secrets',       icon: <ShieldOff    size={12}/> },
  { type: 'token',        label: 'Tokens',         icon: <Key          size={12}/> },
  { type: 'api_endpoint', label: 'API Endpoints',  icon: <Terminal     size={12}/> },
  { type: 'link',         label: 'Links',           icon: <Link         size={12}/> },
  { type: 'comment',      label: 'Comments',        icon: <MessageSquare size={12}/> },
];

const SITEMAP_TYPE_MAP: Record<string, AssetType> = {
  js: 'js', css: 'css', font: 'font', image: 'image',
  api: 'api', media: 'media', file: 'html', host: 'other', dir: 'other',
};

// ── Extract AuditAssets from Sitemap tree ──────────────────────────────

function extractAssets(
  tree: TreeNode[],
  enabled: Record<AssetType, boolean>,
): AuditAsset[] {
  const seen = new Set<string>();
  const result: AuditAsset[] = [];

  for (const hostNode of tree) {
    if (hostNode.type !== 'host') continue;
    const host = hostNode.name; // e.g. "https://example.com"

    for (const child of hostNode.children || []) {
      if (child.type === 'dir' || child.type === 'host') continue;
      const assetType: AssetType = SITEMAP_TYPE_MAP[child.type] || 'other';
      if (!enabled[assetType]) continue;

      const entry = child.trafficEntries?.[0];
      const url = entry?.url || `${host}${child.name}`;
      if (seen.has(url)) continue;
      seen.add(url);

      result.push({
        id: url,
        url,
        path: child.name,
        filename: child.name.split('/').filter(Boolean).pop() || child.name,
        type: assetType,
        size: child.response_length,
        mimeType: child.mime_type,
        content: entry?.response_body || undefined,
        loadedDynamically: false,
        status: child.status,
        responseTime: child.response_time_ms,
      });
    }
  }
  return result;
}

// ── Audit tree (domain → type-group → file) ───────────────────────────

interface AuditTreeNode {
  name: string;
  kind: 'domain' | 'typeGroup' | 'file';
  color?: string;
  icon?: React.ReactNode;
  asset?: AuditAsset;
  children?: AuditTreeNode[];
}

function buildAuditTree(assets: AuditAsset[]): AuditTreeNode[] {
  const byDomain = new Map<string, AuditAsset[]>();
  for (const a of assets) {
    let domain = 'unknown';
    try { domain = new URL(a.url).hostname; } catch {}
    if (!byDomain.has(domain)) byDomain.set(domain, []);
    byDomain.get(domain)!.push(a);
  }

  return [...byDomain.entries()].map(([domain, domainAssets]) => {
    const byType = new Map<AssetType, AuditAsset[]>();
    for (const a of domainAssets) {
      if (!byType.has(a.type)) byType.set(a.type, []);
      byType.get(a.type)!.push(a);
    }
    const ORDER: AssetType[] = ['js','css','html','api','image','font','media','other'];
    const typeGroups: AuditTreeNode[] = ORDER
      .filter(t => byType.has(t))
      .map(t => {
        const meta = ASSET_META[t];
        return {
          name: `${meta.label} (${byType.get(t)!.length})`,
          kind: 'typeGroup' as const,
          color: meta.color,
          icon: meta.icon,
          children: byType.get(t)!.map(a => ({
            name: a.filename,
            kind: 'file' as const,
            color: meta.color,
            icon: meta.icon,
            asset: a,
          })),
        };
      });

    return {
      name: domain,
      kind: 'domain' as const,
      children: typeGroups,
    };
  });
}

// ── Jump target ────────────────────────────────────────────────────────

interface JumpTarget { assetUrl: string; line: number }

// ── Context menu ───────────────────────────────────────────────────────

interface CtxMenuState {
  x: number;
  y: number;
  node: AuditTreeNode;
  domain: string;
}

function AuditContextMenu({ state, assets, findings, onClose }: {
  state: CtxMenuState;
  assets: AuditAsset[];
  findings: AuditFinding[];
  onClose: () => void;
}) {
  const { node, domain } = state;

  // Collect assets scoped to this menu item
  const scopedAssets: AuditAsset[] = (() => {
    if (node.kind === 'domain')    return assets.filter(a => { try { return new URL(a.url).hostname === domain; } catch { return false; } });
    if (node.kind === 'typeGroup') return (node.children || []).map(c => c.asset!).filter(Boolean);
    if (node.kind === 'file')      return node.asset ? [node.asset] : [];
    return [];
  })();

  const scopedUrls = new Set(scopedAssets.map(a => a.url));
  const scopedFindings = findings.filter(f => scopedUrls.has(f.assetUrl));
  const label = node.kind === 'domain' ? domain : node.kind === 'typeGroup' ? `${domain} — ${node.name}` : (node.asset?.filename || node.name);

  const run = (fn: () => Promise<void>) => { fn().catch(console.error); onClose(); };

  const codeAssets = scopedAssets.filter(a => a.content && ['js','css','html','api'].includes(a.type));

  // Section title
  const title = node.kind === 'file' ? (node.asset?.filename || node.name) : node.name;

  // Portal to document.body so position:fixed is relative to the real viewport,
  // not the zoom-scaled .shell-body containing block.
  return ReactDOM.createPortal(
    <div className="audit-ctx-menu" style={{ left: state.x, top: state.y }}>
      <div className="audit-ctx-header" title={title}>{title}</div>
      <div className="audit-ctx-sep"/>

      {/* Source exports */}
      {codeAssets.length > 0 && <>
        {node.kind === 'file' && node.asset?.content && (
          <div className="audit-ctx-item" onClick={() => run(async () => {
            const { beautify: bf, canBeautify: cb } = await import('../../lib/beautify');
            const { detectHighlightLang: dl } = await import('../../lib/highlighter');
            const a = node.asset!;
            const lang = dl(a.mimeType, a.filename);
            const src = cb(lang) ? (bf(a.content!, lang) || a.content!) : a.content!;
            await saveFile(src, a.filename, a.filename.split('.').pop() || 'txt');
          })}>
            <FileCode size={12}/> Export Source (formatted)
          </div>
        )}
        {node.kind !== 'file' && (
          <div className="audit-ctx-item" onClick={() => run(async () => {
            await saveFile(exportSourceConcat(codeAssets, label), `${domain}-sources.txt`, 'txt');
          })}>
            <FileCode size={12}/> Export All Sources (concat)
          </div>
        )}
        {node.kind !== 'file' && node.kind === 'typeGroup' && (
          <div className="audit-ctx-item" onClick={() => run(async () => {
            const ext = scopedAssets[0]?.type === 'css' ? 'css' : 'js';
            await saveFile(exportSourceConcat(scopedAssets, label), `${domain}-${ext}-sources.${ext}`, ext);
          })}>
            <FileCode size={12}/> Export {node.name} Only
          </div>
        )}
        <div className="audit-ctx-sep"/>
      </>}

      {/* Findings exports */}
      {scopedFindings.length > 0 && <>
        <div className="audit-ctx-item" onClick={() => run(async () => {
          await saveFile(exportScopedHtml(scopedAssets, scopedFindings, label), `${domain}-report.html`, 'html');
        })}>
          <AlignLeft size={12}/> HTML Report {scopedFindings.length > 0 && `(${scopedFindings.length} findings)`}
        </div>
        <div className="audit-ctx-item" onClick={() => run(async () => {
          await saveFile(exportScopedFindings(scopedFindings, scopedUrls), `${domain}-findings.csv`, 'csv');
        })}>
          <FileJson size={12}/> All Findings (CSV)
        </div>
        {scopedFindings.some(f => f.type === 'secret') && (
          <div className="audit-ctx-item" onClick={() => run(async () => {
            await saveFile(exportFindingsCsv(scopedFindings.filter(f => f.type === 'secret')), `${domain}-secrets.csv`, 'csv');
          })}>
            <ShieldOff size={12}/> Secrets only (CSV)
          </div>
        )}
        {scopedFindings.some(f => f.type === 'token') && (
          <div className="audit-ctx-item" onClick={() => run(async () => {
            await saveFile(exportFindingsCsv(scopedFindings.filter(f => f.type === 'token')), `${domain}-tokens.csv`, 'csv');
          })}>
            <Key size={12}/> Tokens only (CSV)
          </div>
        )}
        {scopedFindings.some(f => f.type === 'api_endpoint') && (
          <div className="audit-ctx-item" onClick={() => run(async () => {
            await saveFile(exportApiEndpointsTxt(scopedFindings), `${domain}-apis.txt`, 'txt');
          })}>
            <Terminal size={12}/> API Endpoints (TXT)
          </div>
        )}
        {scopedFindings.some(f => f.type === 'link') && (
          <div className="audit-ctx-item" onClick={() => run(async () => {
            await saveFile(exportLinksTxt(scopedFindings), `${domain}-links.txt`, 'txt');
          })}>
            <Link size={12}/> Links (TXT)
          </div>
        )}
        <div className="audit-ctx-sep"/>
      </>}

      {/* Asset metadata */}
      {node.kind === 'domain' && (
        <div className="audit-ctx-item" onClick={() => run(async () => {
          await saveFile(JSON.stringify(scopedAssets.map(a => ({ url: a.url, type: a.type, size: a.size, status: a.status })), null, 2), `${domain}-assets.json`, 'json');
        })}>
          <FileJson size={12}/> Asset List (JSON)
        </div>
      )}

      {/* ZIP export — domain or type-group level */}
      {(node.kind === 'domain' || node.kind === 'typeGroup') && scopedAssets.length > 0 && <>
        <div className="audit-ctx-sep"/>
        <div className="audit-ctx-item" onClick={() => run(async () => {
          await exportDomainZip(scopedAssets, scopedFindings, node.kind === 'domain' ? domain : `${domain}_${node.name}`);
        })}>
          <Archive size={12}/> Export as ZIP (All Files)
        </div>
      </>}

      <div className="audit-ctx-item" onClick={() => {
        navigator.clipboard.writeText(node.kind === 'file' ? (node.asset?.url || '') : `https://${domain}`).catch(() => {});
        onClose();
      }}>
        <Copy size={12}/> Copy URL
      </div>
    </div>,
    document.body,
  );
}

// ── Tree components ────────────────────────────────────────────────────

function AuditTreeItem({ node, depth, selectedUrl, onSelect, findingCounts, onCtx, domain }: {
  node: AuditTreeNode;
  depth: number;
  selectedUrl: string;
  onSelect: (a: AuditAsset) => void;
  findingCounts: Map<string, number>;
  onCtx: (e: React.MouseEvent, node: AuditTreeNode, domain: string) => void;
  domain?: string;
}) {
  const [open, setOpen] = useState(false);
  const indent = 6 + depth * 12;

  if (node.kind === 'domain') {
    const total = (node.children || []).reduce((s, c) => s + (c.children?.length || 0), 0);
    const domainFindings = [...findingCounts.entries()]
      .filter(([url]) => { try { return new URL(url).hostname === node.name; } catch { return false; } })
      .reduce((s, [, n]) => s + n, 0);
    return (
      <>
        <div className="audit-tree-node is-folder" style={{ paddingLeft: indent }}
          onClick={() => setOpen(o => !o)}
          onContextMenu={e => { e.preventDefault(); onCtx(e, node, node.name); }}>
          <span style={{ flexShrink: 0, color: 'var(--text-3)' }}>
            {open ? <ChevronDown size={11}/> : <ChevronRight size={11}/>}
          </span>
          <Globe size={12} style={{ color: 'var(--accent)', flexShrink: 0 }}/>
          <span className="audit-tree-node-name" style={{ color: 'var(--accent)', fontWeight: 600 }}>
            {node.name}
          </span>
          <span style={{ display:'flex', gap:3, alignItems:'center', flexShrink:0 }}>
            {domainFindings > 0 && (
              <span style={{ fontSize:8, background:'rgba(239,68,68,0.2)', color:'#ef4444', padding:'0 4px', borderRadius:3, fontWeight:700 }}>
                {domainFindings}
              </span>
            )}
            <span className="audit-tree-node-size">{total}</span>
          </span>
        </div>
        {open && (node.children || []).map((c, i) => (
          <AuditTreeItem key={i} node={c} depth={depth + 1} selectedUrl={selectedUrl}
            onSelect={onSelect} findingCounts={findingCounts} onCtx={onCtx} domain={node.name}/>
        ))}
      </>
    );
  }

  if (node.kind === 'typeGroup') {
    const groupFindings = (node.children || [])
      .reduce((s, c) => s + (c.asset ? findingCounts.get(c.asset.url) || 0 : 0), 0);
    return (
      <>
        <div className="audit-tree-node is-folder" style={{ paddingLeft: indent }}
          onClick={() => setOpen(o => !o)}
          onContextMenu={e => { e.preventDefault(); onCtx(e, node, domain || ''); }}>
          <span style={{ flexShrink: 0, color: 'var(--text-3)' }}>
            {open ? <ChevronDown size={11}/> : <ChevronRight size={11}/>}
          </span>
          <span style={{ color: node.color, flexShrink: 0, display: 'flex' }}>{node.icon}</span>
          <span className="audit-tree-node-name">{node.name}</span>
          {groupFindings > 0 && (
            <span style={{ fontSize:8, background:'rgba(239,68,68,0.2)', color:'#ef4444', padding:'0 4px', borderRadius:3, fontWeight:700, flexShrink:0 }}>
              {groupFindings}
            </span>
          )}
        </div>
        {open && (node.children || []).map((c, i) => (
          <AuditTreeItem key={i} node={c} depth={depth + 1} selectedUrl={selectedUrl}
            onSelect={onSelect} findingCounts={findingCounts} onCtx={onCtx} domain={domain}/>
        ))}
      </>
    );
  }

  // File
  const a = node.asset!;
  const fc = findingCounts.get(a.url) || 0;
  return (
    <div className={`audit-tree-node ${selectedUrl === a.url ? 'active' : ''}`}
      style={{ paddingLeft: indent }}
      onClick={() => onSelect(a)}
      onContextMenu={e => { e.preventDefault(); onCtx(e, node, domain || ''); }}
      title={a.url}>
      <span style={{ width: 12, flexShrink: 0 }}/>
      <span style={{ color: node.color, flexShrink: 0, display: 'flex' }}>{node.icon}</span>
      <span className="audit-tree-node-name">{node.name}</span>
      <span style={{ display:'flex', gap:3, alignItems:'center', flexShrink:0 }}>
        {fc > 0 && (
          <span style={{ fontSize:8, background:'rgba(239,68,68,0.2)', color:'#ef4444', padding:'0 4px', borderRadius:3, fontWeight:700 }}>
            {fc}
          </span>
        )}
        {!!a.size && a.size > 0 && <span className="audit-tree-node-size">{formatSize(a.size)}</span>}
      </span>
    </div>
  );
}

// ── Code pane ──────────────────────────────────────────────────────────

function CodePane({ code, mime, path, jumpTarget, onReady }: {
  code: string;
  mime?: string;
  path?: string;
  jumpTarget?: JumpTarget | null;
  onReady?: () => void;
}) {
  const [html, setHtml] = useState('');
  const containerRef    = useRef<HTMLDivElement>(null);
  const lang            = detectHighlightLang(mime, path);

  useEffect(() => {
    if (!code) { setHtml(''); return; }
    setHtml(''); // clear immediately — prevents jump firing on stale html
    let cancelled = false;
    (async () => {
      let source = code;
      if (canBeautify(lang)) {
        await new Promise<void>(r => setTimeout(r, 0));
        if (cancelled) return;
        try { source = beautify(code, lang) || code; } catch {}
      }
      if (cancelled) return;
      const h = await highlight(source, lang || 'plaintext');
      if (!cancelled) {
        setHtml(h);
        onReady?.(); // signal parent: "new html is ready, jump now if pending"
      }
    })();
    return () => { cancelled = true; };
  }, [code, lang]); // eslint-disable-line react-hooks/exhaustive-deps

  // Execute jump once html is populated and jumpTarget is set
  useEffect(() => {
    if (!html || !jumpTarget || !containerRef.current) return;
    const line = jumpTarget.line;
    if (line < 1) return;
    const frame = requestAnimationFrame(() => {
      if (!containerRef.current) return;
      const lineEls = containerRef.current.querySelectorAll('.line');
      const target  = lineEls[line - 1] as HTMLElement | undefined;
      if (!target) return;
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      target.classList.add('audit-line-highlight');
      setTimeout(() => target.classList.remove('audit-line-highlight'), 2500);
    });
    return () => cancelAnimationFrame(frame);
  }, [html, jumpTarget]);

  return (
    <div ref={containerRef} className="audit-editor-code shiki-output"
      dangerouslySetInnerHTML={{ __html: html || '<pre class="shiki-fallback"><code><span class="line"></span></code></pre>' }}
    />
  );
}

// ── Editor pane ────────────────────────────────────────────────────────

function EditorPane({ asset, findings, jumpTarget, onCodeReady }: {
  asset: AuditAsset | null;
  findings: AuditFinding[];
  jumpTarget?: JumpTarget | null;
  onCodeReady?: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const assetFindings = findings.filter(f => f.assetUrl === asset?.url);

  const copyCode = useCallback(async () => {
    if (!asset?.content) return;
    try {
      const lang = detectHighlightLang(asset.mimeType, asset.filename);
      const text = canBeautify(lang) ? (beautify(asset.content, lang) || asset.content) : asset.content;
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {}
  }, [asset]);

  if (!asset) {
    return (
      <div className="audit-editor">
        <div className="audit-editor-empty">
          <FileCode size={32} style={{ opacity: 0.3 }}/>
          <span>Select an asset from the tree</span>
          <small>Code is auto-formatted — click a finding to jump to that line</small>
        </div>
      </div>
    );
  }

  const meta = ASSET_META[asset.type] || ASSET_META.other;
  const lang = detectHighlightLang(asset.mimeType, asset.filename);

  return (
    <div className="audit-editor">
      <div className="audit-editor-header">
        <span style={{ color: meta.color, display:'flex', flexShrink:0 }}>{meta.icon}</span>
        <span className="audit-editor-filename">{asset.filename}</span>
        {lang && <span className="audit-editor-lang">{lang}</span>}
        {assetFindings.length > 0 && (
          <span style={{ fontSize:9, background:'rgba(239,68,68,0.2)', color:'#ef4444', padding:'1px 6px', borderRadius:3, fontWeight:700, flexShrink:0 }}>
            {assetFindings.length} findings
          </span>
        )}
        <button className="audit-editor-btn" onClick={copyCode}>
          {copied ? <Check size={11}/> : <Copy size={11}/>} {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <div className="audit-editor-body">
        {asset.type === 'image' ? (
          <div className="audit-image-preview">
            <img
              src={(() => {
                // Prefer a data-URL built from the captured response body so the
                // image renders even when the original URL is inaccessible (no proxy,
                // auth required, CSP img-src restriction, etc.).
                if (asset.content) {
                  try {
                    const mime = asset.mimeType || 'image/png';
                    // Already base64?
                    if (/^[A-Za-z0-9+/=\r\n]+$/.test(asset.content.trim())) {
                      return `data:${mime};base64,${asset.content.trim().replace(/\s/g, '')}`;
                    }
                    // Raw bytes — encode to base64
                    const bytes = new TextEncoder().encode(asset.content);
                    let bin = '';
                    bytes.forEach(b => { bin += String.fromCharCode(b); });
                    return `data:${mime};base64,${btoa(bin)}`;
                  } catch { /* fall through to URL */ }
                }
                return asset.url;
              })()}
              alt={asset.filename}
              style={{ maxWidth:'100%', maxHeight:400, objectFit:'contain', borderRadius:4 }}
              onError={e => { (e.target as HTMLImageElement).src = asset.url; }}
            />
            <div className="audit-asset-info">
              {asset.size && <span className="audit-asset-info-pill">{formatSize(asset.size)}</span>}
              {asset.mimeType && <span className="audit-asset-info-pill">{asset.mimeType}</span>}
            </div>
          </div>
        ) : asset.content ? (
          <CodePane code={asset.content} mime={asset.mimeType} path={asset.filename}
            jumpTarget={jumpTarget && jumpTarget.assetUrl === asset.url ? jumpTarget : null}
            onReady={onCodeReady}/>
        ) : (
          <div className="audit-image-preview">
            <div className="audit-asset-info" style={{ flexDirection:'column', alignItems:'center' }}>
              <span style={{ color:'var(--text-3)', fontSize:11 }}>No content captured</span>
              <span className="audit-asset-info-pill">{asset.url}</span>
              {asset.size && <span className="audit-asset-info-pill">{formatSize(asset.size)}</span>}
              {asset.status && <span className="audit-asset-info-pill">HTTP {asset.status}</span>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Findings panel ─────────────────────────────────────────────────────

function FindingRow({ f, onJump }: {
  f: AuditFinding;
  onJump: (url: string, line: number) => void;
}) {
  const filename = f.assetUrl.split('/').pop() || f.assetUrl;
  return (
    <div className="audit-finding-row" onClick={() => onJump(f.assetUrl, f.lineNumber)}
      title="Click to jump to this line">
      <div className="audit-finding-top">
        <span className={`audit-finding-badge ${f.severity}`}>{f.severity}</span>
        <span className="audit-finding-value" title={f.value}>{f.value}</span>
      </div>
      <div className="audit-finding-meta">
        <span className="audit-finding-file" title={f.assetUrl}>{filename}</span>
        <span style={{ color:'var(--accent)', fontWeight:600 }}>:{f.lineNumber}</span>
        <span style={{ margin:'0 2px' }}>·</span>
        <span className="audit-finding-pattern">{f.patternName}</span>
      </div>
    </div>
  );
}

function FindingsSection({ section, findings, onJump }: {
  section: typeof FINDING_SECTIONS[number];
  findings: AuditFinding[];
  onJump: (url: string, line: number) => void;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const items = findings.filter(f => f.type === section.type);
  if (items.length === 0) return null;

  const doExport = async () => {
    let content = '', ext = 'csv';
    if (section.type === 'api_endpoint') { content = exportApiEndpointsTxt(items); ext = 'txt'; }
    else if (section.type === 'link')    { content = exportLinksTxt(items);         ext = 'txt'; }
    else                                  { content = exportFindingsCsv(items, section.type); }
    await saveFile(content, `${section.type}.${ext}`, ext);
  };

  const sevOrder: Severity[] = ['critical','high','medium','low','info'];
  const sorted = [...items].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
  const critCount = items.filter(f => f.severity === 'critical' || f.severity === 'high').length;

  return (
    <div className="audit-findings-section">
      <div className="audit-findings-section-header" onClick={() => setCollapsed(c => !c)}>
        {collapsed ? <ChevronRight size={10}/> : <ChevronDown size={10}/>}
        <span style={{ color: section.type === 'secret' ? '#ef4444' : section.type === 'token' ? '#f97316' : 'inherit' }}>
          {section.icon}
        </span>
        <span style={{ flex:1 }}>{section.label}</span>
        {critCount > 0 && (
          <span style={{ fontSize:8, background:'rgba(239,68,68,0.2)', color:'#ef4444', padding:'1px 5px', borderRadius:3, fontWeight:700 }}>
            {critCount} ⚠
          </span>
        )}
        <span className="audit-findings-count">{items.length}</span>
        <button className="audit-findings-export-btn" onClick={e => { e.stopPropagation(); doExport(); }}>
          <Download size={9}/> Export
        </button>
      </div>
      {!collapsed && sorted.map(f => <FindingRow key={f.id} f={f} onJump={onJump}/>)}
    </div>
  );
}

function SummaryPane({ assets, findings, selectedAsset, onExport }: {
  assets: AuditAsset[];
  findings: AuditFinding[];
  selectedAsset: AuditAsset | null;
  onExport: (fmt: string) => void;
}) {
  const [fileOnly, setFileOnly] = useState(false);

  // Reset toggle when selected asset changes
  useEffect(() => { if (!selectedAsset) setFileOnly(false); }, [selectedAsset]);

  const displayAssets  = fileOnly && selectedAsset ? [selectedAsset] : assets;
  const displayFinds   = fileOnly && selectedAsset
    ? findings.filter(f => f.assetUrl === selectedAsset.url)
    : findings;

  const stats = useMemo(() => computeStats(displayAssets, displayFinds), [displayAssets, displayFinds]);

  return (
    <div className="audit-summary">

      {/* Scope selector */}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:8 }}>
        <span style={{ fontSize:10, color:'var(--text-3)', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.04em' }}>
          {fileOnly && selectedAsset ? selectedAsset.filename : 'All files'}
        </span>
        {selectedAsset && (
          <button
            onClick={() => setFileOnly(f => !f)}
            style={{
              fontSize:10, padding:'2px 8px', borderRadius:'var(--radius-s)',
              border:`1px solid ${fileOnly ? 'var(--accent)' : 'var(--border-0)'}`,
              background: fileOnly ? 'color-mix(in srgb, var(--accent) 15%, transparent)' : 'var(--bg-2)',
              color: fileOnly ? 'var(--accent)' : 'var(--text-2)',
              cursor:'pointer', fontWeight:600,
            }}>
            {fileOnly ? 'Show all files' : 'This file only'}
          </button>
        )}
      </div>

      <div className="audit-summary-title">Assets</div>
      <div className="audit-summary-grid">
        <div className="audit-summary-card">
          <span className="audit-summary-card-val">{stats.totalAssets}</span>
          <span className="audit-summary-card-lbl">Total</span>
        </div>
        <div className="audit-summary-card">
          <span className="audit-summary-card-val">{formatSize(stats.totalSize)}</span>
          <span className="audit-summary-card-lbl">Total Size</span>
        </div>
        {(Object.entries(stats.byType) as [string, number][]).filter(([,v]) => v > 0).map(([k,v]) => (
          <div key={k} className="audit-summary-card">
            <span className="audit-summary-card-val" style={{ fontSize:14 }}>{v}</span>
            <span className="audit-summary-card-lbl">{k}</span>
          </div>
        ))}
      </div>

      <div className="audit-summary-title">Findings ({displayFinds.length})</div>
      {(['critical','high','medium','low','info'] as Severity[]).map(sev => (
        <div key={sev} className="audit-sev-row">
          <span className="audit-sev-dot" style={{ background: SEV_COLOR[sev] }}/>
          <span className="audit-sev-label" style={{ textTransform:'capitalize' }}>{sev}</span>
          <span className="audit-sev-count" style={{ color: SEV_COLOR[sev] }}>
            {stats.findingsBySeverity[sev] || 0}
          </span>
        </div>
      ))}

      <div className="audit-summary-title">Export</div>
      <div className="audit-export-section">
        <div className="audit-export-row"
          style={{ background:'var(--accent)', color:'#fff', fontWeight:700 }}
          onClick={() => onExport('all')}>
          <Download size={12}/> Export All (HTML + JSON)
        </div>
        {[
          { fmt:'json',    icon:<FileJson   size={12}/>, label:'Full Data (JSON)' },
          { fmt:'html',    icon:<AlignLeft  size={12}/>, label:'HTML Report' },
          { fmt:'tree',    icon:<Folder     size={12}/>, label:'Asset Tree (TXT)' },
          { fmt:'secrets', icon:<ShieldOff  size={12}/>, label:'Secrets only (CSV)' },
          { fmt:'tokens',  icon:<Key        size={12}/>, label:'Tokens only (CSV)' },
          { fmt:'apis',    icon:<Terminal   size={12}/>, label:'API Endpoints (TXT)' },
          { fmt:'links',   icon:<Link       size={12}/>, label:'Links (TXT)' },
        ].map(({ fmt, icon, label }) => (
          <div key={fmt} className="audit-export-row" onClick={() => onExport(fmt)}>
            {icon} {label}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Settings overlay ───────────────────────────────────────────────────

function SettingsPanel({ settings, onChange, onClose }: {
  settings: AuditSettings;
  onChange: (s: AuditSettings) => void;
  onClose: () => void;
}) {
  const toggle = (group: 'enabledTypes' | 'enabledFinders', key: string) => {
    onChange({ ...settings, [group]: { ...(settings[group] as any), [key]: !(settings[group] as any)[key] } });
  };
  return (
    <div className="audit-settings-overlay" onClick={onClose}>
      <div className="audit-settings-panel" onClick={e => e.stopPropagation()}>
        <div className="audit-settings-header">
          Finder Settings
          <button className="audit-icon-btn" onClick={onClose}><X size={13}/></button>
        </div>
        <div className="audit-settings-body">
          <div className="audit-settings-section">Asset Types to Analyse</div>
          {(Object.keys(settings.enabledTypes) as Array<keyof typeof settings.enabledTypes>).map(k => (
            <div key={k} className="audit-settings-row">
              <span>{ASSET_META[k]?.label || k}</span>
              <input type="checkbox" checked={settings.enabledTypes[k]} onChange={() => toggle('enabledTypes', k)}/>
            </div>
          ))}
          <div className="audit-settings-section">Active Finders</div>
          {(Object.keys(settings.enabledFinders) as FindingType[]).map(k => (
            <div key={k} className="audit-settings-row">
              <span>{FINDING_SECTIONS.find(s => s.type === k)?.label || k}</span>
              <input type="checkbox" checked={settings.enabledFinders[k]} onChange={() => toggle('enabledFinders', k)}/>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────

export function AuditTab({ tree }: { tree: TreeNode[] }) {
  const [settings, setSettings]           = useState<AuditSettings>(DEFAULT_SETTINGS);
  const [findings, setFindings]           = useState<AuditFinding[]>([]);
  const [selectedAsset, setSelectedAsset] = useState<AuditAsset | null>(null);
  const [jumpTarget, setJumpTarget]       = useState<JumpTarget | null>(null);
  const [treeFilter, setTreeFilter]       = useState('');
  const [panelTab, setPanelTab]           = useState<'tools' | 'summary'>('tools');
  const [showSettings, setShowSettings]   = useState(false);
  const [analysing, setAnalysing]         = useState(false);
  const [ctxMenu, setCtxMenu]             = useState<CtxMenuState | null>(null);

  useEffect(() => { initHighlighter(); }, []);

  // Derive AuditAssets from the Sitemap tree (live, no scan needed)
  const assets = useMemo(
    () => extractAssets(tree, settings.enabledTypes),
    [tree, settings.enabledTypes],
  );

  // Run finders whenever assets or finder config changes (debounced).
  // IMPORTANT: beautify each asset BEFORE running finders so that finding
  // line numbers match what CodePane displays (CodePane also beautifies).
  useEffect(() => {
    if (assets.length === 0) { setFindings([]); return; }
    setAnalysing(true);
    let cancelled = false;
    const timer = setTimeout(async () => {
      const all: AuditFinding[] = [];
      for (let i = 0; i < assets.length; i++) {
        if (cancelled) return;
        const a = assets[i];
        if (!a.content) continue;

        // Beautify first — same transform CodePane applies when rendering,
        // so line N in a finding == line N the user sees in the editor.
        let src = a.content;
        const lang = detectHighlightLang(a.mimeType, a.filename);
        if (canBeautify(lang)) {
          // Yield so the UI stays responsive during heavy beautification
          await new Promise<void>(r => setTimeout(r, 0));
          if (cancelled) return;
          try { src = beautify(a.content, lang) || a.content; } catch { /* keep raw */ }
        }

        all.push(...runFinders({ ...a, content: src }, settings));
        if (i % 6 === 0) await new Promise<void>(r => setTimeout(r, 0));
      }
      if (!cancelled) { setFindings(all); setAnalysing(false); }
    }, 400);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [assets, settings.enabledFinders]);

  // Finding counts per asset URL (for tree badges)
  const findingCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set(f.assetUrl, (m.get(f.assetUrl) || 0) + 1);
    return m;
  }, [findings]);

  // Context menu open / close
  const handleCtxMenu = useCallback((e: React.MouseEvent, node: AuditTreeNode, domain: string) => {
    const vw = window.innerWidth, vh = window.innerHeight;
    const menuW = 240, menuH = 320;
    const x = Math.min(e.clientX, vw - menuW - 8);
    const y = Math.min(e.clientY, vh - menuH - 8);
    setCtxMenu({ x, y, node, domain });
  }, []);

  // Close context menu on click outside
  useEffect(() => {
    if (!ctxMenu) return;
    const close = () => setCtxMenu(null);
    window.addEventListener('mousedown', close);
    return () => window.removeEventListener('mousedown', close);
  }, [ctxMenu]);

  // Pending jump — set when clicking a finding, consumed once CodePane finishes rendering
  const pendingJump = useRef<JumpTarget | null>(null);

  // Called by CodePane when new html is ready — flush pendingJump if asset matches
  const handleCodeReady = useCallback(() => {
    if (!pendingJump.current) return;
    const j = pendingJump.current;
    pendingJump.current = null;
    // Small delay so React has painted the new html before we scroll
    setTimeout(() => setJumpTarget(j), 30);
  }, []);

  // Jump to a finding in the editor
  const handleFindingJump = useCallback((assetUrl: string, line: number) => {
    const asset = assets.find(a => a.url === assetUrl);
    if (!asset) return;
    if (selectedAsset?.url === assetUrl) {
      // Asset already loaded — CodePane won't re-render so onReady won't fire.
      // Clear the old highlight first, then set the new target directly.
      setJumpTarget(null);
      setTimeout(() => setJumpTarget({ assetUrl, line }), 20);
    } else {
      // Different asset — set pending jump, wait for CodePane onReady to fire it.
      pendingJump.current = { assetUrl, line };
      setJumpTarget(null);
      setSelectedAsset(asset);
    }
  }, [assets, selectedAsset]);

  // Export
  const handleExport = useCallback(async (fmt: string) => {
    const result = {
      targetUrl: tree[0]?.name || 'unknown', scannedAt: new Date().toISOString(),
      durationMs: 0, assets, findings, stats: computeStats(assets, findings),
    };
    switch (fmt) {
      case 'all':     await exportAll(result); break;
      case 'json':    await saveFile(exportResultJson(result), 'audit-report.json', 'json'); break;
      case 'html':    await saveFile(exportHtmlReport(result), 'audit-report.html', 'html'); break;
      case 'tree':    await saveFile(exportAssetTree(assets), 'asset-tree.txt', 'txt'); break;
      case 'secrets': await saveFile(exportFindingsCsv(findings.filter(f => f.type === 'secret')), 'secrets.csv', 'csv'); break;
      case 'tokens':  await saveFile(exportFindingsCsv(findings.filter(f => f.type === 'token')), 'tokens.csv', 'csv'); break;
      case 'apis':    await saveFile(exportApiEndpointsTxt(findings), 'api-endpoints.txt', 'txt'); break;
      case 'links':   await saveFile(exportLinksTxt(findings), 'links.txt', 'txt'); break;
    }
  }, [tree, assets, findings]);

  // Filtered assets for tree
  const filteredAssets = useMemo(() => {
    if (!treeFilter) return assets;
    const f = treeFilter.toLowerCase();
    return assets.filter(a => a.filename.toLowerCase().includes(f) || a.path.toLowerCase().includes(f));
  }, [assets, treeFilter]);

  const auditTree = useMemo(() => buildAuditTree(filteredAssets), [filteredAssets]);

  const typeKeys = Object.keys(settings.enabledTypes) as Array<keyof typeof settings.enabledTypes>;
  const critCount = findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;

  // Empty state
  const isEmpty = tree.length === 0;

  return (
    <div className="audit-tab" style={{ position: 'relative' }}>

      {/* Slim toolbar: type chips + status */}
      <div className="audit-toolbar" style={{ borderBottom:'1px solid var(--border-0)' }}>
        <div className="audit-filter-row" style={{ padding:'6px 12px' }}>
          <span className="audit-filter-label">Analyse:</span>
          {typeKeys.map(k => {
            const meta = ASSET_META[k];
            const count = assets.filter(a => a.type === k).length;
            const on = settings.enabledTypes[k];
            return (
              <div key={k} className={`audit-chip ${on ? 'on' : ''}`}
                onClick={() => setSettings(s => ({ ...s, enabledTypes: { ...s.enabledTypes, [k]: !s.enabledTypes[k] } }))}>
                <span style={{ color: on ? meta.color : 'var(--text-3)', display:'flex' }}>{meta.icon}</span>
                {meta.label}
                {count > 0 && <span style={{ opacity:0.7 }}>({count})</span>}
              </div>
            );
          })}
          <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:8 }}>
            {analysing && (
              <span style={{ fontSize:10, color:'var(--text-3)', display:'flex', alignItems:'center', gap:4 }}>
                <span style={{ width:6, height:6, borderRadius:'50%', background:'var(--accent)', display:'inline-block', animation:'audit-pulse 1s infinite' }}/>
                Analysing…
              </span>
            )}
            {!analysing && critCount > 0 && (
              <span style={{ fontSize:10, color:'#ef4444', fontWeight:700 }}>⚠ {critCount} critical/high</span>
            )}
            {!analysing && findings.length > 0 && critCount === 0 && (
              <span style={{ fontSize:10, color:'var(--text-3)' }}>{findings.length} findings</span>
            )}
            <button className={`audit-icon-btn ${showSettings ? 'active' : ''}`}
              onClick={() => setShowSettings(s => !s)} title="Finder Settings">
              <Settings size={13}/>
            </button>
          </div>
        </div>
      </div>

      {/* Body */}
      {isEmpty ? (
        <div className="audit-scan-prompt">
          <Network size={36} style={{ opacity: 0.3 }}/>
          <span>No proxy traffic yet</span>
          <small>Browse a target with the proxy enabled — assets appear here automatically</small>
        </div>
      ) : (
        <div className="audit-body">

          {/* Left: Domain → Type → File tree */}
          <div className="audit-tree">
            <div className="audit-tree-header">
              <span>Assets</span>
              <span style={{ fontWeight:400, color:'var(--accent)' }}>{assets.length}</span>
            </div>
            <input className="audit-tree-filter" placeholder="Filter…"
              value={treeFilter} onChange={e => setTreeFilter(e.target.value)}/>
            <div className="audit-tree-list">
              {auditTree.length === 0 ? (
                <div className="audit-tree-empty">
                  <span>No matching assets</span>
                </div>
              ) : auditTree.map((node, i) => (
                <AuditTreeItem key={i} node={node} depth={0}
                  selectedUrl={selectedAsset?.url || ''} onSelect={setSelectedAsset}
                  findingCounts={findingCounts} onCtx={handleCtxMenu}/>
              ))}
            </div>
            {assets.length > 0 && (
              <div className="audit-tree-export">
                <button className="audit-tree-export-btn" onClick={() => handleExport('tree')}>
                  <Download size={11}/> Export Tree
                </button>
              </div>
            )}
          </div>

          {/* Middle: Editor */}
          <EditorPane asset={selectedAsset} findings={findings} jumpTarget={jumpTarget} onCodeReady={handleCodeReady}/>

          {/* Right: Panel */}
          <div className="audit-panel">
            <div className="audit-panel-tabs">
              <button className={`audit-panel-tab ${panelTab==='tools'?'active':''}`}
                onClick={() => setPanelTab('tools')}>
                {selectedAsset
                  ? `Findings (${findings.filter(f => f.assetUrl === selectedAsset.url).length})`
                  : 'Findings'}
              </button>
              <button className={`audit-panel-tab ${panelTab==='summary'?'active':''}`}
                onClick={() => setPanelTab('summary')}>
                Summary
              </button>
            </div>
            <div className="audit-panel-body">
              {panelTab === 'tools' ? (
                // Tools = findings for the selected file only
                !selectedAsset ? (
                  <div className="audit-panel-empty">
                    <FileCode size={28} style={{ opacity:0.3 }}/>
                    <span>Select a file to see its findings</span>
                    {analysing && <small>Analysis running…</small>}
                  </div>
                ) : (() => {
                  const fileFins = findings.filter(f => f.assetUrl === selectedAsset.url);
                  return fileFins.length === 0 ? (
                    <div className="audit-panel-empty">
                      <ShieldOff size={28} style={{ opacity:0.3 }}/>
                      <span>No findings in {selectedAsset.filename}</span>
                      {!analysing && <small>This file looks clean</small>}
                    </div>
                  ) : (
                    FINDING_SECTIONS.map(section => (
                      <FindingsSection key={section.type} section={section}
                        findings={fileFins} onJump={handleFindingJump}/>
                    ))
                  );
                })()
              ) : (
                // Summary = global stats + optional file-only toggle
                <SummaryPane
                  assets={assets}
                  findings={findings}
                  selectedAsset={selectedAsset}
                  onExport={handleExport}
                />
              )}
            </div>
          </div>

        </div>
      )}

      {showSettings && (
        <SettingsPanel settings={settings} onChange={setSettings}
          onClose={() => setShowSettings(false)}/>
      )}

      {ctxMenu && (
        <div onMouseDown={e => e.stopPropagation()}>
          <AuditContextMenu
            state={ctxMenu}
            assets={assets}
            findings={findings}
            onClose={() => setCtxMenu(null)}
          />
        </div>
      )}
    </div>
  );
}
