import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { ChevronRight, ChevronDown, Globe, Folder, FileText, FileCode, Palette, Type, Image, Zap, Network, ListTree, GitMerge, Code2, Download, Lock, FileJson, Table, FileType, Archive, FileEdit, Link, Trash2, Wand2, Copy, Check, PlusCircle, Ban, X } from 'lucide-react';
import { VisualMap } from './VisualMap';
import { MermaidView } from './MermaidView';
import { useAppStore } from '../../stores';
import './Sitemap.css';

export interface TrafficEntryData {
  id?: number; method: string; url: string; host: string; path: string;
  status: number; mime_type?: string; response_length?: number;
  response_time_ms?: number; tls?: boolean; request_headers?: string;
  request_body?: string; response_headers?: string; response_body?: string;
  timestamp?: string;
}

export interface TreeNode {
  name: string;
  type: 'host'|'dir'|'file'|'js'|'css'|'font'|'image'|'api'|'media';
  children?: TreeNode[];
  status?: number; method?: string; issues?: number;
  trafficEntries?: TrafficEntryData[];
  mime_type?: string; response_length?: number; response_time_ms?: number; tls?: boolean;
}

function detectType(path: string, mime?: string): TreeNode['type'] {
  const ext = path.split('?')[0].split('.').pop()?.toLowerCase() || '';
  if (['js','mjs','jsx','ts','tsx'].includes(ext) || mime?.includes('javascript')) return 'js';
  if (['css','scss','less'].includes(ext) || mime?.includes('css')) return 'css';
  if (['ttf','woff','woff2','eot','otf'].includes(ext) || mime?.includes('font')) return 'font';
  if (['png','jpg','jpeg','gif','svg','webp','ico','bmp','avif'].includes(ext) || mime?.includes('image')) return 'image';
  if (['mp4','webm','mp3','ogg','wav'].includes(ext) || mime?.includes('video') || mime?.includes('audio')) return 'media';
  if (/\/(api|v[0-9]|graphql)\b/.test(path)) return 'api';
  return 'file';
}

const TypeIcon: Record<string, typeof FileText> = {
  host: Globe, dir: Folder, file: FileText, js: FileCode,
  css: Palette, font: Type, image: Image, api: Zap, media: FileText,
};

function formatSize(b: number): string {
  if (b > 1048576) return `${(b/1048576).toFixed(1)}MB`;
  if (b > 1024) return `${(b/1024).toFixed(1)}KB`;
  return `${b}B`;
}

const mc = (m: string) => {
  const c: Record<string,string> = { GET:'#4ec58a', POST:'#5b9fd6', PUT:'#e8873c', DELETE:'#d95757', PATCH:'#a78bda', OPTIONS:'var(--text-3)', HEAD:'var(--text-2)' };
  return c[m] || 'var(--text-1)';
};

function parseHeaders(raw: string): {key:string;value:string}[] {
  return raw.split('\n').filter(l=>l.includes(':')).map(l=>{
    const i=l.indexOf(':'); return {key:l.slice(0,i).trim(),value:l.slice(i+1).trim()};
  });
}

/* ─── Syntax Highlighting ─── */
function detectLang(mime?: string, path?: string): string {
  if (mime?.includes('javascript') || mime?.includes('ecmascript') || path?.match(/\.m?jsx?$/)) return 'js';
  if (mime?.includes('css') || path?.match(/\.s?css$/)) return 'css';
  if (mime?.includes('json') || path?.match(/\.json$/)) return 'json';
  if (mime?.includes('html') || path?.match(/\.html?$/)) return 'html';
  if (mime?.includes('xml') || path?.match(/\.xml$/)) return 'xml';
  return '';
}

function highlightCode(code: string, lang: string): React.ReactElement[] {
  return code.split('\n').map((line, i) => {
    let el: React.ReactElement;
    if (lang === 'js' || lang === 'json') {
      el = <span dangerouslySetInnerHTML={{ __html: line
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/(\b(?:function|const|let|var|return|if|else|for|while|class|import|export|from|new|this|async|await|try|catch|throw|typeof|instanceof|switch|case|break|default|continue|do|in|of|yield|null|undefined|true|false|NaN|Infinity)\b)/g, '<span style="color:#c678dd">$1</span>')
        .replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)/g, '<span style="color:#98c379">$1</span>')
        .replace(/(\b\d+\.?\d*\b)/g, '<span style="color:#d19a66">$1</span>')
        .replace(/(\/\/.*$)/gm, '<span style="color:#5c6370;font-style:italic">$1</span>')
      }} />;
    } else if (lang === 'css') {
      el = <span dangerouslySetInnerHTML={{ __html: line
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/([.#]?[a-zA-Z_][\w-]*)(\s*\{)/g, '<span style="color:#e06c75">$1</span>$2')
        .replace(/(\b(?:px|em|rem|%|vh|vw|fr|s|ms|deg)\b)/g, '<span style="color:#d19a66">$1</span>')
        .replace(/(#[0-9a-fA-F]{3,8}\b)/g, '<span style="color:#98c379">$1</span>')
      }} />;
    } else if (lang === 'html' || lang === 'xml') {
      el = <span dangerouslySetInnerHTML={{ __html: line
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/(&lt;\/?\w+)/g, '<span style="color:#e06c75">$1</span>')
        .replace(/(\w+)=("[^"]*")/g, '<span style="color:#d19a66">$1</span>=<span style="color:#98c379">$2</span>')
      }} />;
    } else {
      el = <span>{line}</span>;
    }
    return <div key={i} className="sitemap-code-line"><span className="sitemap-code-num">{i+1}</span>{el}</div>;
  });
}

/* ─── Code Beautifier ─── */
function beautifyCode(code: string, lang: string): string {
  if (lang === 'json') {
    try { return JSON.stringify(JSON.parse(code), null, 2); } catch { return code; }
  }
  if (lang === 'js') {
    let result = code;
    result = result.replace(/;/g, ';\n');
    result = result.replace(/\{/g, ' {\n');
    result = result.replace(/\}/g, '\n}\n');
    result = result.replace(/,\s*/g, ',\n');
    let indent = 0; const lines = result.split('\n');
    return lines.map(l => {
      const trimmed = l.trim(); if (!trimmed) return '';
      if (trimmed.startsWith('}')) indent = Math.max(0, indent - 1);
      const out = '  '.repeat(indent) + trimmed;
      if (trimmed.endsWith('{')) indent++;
      return out;
    }).filter(l => l.trim()).join('\n');
  }
  if (lang === 'css') {
    let result = code;
    result = result.replace(/\{/g, ' {\n  ');
    result = result.replace(/\}/g, '\n}\n');
    result = result.replace(/;/g, ';\n  ');
    return result.replace(/\n\s*\n/g, '\n');
  }
  if (lang === 'html' || lang === 'xml') {
    let result = code;
    result = result.replace(/></g, '>\n<');
    let indent = 0;
    return result.split('\n').map(l => {
      const trimmed = l.trim(); if (!trimmed) return '';
      if (trimmed.startsWith('</')) indent = Math.max(0, indent - 1);
      const out = '  '.repeat(indent) + trimmed;
      if (trimmed.match(/^<[^/!][^>]*[^/]>$/) && !trimmed.match(/^<(br|hr|img|input|link|meta)\b/i)) indent++;
      return out;
    }).join('\n');
  }
  return code;
}

/* ─── Header value highlighting ─── */
const securityHeaders = ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','x-xss-protection','referrer-policy','permissions-policy','cross-origin-opener-policy','cross-origin-embedder-policy','cross-origin-resource-policy'];
const sensitiveHeaders = ['authorization','cookie','set-cookie','x-api-key','x-auth-token'];

function headerValueStyle(key: string, value: string): React.CSSProperties {
  const k = key.toLowerCase();
  if (sensitiveHeaders.includes(k)) return { color: '#e8a145', fontWeight: 600 };
  if (securityHeaders.includes(k)) return { color: '#4ec58a' };
  if (k === 'content-type') return { color: '#5b9fd6' };
  if (k === 'server' || k === 'x-powered-by') return { color: '#a78bda' };
  if (value.startsWith('https://') || value.startsWith('http://')) return { color: '#5b9fd6', textDecoration: 'underline', textDecorationColor: 'rgba(91,159,214,0.3)' };
  return {};
}

function isImageMime(mime?: string): boolean {
  return !!mime && (mime.includes('image/png') || mime.includes('image/jpeg') || mime.includes('image/gif') || mime.includes('image/svg') || mime.includes('image/webp') || mime.includes('image/bmp') || mime.includes('image/ico'));
}

function TreeItem({ node, depth, selected, onSelect, parentHost, deleteMode, onToggleDelete, markedForDelete }: {
  node: TreeNode; depth: number; selected: string; onSelect: (n:TreeNode)=>void; parentHost?: string;
  deleteMode?: boolean; onToggleDelete?: (key:string)=>void; markedForDelete?: Set<string>;
}) {
  const [open, setOpen] = useState(false);
  const { openContextMenu } = useAppStore();
  const hasChildren = node.children && node.children.length > 0;
  const Icon = TypeIcon[node.type] || FileText;
  const currentHost = node.type === 'host' ? node.name : parentHost;
  const nodeKey = node.type === 'host' ? `host::${node.name}` : `${parentHost}::${node.name}`;
  const isMarked = markedForDelete?.has(nodeKey) || false;

  const handleContextMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    const url = node.type === 'host' ? node.name : `${parentHost}${node.name === '/' ? '' : node.name}`;
    openContextMenu(e.clientX, e.clientY, {
      method: (node.method || 'GET') as string, url: url as string,
      requestRaw: node.trafficEntries?.[0]?.request_headers || `${node.method||'GET'} ${node.name} HTTP/1.1\r\nHost: target\r\n\r\n`,
      responseRaw: node.trafficEntries?.[0]?.response_headers || 'HTTP/1.1 200 OK\r\n\r\n',
      source: 'sitemap',
      // sitemap-specific delete is handled by the existing pendingDeleteUrl pipeline
    });
  };

  return (
    <>
      <div className={`sitemap-node ${selected === node.name ? 'active' : ''} ${isMarked ? 'marked-delete' : ''}`}
        style={{ paddingLeft: 8 + depth * 16 }}
        onClick={() => { if (deleteMode && onToggleDelete) { onToggleDelete(nodeKey); return; } if (hasChildren) setOpen(!open); onSelect(node); }}
        onContextMenu={handleContextMenu}
      >
        {deleteMode ? (
          <span className="sitemap-node-checkbox">
            <input type="checkbox" checked={isMarked} readOnly style={{accentColor:'var(--red)',width:12,height:12}}/>
          </span>
        ) : (
          <span className="sitemap-node-toggle">
            {hasChildren ? (open ? <ChevronDown size={12}/> : <ChevronRight size={12}/>) : <span style={{width:12}}/>}
          </span>
        )}
        <Icon size={13} className={`sitemap-node-icon ${node.type}`} />
        <span className="sitemap-node-name">{node.name}</span>
        <span className="sitemap-node-meta">
          {node.method && <span className="sitemap-node-badge" style={{color:mc(node.method)}}>{node.method}</span>}
          {node.status && <span className="sitemap-node-badge" style={{color:node.status<300?'var(--green)':node.status<400?'var(--accent)':'var(--red)'}}>{node.status}</span>}
          {node.response_length != null && node.response_length > 0 && <span style={{fontSize:9,color:'var(--text-3)'}}>{formatSize(node.response_length)}</span>}
          {node.tls && <Lock size={9} style={{color:'var(--green)',opacity:0.6}} />}
          {(node.issues||0)>0 && <span className="sitemap-node-badge" style={{background:'rgba(239,68,68,0.15)',color:'var(--red)'}}>{node.issues}</span>}
        </span>
      </div>
      {open && hasChildren && node.children!.map((child, i) => (
        <TreeItem key={`${child.name}-${i}`} node={child} depth={depth+1} selected={selected} onSelect={onSelect} parentHost={currentHost} deleteMode={deleteMode} onToggleDelete={onToggleDelete} markedForDelete={markedForDelete} />
      ))}
    </>
  );
}

function buildTreeFromTraffic(entries: any[], checkBlacklist?: (url: string) => boolean): TreeNode[] {
  const hostMap = new Map<string, TreeNode>();
  for (const entry of entries) {
    try {
      const url = new URL(entry.url || entry.host || '');
      const fullUrl = url.href;
      if (checkBlacklist && checkBlacklist(fullUrl)) continue;
      const hostKey = `${url.protocol}//${url.host}`;
      if (!hostMap.has(hostKey)) {
        hostMap.set(hostKey, { name: hostKey, type: 'host', children: [], issues: 0, tls: url.protocol === 'https:' });
      }
      const host = hostMap.get(hostKey)!;
      const path = url.pathname || '/';
      const existing = host.children?.find(c => c.name === path);
      if (existing) {
        if (!existing.trafficEntries) existing.trafficEntries = [];
        existing.trafficEntries.push(entry);
      } else {
        host.children!.push({
          name: path, type: detectType(path, entry.mime_type),
          method: entry.method || 'GET', status: entry.status || 200,
          mime_type: entry.mime_type, response_length: entry.response_length,
          response_time_ms: entry.response_time_ms, tls: entry.tls,
          trafficEntries: [entry],
        });
      }
    } catch {}
  }
  return Array.from(hostMap.values());
}

type ViewMode = 'list' | 'map' | 'mermaid';
type DetailTab = 'overview' | 'request' | 'response' | 'headers';

export function Sitemap() {
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [selected, setSelected] = useState('');
  const [selectedNode, setSelectedNode] = useState<TreeNode | null>(null);
  const [detailTab, setDetailTab] = useState<DetailTab>('overview');
  const [filter, setFilter] = useState('');
  const [viewMode, setViewMode] = useState<ViewMode>('list');
  const [showExport, setShowExport] = useState(false);
  const [deleteMode, setDeleteMode] = useState(false);
  const [markedForDelete, setMarkedForDelete] = useState<Set<string>>(new Set());
  const [formatted, setFormatted] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showBlacklist, setShowBlacklist] = useState(false);
  const { pendingDeleteUrl, clearDeleteUrl, isBlacklisted, addToBlacklist, sitemapBlacklist, removeFromBlacklist, clearBlacklist } = useAppStore();

  useEffect(() => {
    if (!pendingDeleteUrl) return;
    setTree(prev => {
      try {
        const u = new URL(pendingDeleteUrl);
        const hostKey = `${u.protocol}//${u.host}`;
        const path = u.pathname || '/';
        if (path === '/' && !u.search) {
          return prev.filter(h => h.name !== hostKey);
        }
        return prev.map(h => h.name === hostKey ? { ...h, children: h.children?.filter(c => c.name !== path) } : h);
      } catch { return prev; }
    });
    setSelectedNode(null); setSelected('');
    clearDeleteUrl();
  }, [pendingDeleteUrl, clearDeleteUrl]);

  useEffect(() => {
    if (sitemapBlacklist.size === 0) return;
    setTree(prev => {
      let changed = false;
      const next = prev.map(host => {
        const filtered = (host.children || []).filter(child => {
          const fullUrl = `${host.name}${child.name === '/' ? '' : child.name}`;
          const blocked = isBlacklisted(fullUrl);
          if (blocked) changed = true;
          return !blocked;
        });
        return filtered.length !== (host.children || []).length ? { ...host, children: filtered } : host;
      }).filter(h => (h.children?.length || 0) > 0 || !isBlacklisted(h.name + '/*'));
      return changed ? next : prev;
    });
  }, [sitemapBlacklist, isBlacklisted]);

  useEffect(() => {
    let unlisten: (()=>void)|undefined;
    let pendingEntries: any[] = [];
    let rafId = 0;

    const flushEntries = () => {
      if (pendingEntries.length === 0) return;
      const batch = pendingEntries.splice(0);
      setTree(prev => {
        const hostMap = new Map<string, TreeNode>();
        for (const h of prev) hostMap.set(h.name, { ...h, children: [...(h.children || [])] });

        for (const entry of batch) {
          try {
            const url = new URL(entry.url || entry.host || '');
            const fullUrl = url.href;
            if (isBlacklisted(fullUrl)) continue;
            const hostKey = `${url.protocol}//${url.host}`;
            let host = hostMap.get(hostKey);
            if (!host) {
              host = { name: hostKey, type: 'host', children: [], issues: 0, tls: url.protocol === 'https:' };
              hostMap.set(hostKey, host);
            }
            const path = url.pathname || '/';
            const ex = host.children?.find(c => c.name === path);
            if (ex) {
              if (!ex.trafficEntries) ex.trafficEntries = [];
              ex.trafficEntries.push(entry);
            } else {
              host.children = host.children || [];
              host.children.push({
                name: path, type: detectType(path, entry.mime_type),
                method: entry.method || 'GET', status: entry.status || 200,
                mime_type: entry.mime_type, response_length: entry.response_length,
                response_time_ms: entry.response_time_ms, tls: entry.tls,
                trafficEntries: [entry],
              });
            }
          } catch {}
        }
        return Array.from(hostMap.values());
      });
    };

    (async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const traffic = await invoke<any[]>('proxy_get_traffic');
        if (traffic?.length) setTree(buildTreeFromTraffic(traffic, isBlacklisted));
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen<any>('proxy-event', (event) => {
          if (event.payload?.type === 'traffic') {
            pendingEntries.push(event.payload.entry);
            cancelAnimationFrame(rafId);
            rafId = requestAnimationFrame(flushEntries);
          }
        });
      } catch {}
    })();
    return () => { unlisten?.(); cancelAnimationFrame(rafId); };
  }, []);

  const handleSelect = (n: TreeNode) => { setSelected(n.name); setSelectedNode(n); setFormatted(false); };
  const totalEndpoints = tree.reduce((s, h) => s + (h.children?.length || 0), 0);

  const toggleDeleteMark = useCallback((name: string) => {
    setMarkedForDelete(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  }, []);

  const deleteMarked = useCallback(() => {
    setTree(prev => prev
      .filter(h => !markedForDelete.has(`host::${h.name}`))
      .map(host => ({
        ...host,
        children: host.children?.filter(c => !markedForDelete.has(`${host.name}::${c.name}`)),
      }))
    );
    setMarkedForDelete(new Set());
    setDeleteMode(false);
    setSelectedNode(null); setSelected('');
  }, [markedForDelete]);

  const copyBody = useCallback(async (text: string) => {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch {}
  }, []);

  const filteredTree = useMemo(() => {
    if (!filter) return tree;
    const f = filter.toLowerCase();
    return tree.map(host => {
      const kids = host.children?.filter(c => c.name.toLowerCase().includes(f) || (c.method||'').toLowerCase().includes(f));
      if (host.name.toLowerCase().includes(f) || (kids && kids.length > 0)) return { ...host, children: kids };
      return null;
    }).filter(Boolean) as TreeNode[];
  }, [tree, filter]);

  const exportAs = useCallback(async (fmt: string) => {
    setShowExport(false);
    let content = ''; let filename = ''; const ext = fmt === 'urls' ? 'txt' : fmt;
    const allEntries = tree.flatMap(h => (h.children||[]).map(c => ({ host: h.name, ...c })));

    switch(fmt) {
      case 'json': {
        const jsonData = {
          exported: new Date().toISOString(),
          summary: { hosts: tree.length, endpoints: allEntries.length },
          hosts: tree.map(h => ({
            host: h.name, tls: h.tls, endpoints: (h.children || []).map(c => {
              const te = c.trafficEntries?.[0];
              return {
                path: c.name, method: c.method || 'GET', status: c.status || 200,
                mime_type: c.mime_type, response_length: c.response_length,
                response_time_ms: c.response_time_ms, type: c.type,
                request: te ? {
                  headers: te.request_headers || null,
                  body: te.request_body || null,
                } : null,
                response: te ? {
                  headers: te.response_headers || null,
                  body: te.response_body || null,
                } : null,
                traffic_entries: (c.trafficEntries || []).map((t: any) => ({
                  id: t.id, method: t.method, url: t.url, status: t.status,
                  mime_type: t.mime_type, response_length: t.response_length,
                  response_time_ms: t.response_time_ms,
                  request_headers: t.request_headers || null,
                  request_body: t.request_body || null,
                  response_headers: t.response_headers || null,
                  response_body: t.response_body || null,
                })),
              };
            }),
          })),
        };
        content = JSON.stringify(jsonData, null, 2);
        filename = `sitemap-export.json`; break;
      }
      case 'csv':
        content = 'Method,URL,Status,MIME,Size,Time\n' + allEntries.map(e =>
          `${e.method||'GET'},${e.host}${e.name},${e.status||200},${e.mime_type||''},${e.response_length||0},${e.response_time_ms||0}`
        ).join('\n');
        filename = `sitemap-export.csv`; break;
      case 'urls':
        content = allEntries.map(e => `${e.host}${e.name}`).join('\n');
        filename = `sitemap-urls.txt`; break;
      case 'md':
        content = `# Sitemap Export\n\n${tree.map(h => `## ${h.name}\n\n${(h.children||[]).map(c => `- \`${c.method||'GET'}\` ${c.name} → ${c.status||200}`).join('\n')}`).join('\n\n')}`;
        filename = `sitemap-export.md`; break;
      case 'xml':
        content = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${allEntries.map(e => `  <url><loc>${e.host}${e.name}</loc></url>`).join('\n')}\n</urlset>`;
        filename = `sitemap-export.xml`; break;
      case 'har': {
        const harEntries = allEntries.map(e => {
          const te = e.trafficEntries?.[0];
          const parseHeaders = (raw?: string) => {
            if (!raw) return [];
            return raw.split('\n').filter(l => l.includes(':')).map(l => {
              const [name, ...rest] = l.split(':');
              return { name: name.trim(), value: rest.join(':').trim() };
            });
          };
          return {
            request: {
              method: e.method || 'GET', url: `${e.host}${e.name}`,
              headers: parseHeaders(te?.request_headers),
              postData: te?.request_body ? { mimeType: 'application/json', text: te.request_body } : undefined,
            },
            response: {
              status: e.status || 200,
              headers: parseHeaders(te?.response_headers),
              content: {
                size: e.response_length || 0,
                mimeType: e.mime_type || '',
                text: te?.response_body || '',
              },
            },
            time: e.response_time_ms || 0,
          };
        });
        content = JSON.stringify({ log: { version: '1.2', entries: harEntries } }, null, 2);
        filename = `sitemap-export.har`; break;
      }
      default: return;
    }
    try {
      const { save } = await import('@tauri-apps/plugin-dialog');
      const { invoke } = await import('@tauri-apps/api/core');
      const filePath = await save({ title: `Export Sitemap as ${ext.toUpperCase()}`, defaultPath: filename, filters: [{ name: ext.toUpperCase(), extensions: [ext] }] });
      if (filePath) await invoke('save_file_text', { path: filePath, content });
    } catch (err) { console.error('Export failed:', err); }
  }, [tree]);

  const entry = selectedNode?.trafficEntries?.[0];

  return (
    <div className="sitemap">
      <div className="sitemap-tree" style={{ flex: viewMode === 'mermaid' ? 0 : (viewMode === 'map' ? 2 : 1), display: viewMode === 'mermaid' ? 'none' : 'flex' }}>
        <div className="sitemap-tree-header">
          <div style={{ display:'flex', alignItems:'center', gap:6 }}>
            <span>Site Map</span>
            <span style={{color:'var(--text-2)',fontWeight:400,textTransform:'none'}}>{totalEndpoints} endpoints</span>
          </div>
          <div style={{ display:'flex', gap:2, alignItems:'center' }}>
            <button className={`comparer-mode-btn ${viewMode==='list'?'active':''}`} onClick={()=>setViewMode('list')} title="Tree View"><ListTree size={12}/></button>
            <button className={`comparer-mode-btn ${viewMode==='map'?'active':''}`} onClick={()=>setViewMode('map')} title="Flow Map"><GitMerge size={12}/></button>
            <button className={`comparer-mode-btn ${viewMode==='mermaid'?'active':''}`} onClick={()=>setViewMode('mermaid')} title="Mermaid"><Code2 size={12}/></button>
            <button className={`comparer-mode-btn ${deleteMode?'active':''}`} onClick={()=>{setDeleteMode(!deleteMode);if(deleteMode)setMarkedForDelete(new Set());}} title="Select & Delete" style={deleteMode?{color:'var(--red)'}:{}}><Trash2 size={12}/></button>
            <div className="sitemap-export-wrap">
              <button className={`comparer-mode-btn ${showBlacklist?'active':''}`} onClick={()=>setShowBlacklist(!showBlacklist)} title="Blacklist" style={sitemapBlacklist.size>0?{color:'#e8873c'}:{}}>
                <Ban size={12}/>
                {sitemapBlacklist.size > 0 && <span style={{position:'absolute',top:-2,right:-2,background:'#e8873c',color:'#fff',fontSize:8,borderRadius:'50%',width:12,height:12,display:'flex',alignItems:'center',justifyContent:'center',fontWeight:700}}>{sitemapBlacklist.size}</span>}
              </button>
              {showBlacklist && (
                <div className="sitemap-export-dropdown" style={{minWidth:220,maxHeight:300,overflowY:'auto'}}>
                  <div className="sitemap-export-label" style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
                    Blacklisted Patterns
                    {sitemapBlacklist.size > 0 && <span style={{fontSize:9,color:'#d95757',cursor:'pointer',fontWeight:400}} onClick={()=>{clearBlacklist();setShowBlacklist(false);}}>Clear All</span>}
                  </div>
                  {sitemapBlacklist.size === 0 ? (
                    <div style={{padding:'12px 8px',fontSize:10,color:'var(--text-3)',textAlign:'center'}}>No patterns blacklisted</div>
                  ) : [...sitemapBlacklist].map((pattern, i) => (
                    <div key={i} className="sitemap-export-item" style={{display:'flex',justifyContent:'space-between',alignItems:'center',gap:6}}>
                      <span style={{fontFamily:'monospace',fontSize:10,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',flex:1}} title={pattern}>{pattern}</span>
                      <X size={10} style={{cursor:'pointer',color:'var(--text-3)',flexShrink:0}} onClick={()=>removeFromBlacklist(pattern)}/>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="sitemap-export-wrap">
              <button className="comparer-mode-btn" onClick={()=>setShowExport(!showExport)} title="Export"><Download size={12}/></button>
              {showExport && (
                <div className="sitemap-export-dropdown">
                  <div className="sitemap-export-label">Data Formats</div>
                  <div className="sitemap-export-item" onClick={()=>exportAs('json')}><FileJson size={13}/> JSON</div>
                  <div className="sitemap-export-item" onClick={()=>exportAs('csv')}><Table size={13}/> CSV</div>
                  <div className="sitemap-export-item" onClick={()=>exportAs('xml')}><FileType size={13}/> XML Sitemap</div>
                  <div className="sitemap-export-item" onClick={()=>exportAs('har')}><Archive size={13}/> HAR (HTTP Archive)</div>
                  <div className="sitemap-export-sep"/>
                  <div className="sitemap-export-label">Text Formats</div>
                  <div className="sitemap-export-item" onClick={()=>exportAs('md')}><FileEdit size={13}/> Markdown</div>
                  <div className="sitemap-export-item" onClick={()=>exportAs('urls')}><Link size={13}/> URLs (plain text)</div>
                </div>
              )}
            </div>
          </div>
        </div>
        {viewMode === 'list' ? (
          <>
            <input className="sitemap-tree-filter" placeholder="Filter..." value={filter} onChange={e=>setFilter(e.target.value)} />
            <div className="sitemap-tree-list">
              {filteredTree.length === 0 ? (
                <div style={{display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',height:'100%',color:'var(--text-3)',gap:8}}>
                  <Network size={24}/><span style={{fontSize:11}}>No sites discovered</span>
                  <span style={{fontSize:10}}>Start the proxy and browse to populate</span>
                </div>
              ) : filteredTree.map((node) => (
                <TreeItem key={node.name} node={node} depth={0} selected={selected} onSelect={handleSelect} deleteMode={deleteMode} onToggleDelete={toggleDeleteMark} markedForDelete={markedForDelete} />
              ))}
            </div>
            {deleteMode && (
              <div className="sitemap-delete-bar">
                <span style={{fontSize:10,color:'var(--text-2)'}}>{markedForDelete.size} selected</span>
                <div style={{display:'flex',gap:4}}>
                  <button className="sitemap-delete-cancel" onClick={()=>{setDeleteMode(false);setMarkedForDelete(new Set());}}>Cancel</button>
                  <button className="sitemap-delete-confirm" style={{background:'rgba(232,135,60,0.15)',color:'#e8873c',border:'1px solid rgba(232,135,60,0.3)'}} onClick={() => {
                    const urls: string[] = [];
                    markedForDelete.forEach(key => {
                      if (key.startsWith('host::')) {
                        urls.push(key.replace('host::', '') + '/*');
                      } else {
                        const [host, ...pathParts] = key.split('::');
                        urls.push(host + pathParts.join('::'));
                      }
                    });
                    addToBlacklist(urls);
                    deleteMarked();
                  }} disabled={markedForDelete.size===0}>
                    <PlusCircle size={11}/> Blacklist ({markedForDelete.size})
                  </button>
                  <button className="sitemap-delete-confirm" onClick={deleteMarked} disabled={markedForDelete.size===0}>
                    <Trash2 size={11}/> Delete ({markedForDelete.size})
                  </button>
                </div>
              </div>
            )}
          </>
        ) : viewMode === 'map' ? (
          <div style={{flex:1,position:'relative'}}><VisualMap tree={tree} onNodeSelect={handleSelect}/></div>
        ) : null}
      </div>

      {viewMode === 'mermaid' ? (
        <div style={{flex:1}}><MermaidView tree={tree}/></div>
      ) : (
        <div className="sitemap-detail" style={{flex:1}}>
          {selectedNode ? (
            <>
              <div className="sitemap-detail-header">
                <Network size={14} style={{color:'var(--accent)'}}/> 
                <span className="sitemap-detail-url">{selectedNode.name}</span>
                {selectedNode.tls && <Lock size={12} style={{color:'var(--green)'}}/>}
              </div>
              <div className="sitemap-detail-tabs">
                {(['overview','request','response','headers'] as const).map(t => (
                  <button key={t} className={`sitemap-detail-tab ${detailTab===t?'active':''}`} onClick={()=>setDetailTab(t)}>
                    {t.charAt(0).toUpperCase()+t.slice(1)}
                  </button>
                ))}
              </div>
              <div className="sitemap-detail-content">
                {detailTab === 'overview' && (
                  <div className="sitemap-overview">
                    {selectedNode.type === 'host' ? (<>
                      <div className="sitemap-overview-card"><span className="sitemap-overview-card-label">Endpoints</span><span className="sitemap-overview-card-value">{selectedNode.children?.length||0}</span></div>
                      <div className="sitemap-overview-card"><span className="sitemap-overview-card-label">TLS</span><span className="sitemap-overview-card-value">{selectedNode.tls?'Yes':'No'}</span></div>
                      <div className="sitemap-overview-card"><span className="sitemap-overview-card-label">Total Size</span><span className="sitemap-overview-card-value">{formatSize((selectedNode.children||[]).reduce((s,c)=>s+(c.response_length||0),0))}</span></div>
                    </>) : (<>
                      <div className="sitemap-overview-card"><span className="sitemap-overview-card-label">Method</span><span className="sitemap-overview-card-value" style={{color:mc(selectedNode.method||'GET')}}>{selectedNode.method||'GET'}</span></div>
                      <div className="sitemap-overview-card"><span className="sitemap-overview-card-label">Status</span><span className="sitemap-overview-card-value" style={{color:(selectedNode.status||200)<300?'var(--green)':'var(--red)'}}>{selectedNode.status||200}</span></div>
                      <div className="sitemap-overview-card"><span className="sitemap-overview-card-label">Type</span><span className="sitemap-overview-card-value">{selectedNode.type}</span></div>
                      <div className="sitemap-overview-card"><span className="sitemap-overview-card-label">MIME</span><span className="sitemap-overview-card-value" style={{fontSize:11}}>{selectedNode.mime_type||'—'}</span></div>
                      <div className="sitemap-overview-card"><span className="sitemap-overview-card-label">Size</span><span className="sitemap-overview-card-value">{selectedNode.response_length?formatSize(selectedNode.response_length):'—'}</span></div>
                      <div className="sitemap-overview-card"><span className="sitemap-overview-card-label">Time</span><span className="sitemap-overview-card-value">{selectedNode.response_time_ms?`${selectedNode.response_time_ms}ms`:'—'}</span></div>
                    </>)}
                  </div>
                )}
                {detailTab === 'request' && (
                  entry?.request_headers ? (
                    <div className="sitemap-body-view">
                      <div className="sitemap-body-toolbar">
                        <span style={{fontSize:10,color:'var(--text-3)'}}>Request</span>
                        <button className="mermaid-action-btn" onClick={()=>copyBody(entry.request_headers+(entry.request_body?'\n\n'+entry.request_body:''))}>
                          {copied?<Check size={11}/>:<Copy size={11}/>} <span>{copied?'Copied':'Copy'}</span>
                        </button>
                      </div>
                      <div className="sitemap-code-scroll">
                        {highlightCode(entry.request_headers+(entry.request_body?'\n\n'+entry.request_body:''), detectLang(entry.mime_type, selectedNode?.name))}
                      </div>
                    </div>
                  ) : <div style={{padding:20,textAlign:'center',color:'var(--text-3)',fontSize:11}}>No request data available</div>
                )}
                {detailTab === 'response' && (
                  entry?.response_headers ? (
                    <div className="sitemap-body-view">
                      <div className="sitemap-body-toolbar">
                        <span style={{fontSize:10,color:'var(--text-3)'}}>Response {entry.mime_type && `(${entry.mime_type})`}</span>
                        <div style={{display:'flex',gap:2,alignItems:'center'}}>
                          {detectLang(selectedNode?.mime_type, selectedNode?.name) && (
                            <button className="mermaid-action-btn" onClick={()=>setFormatted(!formatted)}>
                              <Wand2 size={11}/> <span>{formatted?'Raw':'Format'}</span>
                            </button>
                          )}
                          <button className="mermaid-action-btn" onClick={()=>copyBody(entry.response_headers+(entry.response_body?'\n\n'+entry.response_body:''))}>
                            {copied?<Check size={11}/>:<Copy size={11}/>} <span>{copied?'Copied':'Copy'}</span>
                          </button>
                        </div>
                      </div>
                      {/* Image preview */}
                      {isImageMime(selectedNode?.mime_type) && entry.url && (
                        <div className="sitemap-image-preview">
                          <img src={entry.url} alt="Preview" style={{maxWidth:'100%',maxHeight:300,objectFit:'contain',borderRadius:4,background:'var(--bg-2)'}} onError={(e)=>{(e.target as HTMLElement).style.display='none';}}/>
                        </div>
                      )}
                      {isImageMime(selectedNode?.mime_type) && !entry.url && entry.response_body && (
                        <div className="sitemap-image-preview">
                          <img src={(() => {
                            try {
                              if (/^[A-Za-z0-9+/=]+$/.test(entry.response_body.trim())) {
                                return `data:${selectedNode?.mime_type || 'image/png'};base64,${entry.response_body.trim()}`;
                              }
                              const bytes = new TextEncoder().encode(entry.response_body);
                              let binary = '';
                              bytes.forEach((b: number) => { binary += String.fromCharCode(b); });
                              return `data:${selectedNode?.mime_type || 'image/png'};base64,${btoa(binary)}`;
                            } catch { return ''; }
                          })()} alt="Preview" style={{maxWidth:'100%',maxHeight:300,objectFit:'contain',borderRadius:4,background:'var(--bg-2)'}} onError={(e)=>{(e.target as HTMLElement).style.display='none';}}/>
                        </div>
                      )}
                      <div className="sitemap-code-scroll">
                        {(() => {
                          const lang = detectLang(selectedNode?.mime_type, selectedNode?.name);
                          const hdrs = entry.response_headers || '';
                          let body = entry.response_body || '';
                          if (formatted && lang) body = beautifyCode(body, lang);
                          const full = hdrs + (body ? '\n\n' + body : '');
                          return highlightCode(full, lang);
                        })()}
                      </div>
                    </div>
                  ) : <div style={{padding:20,textAlign:'center',color:'var(--text-3)',fontSize:11}}>No response data available</div>
                )}
                {detailTab === 'headers' && entry ? (
                  <div>
                    <div className="sitemap-hdr-section">Request Headers</div>
                    <table className="sitemap-hdr-table"><tbody>
                      {parseHeaders(entry.request_headers||'').map((h,i)=><tr key={i}><td className="sitemap-hdr-key">{h.key}</td><td style={headerValueStyle(h.key,h.value)}>{h.value}</td></tr>)}
                    </tbody></table>
                    <div className="sitemap-hdr-section">Response Headers</div>
                    <table className="sitemap-hdr-table"><tbody>
                      {parseHeaders(entry.response_headers||'').map((h,i)=><tr key={i}><td className="sitemap-hdr-key">{h.key}</td><td style={headerValueStyle(h.key,h.value)}>{h.value}</td></tr>)}
                    </tbody></table>
                  </div>
                ) : detailTab === 'headers' && (
                  <div style={{padding:20,textAlign:'center',color:'var(--text-3)',fontSize:11}}>No header data available</div>
                )}
              </div>
            </>
          ) : (
            <div style={{flex:1,display:'flex',alignItems:'center',justifyContent:'center',color:'var(--text-3)'}}>
              <div style={{textAlign:'center'}}>
                <Network size={32} style={{marginBottom:8}}/>
                <div style={{fontSize:12}}>{tree.length===0?'Start proxy to build sitemap':'Select an endpoint from the sitemap'}</div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
