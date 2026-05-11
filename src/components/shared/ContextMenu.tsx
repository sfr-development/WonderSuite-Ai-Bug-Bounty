import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Zap, FileJson, ArrowRightLeft, Target, PlusCircle, ListOrdered, Layers, Globe, Search, MessageSquare, Code, Link2, Activity, Network, Clock, Bug, GitCompare, Trash2, Link, TerminalSquare, Download, BookText } from 'lucide-react';
import { useAppStore } from '../../stores';
import './ContextMenu.css';

async function mcpTool(name: string, params: Record<string, any>): Promise<any> {
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke('mcp_execute_tool', { name, params });
}

export function ContextMenu() {
  const { contextMenu, closeContextMenu, sendTo, addToast, addScope, setActiveModule, deleteSitemapNode, addToBlacklist } = useAppStore();
  const menuRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<React.CSSProperties>({ top: -9999, left: -9999, opacity: 0 });
  const [subFlip, setSubFlip] = useState(false);

  useLayoutEffect(() => {
    if (!contextMenu.isOpen || !menuRef.current) return;
    const el = menuRef.current;
    const pad = 12;

    const actionsEl = el.querySelector('.context-menu-actions') as HTMLElement;
    if (actionsEl) actionsEl.style.maxHeight = 'none';

    el.style.visibility = 'hidden';
    el.style.top = '0';
    el.style.left = '0';
    el.style.maxHeight = 'none';

    requestAnimationFrame(() => {
      if (!menuRef.current) return;
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const rect = el.getBoundingClientRect();
      const menuW = rect.width;
      let menuH = rect.height;

      let x = contextMenu.x;
      let y = contextMenu.y;

      if (x + menuW > vw - pad) x = vw - menuW - pad;
      if (x < pad) x = pad;

      const spaceBelow = vh - y - pad;
      const spaceAbove = y - pad;

      if (menuH <= spaceBelow) {
      } else if (menuH <= spaceAbove) {
        y = y - menuH;
      } else {
        if (spaceBelow >= spaceAbove) {
          if (actionsEl) actionsEl.style.maxHeight = `${spaceBelow - 60}px`;
          menuH = spaceBelow;
        } else {
          y = pad;
          if (actionsEl) actionsEl.style.maxHeight = `${spaceAbove - 60}px`;
        }
      }

      if (y < pad) y = pad;
      if (y + menuH > vh - pad) {
        if (actionsEl) actionsEl.style.maxHeight = `${vh - y - pad - 60}px`;
      }

      setSubFlip(x + menuW + 200 > vw);

      el.style.visibility = '';
      setPos({ top: y, left: x, opacity: 1 });
    });
  }, [contextMenu.isOpen, contextMenu.x, contextMenu.y]);

  useEffect(() => {
    if (!contextMenu.isOpen) return;
    const handleResize = () => {
      if (menuRef.current) {
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const rect = menuRef.current.getBoundingClientRect();
        let { top, left } = rect;
        if (left + rect.width > vw - 12) left = vw - rect.width - 12;
        if (top + rect.height > vh - 12) top = vh - rect.height - 12;
        if (left < 12) left = 12;
        if (top < 12) top = 12;
        setPos(p => ({ ...p, top, left }));
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [contextMenu.isOpen]);

  useEffect(() => {
    if (!contextMenu.isOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) closeContextMenu();
    };
    const handleKey = (e: KeyboardEvent) => { if (e.key === 'Escape') closeContextMenu(); };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => { document.removeEventListener('mousedown', handleClick); document.removeEventListener('keydown', handleKey); };
  }, [contextMenu.isOpen, closeContextMenu]);

  if (!contextMenu.isOpen || !contextMenu.data) return null;
  const { method, url, requestRaw, responseRaw } = contextMenu.data;
  const subCls = subFlip ? 'context-submenu flip-left' : 'context-submenu';

  const handleAction = (tool: string, target?: 'left' | 'right') => { sendTo(tool, method, url, requestRaw, responseRaw, target); closeContextMenu(); };

  const executeAddToScope = () => {
    try { const u = new URL(url); addScope(u.hostname); addToast({ title: 'Scope Updated', message: `${u.hostname} added.`, type: 'success' }); }
    catch { addToast({ title: 'Error', message: 'Invalid URL.', type: 'error' }); }
    closeContextMenu();
  };

  const copyUrl = () => { navigator.clipboard.writeText(url); addToast({ title: 'Copied', message: 'URL copied.', type: 'success' }); closeContextMenu(); };

  const copyCurl = () => {
    const hdrs = requestRaw?.split('\n').slice(1).filter((l: string) => l.includes(':') && l.trim()).map((l: string) => `-H "${l.trim()}"`).join(' ') || '';
    navigator.clipboard.writeText(`curl -X ${method || 'GET'} "${url}" ${hdrs}`.trim());
    addToast({ title: 'Copied', message: 'cURL copied.', type: 'success' }); closeContextMenu();
  };

  const requestInBrowser = async (mode: 'wonder' | 'system') => {
    closeContextMenu();
    if (mode === 'wonder') {
      try {
        await mcpTool('browser_navigate', { action: 'navigate', url });
        addToast({ title: 'Browser', message: `WonderBrowser → ${new URL(url).hostname}`, type: 'success' });
      } catch {
        addToast({ title: 'Browser', message: 'WonderBrowser not running. Opening in system browser.', type: 'warning' });
        window.open(url, '_blank');
      }
    } else {
      window.open(url, '_blank');
      addToast({ title: 'Browser', message: 'Opened in system browser.', type: 'info' });
    }
  };

  const engagementSearch = () => {
    closeContextMenu();
    sendTo('tools', method, url, requestRaw, responseRaw);
    addToast({ title: 'Search', message: `Opening Tools → Research for ${new URL(url).hostname}`, type: 'info' });
  };

  const findComments = async () => {
    closeContextMenu();
    addToast({ title: 'Finding Comments', message: 'Crawling page...', type: 'info' });
    try {
      const result = await mcpTool('crawl_target', { target: url, extract_comments: true, extract_forms: false, extract_emails: false, max_pages: 5, max_depth: 1 });
      const comments = result?.comments || [];
      if (comments.length > 0) {
        navigator.clipboard.writeText(comments.slice(0, 50).join('\n'));
        addToast({ title: `${comments.length} Comments Found`, message: 'Copied to clipboard.', type: 'success' });
      } else { addToast({ title: 'No Comments', message: 'No HTML comments on this page.', type: 'info' }); }
    } catch { addToast({ title: 'Error', message: 'Crawl failed.', type: 'error' }); }
  };

  const findScripts = async () => {
    closeContextMenu();
    addToast({ title: 'Finding Scripts', message: 'Analyzing JS files...', type: 'info' });
    try {
      const result = await mcpTool('js_link_finder', { target: url, max_js_files: 10 });
      const endpoints = result?.endpoints || [];
      const files = result?.js_files || [];
      if (endpoints.length + files.length > 0) {
        const out = [...files.map((f: string) => `[JS] ${f}`), ...endpoints.slice(0, 40).map((e: string) => `[API] ${e}`)].join('\n');
        navigator.clipboard.writeText(out);
        addToast({ title: `${files.length} Scripts, ${endpoints.length} Endpoints`, message: 'Copied to clipboard.', type: 'success' });
      } else { addToast({ title: 'No Scripts', message: 'No JS files or endpoints found.', type: 'info' }); }
    } catch { addToast({ title: 'Error', message: 'JS analysis failed.', type: 'error' }); }
  };

  const findReferences = async () => {
    closeContextMenu();
    addToast({ title: 'Finding References', message: 'Crawling for links, forms, emails...', type: 'info' });
    try {
      const result = await mcpTool('crawl_target', { target: url, extract_comments: false, extract_forms: true, extract_emails: true, max_pages: 15, max_depth: 2 });
      const pages = result?.pages?.length || 0;
      const forms = result?.forms?.length || 0;
      const emails = result?.emails?.length || 0;
      const out = [
        ...(result?.pages || []).slice(0, 40).map((p: any) => `[PAGE] ${p.url || p}`),
        ...(result?.forms || []).map((f: any) => `[FORM] ${f.action || f}`),
        ...(result?.emails || []).map((e: string) => `[EMAIL] ${e}`),
      ].join('\n');
      navigator.clipboard.writeText(out);
      addToast({ title: 'References', message: `${pages} pages, ${forms} forms, ${emails} emails. Copied.`, type: 'success' });
    } catch { addToast({ title: 'Error', message: 'Crawl failed.', type: 'error' }); }
  };

  const analyzeTarget = async () => {
    closeContextMenu();
    addToast({ title: 'Analyzing', message: 'Tech detection + passive scan...', type: 'info' });
    try {
      const [tech, passive] = await Promise.all([
        mcpTool('tech_detect', { target: url }).catch(() => null),
        mcpTool('passive_scan', { target: url }).catch(() => null),
      ]);
      const techs = tech?.technologies?.map((t: any) => t.name || t).join(', ') || 'Unknown';
      const findings = passive?.findings?.length || 0;
      let report = `=== Analysis: ${url} ===\nTech: ${techs}\n`;
      if (tech?.server) report += `Server: ${tech.server}\n`;
      if (findings) {
        report += `\nFindings (${findings}):\n`;
        (passive.findings || []).forEach((f: any) => { report += `  [${f.severity || 'INFO'}] ${f.title || f}\n`; });
      }
      navigator.clipboard.writeText(report);
      addToast({ title: 'Analysis Done', message: `Tech: ${techs.substring(0, 50)}... ${findings} findings. Copied.`, type: 'success' });
      setActiveModule('scan');
    } catch { addToast({ title: 'Error', message: 'Analysis failed.', type: 'error' }); }
  };

  const discoverContent = async () => {
    closeContextMenu();
    addToast({ title: 'Discovering', message: 'Directory bruteforce...', type: 'info' });
    try {
      const result = await mcpTool('discover_content', { target: url, wordlist: 'common', max_concurrent: 15 });
      const found = result?.found || result?.results || [];
      if (found.length > 0) {
        navigator.clipboard.writeText(found.map((f: any) => `[${f.status || 200}] ${f.url || f.path || f}`).join('\n'));
        addToast({ title: `${found.length} Paths Found`, message: 'Copied to clipboard.', type: 'success' });
      } else { addToast({ title: 'No Content', message: 'Nothing discovered.', type: 'info' }); }
      setActiveModule('discovery');
    } catch { addToast({ title: 'Error', message: 'Discovery failed.', type: 'error' }); }
  };

  const scheduleScan = async () => {
    closeContextMenu();
    addToast({ title: 'Scanning', message: `Active scan on ${new URL(url).hostname}...`, type: 'info' });
    try {
      const result = await mcpTool('active_scan', { target: url, scan_types: ['all'], max_payloads_per_type: 10, max_concurrent: 3 });
      const vulns = result?.vulnerabilities?.length || result?.findings?.length || 0;
      addToast({ title: 'Scan Complete', message: `${vulns} vulnerabilities found.`, type: vulns > 0 ? 'warning' : 'success' });
      setActiveModule('scan');
    } catch { addToast({ title: 'Error', message: 'Scan failed.', type: 'error' }); }
  };

  const autoSetupAttack = () => { closeContextMenu(); sendTo('intruder', method, url, requestRaw, responseRaw); };

  const compareSiteMaps = async () => {
    closeContextMenu();
    addToast({ title: 'Crawling', message: `Full site map crawl...`, type: 'info' });
    try {
      const result = await mcpTool('crawl_target', { target: url, max_pages: 50, max_depth: 3, extract_comments: true, extract_forms: true, extract_emails: true });
      const pages = result?.pages?.length || 0;
      const forms = result?.forms?.length || 0;
      const emails = result?.emails?.length || 0;
      let report = `=== Site Map: ${url} ===\nPages: ${pages} | Forms: ${forms} | Emails: ${emails}\n\n`;
      if (result?.pages) report += result.pages.slice(0, 60).map((p: any) => `  ${p.url || p}`).join('\n');
      if (result?.forms?.length) report += '\n\nForms:\n' + result.forms.map((f: any) => `  [${f.method || 'GET'}] ${f.action || f}`).join('\n');
      if (result?.emails?.length) report += '\n\nEmails:\n' + result.emails.join('\n');
      navigator.clipboard.writeText(report);
      addToast({ title: 'Site Map', message: `${pages} pages, ${forms} forms, ${emails} emails. Copied.`, type: 'success' });
    } catch { addToast({ title: 'Error', message: 'Crawl failed.', type: 'error' }); }
  };

  const saveItem = () => {
    closeContextMenu();
    const content = `=== ${method||'GET'} ${url} ===\n\n--- Request ---\n${requestRaw||'(none)'}\n\n--- Response ---\n${responseRaw||'(none)'}`;
    const blob = new Blob([content], { type: 'text/plain' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = `${(() => { try { return new URL(url).hostname; } catch { return 'item'; } })()}-${Date.now()}.txt`;
    a.click(); URL.revokeObjectURL(a.href);
    addToast({ title: 'Saved', message: 'Downloaded.', type: 'success' });
  };

  return (
    <div ref={menuRef} className="context-menu" style={pos} onContextMenu={e => e.preventDefault()}>
      <div className="context-menu-header">
        <span className="context-method">{method || 'TARGET'}</span>
        <span className="context-url" title={url}>{url || 'Global Selection'}</span>
      </div>
      <div className="context-menu-actions">
        <button onClick={executeAddToScope}><PlusCircle size={13} /> Add to scope</button>
        <div className="context-menu-divider" />

        <button onClick={() => handleAction('intruder')}><Zap size={13} /> Send to Intruder</button>
        <button onClick={() => handleAction('repeater')}><ArrowRightLeft size={13} /> Send to Repeater</button>
        <button onClick={() => handleAction('sequencer')}><ListOrdered size={13} /> Send to Sequencer</button>
        <button onClick={() => handleAction('organizer')}><Layers size={13} /> Send to Organizer</button>

        <div className="context-submenu-trigger">
          <button><FileJson size={13} /> Send to Comparer</button>
          <div className={subCls}>
            <button onClick={() => handleAction('comparer', 'left')}>Send to Left (Item 1)</button>
            <button onClick={() => handleAction('comparer', 'right')}>Send to Right (Item 2)</button>
          </div>
        </div>

        <div className="context-menu-divider" />

        <div className="context-submenu-trigger">
          <button><Globe size={13} /> Request in browser</button>
          <div className={subCls}>
            <button onClick={() => requestInBrowser('wonder')}>In WonderBrowser</button>
            <button onClick={() => requestInBrowser('system')}>In system browser</button>
          </div>
        </div>

        <div className="context-submenu-trigger">
          <button><Target size={13} /> Engagement tools</button>
          <div className={subCls}>
            <button onClick={engagementSearch}><Search size={12} /> Search</button>
            <button onClick={findComments}><MessageSquare size={12} /> Find comments</button>
            <button onClick={findScripts}><Code size={12} /> Find scripts</button>
            <button onClick={findReferences}><Link2 size={12} /> Find references</button>
            <button onClick={analyzeTarget}><Activity size={12} /> Analyze target</button>
            <button onClick={discoverContent}><Network size={12} /> Discover content</button>
            <button onClick={scheduleScan}><Clock size={12} /> Schedule scan</button>
            <button onClick={autoSetupAttack}><Bug size={12} /> Auto-setup attack</button>
          </div>
        </div>

        <button onClick={compareSiteMaps}><GitCompare size={13} /> Compare site maps</button>

        <div className="context-menu-divider" />

        <button onClick={copyUrl}><Link size={13} /> Copy URL</button>
        <button onClick={copyCurl}><TerminalSquare size={13} /> Copy as cURL</button>
        <button onClick={saveItem}><Download size={13} /> Save item</button>
        <button onClick={() => { closeContextMenu(); window.open('https://portswigger.net/burp/documentation/desktop/tools/target/site-map', '_blank'); }}>
          <BookText size={13} /> Documentation
        </button>

        <div className="context-menu-divider" />
        <button onClick={() => { deleteSitemapNode(url); closeContextMenu(); addToast({ title: 'Deleted', message: 'Item removed from sitemap.', type: 'success' }); }} style={{ color: 'var(--red)' }}>
          <Trash2 size={13} /> Delete item
        </button>
        <button onClick={() => { addToBlacklist([url]); deleteSitemapNode(url); closeContextMenu(); addToast({ title: 'Blacklisted', message: 'Item blacklisted — will not reappear.', type: 'warning' }); }} style={{ color: 'var(--orange, #e8873c)' }}>
          <PlusCircle size={13} /> Blacklist item
        </button>
      </div>
    </div>
  );
}
