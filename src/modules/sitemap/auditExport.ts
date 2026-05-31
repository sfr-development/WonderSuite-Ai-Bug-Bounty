import type JSZip from 'jszip';
import type { AuditAsset, AuditFinding, AuditResult, FindingType } from './audit.types';
import { beautify, canBeautify } from '../../lib/beautify';
import { detectHighlightLang } from '../../lib/highlighter';

function formatSize(b: number): string {
  if (b >= 1048576) return `${(b / 1048576).toFixed(1)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${b} B`;
}

// ── Core save ─────────────────────────────────────────────────────────

export async function saveFile(
  content: string,
  filename: string,
  ext: string,
): Promise<boolean> {
  try {
    const { save }   = await import('@tauri-apps/plugin-dialog');
    const { invoke } = await import('@tauri-apps/api/core');
    const path = await save({
      title: `Export — ${filename}`,
      defaultPath: filename,
      filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
    });
    if (!path) return false; // user cancelled
    // Use save_file_text_any — path came from native OS dialog, no validate_path restriction.
    await invoke('save_file_text_any', { path, content });
    return true;
  } catch (err) {
    console.error('[AuditExport] save_file_text failed:', err);
    // Surface the error to the user (simple fallback)
    try {
      const blob = new Blob([content], { type: 'text/plain' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      return true;
    } catch (e2) {
      console.error('[AuditExport] browser download also failed:', e2);
      return false;
    }
  }
}

// ── JSON ──────────────────────────────────────────────────────────────

export function exportResultJson(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}

// ── Selective findings ────────────────────────────────────────────────

export function exportFindingsCsv(findings: AuditFinding[], type?: FindingType): string {
  const f = type ? findings.filter(x => x.type === type) : findings;
  const rows = f.map(x =>
    `${x.severity},${x.type},${x.patternName},"${x.value.replace(/"/g, '""')}","${x.assetUrl}",${x.lineNumber}`
  );
  return 'Severity,Type,Pattern,Value,File,Line\n' + rows.join('\n');
}

export function exportApiEndpointsTxt(findings: AuditFinding[]): string {
  return [...new Set(findings.filter(f => f.type === 'api_endpoint').map(f => f.value))].sort().join('\n');
}

export function exportLinksTxt(findings: AuditFinding[]): string {
  return [...new Set(findings.filter(f => f.type === 'link').map(f => f.value))].sort().join('\n');
}

// ── Asset tree text ───────────────────────────────────────────────────

export function exportAssetTree(assets: AuditAsset[]): string {
  const byFolder = new Map<string, AuditAsset[]>();
  for (const a of assets) {
    const folder = a.path.includes('/') ? a.path.slice(0, a.path.lastIndexOf('/')) || '/' : '/';
    if (!byFolder.has(folder)) byFolder.set(folder, []);
    byFolder.get(folder)!.push(a);
  }
  const lines: string[] = [`Asset Tree — ${assets.length} total\n`];
  for (const folder of [...byFolder.keys()].sort()) {
    lines.push(`📁 ${folder}`);
    for (const a of byFolder.get(folder)!) {
      const size = a.size ? ` (${formatSize(a.size)})` : '';
      lines.push(`  ${a.filename}${size} [${a.type}]`);
    }
  }
  return lines.join('\n');
}

// ── HTML report ───────────────────────────────────────────────────────

export function exportHtmlReport(result: AuditResult): string {
  const sev = result.stats.findingsBySeverity;
  const color: Record<string, string> = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280',
  };
  const badge = (s: string) =>
    `<span style="background:${color[s]||'#888'};color:#fff;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600">${s.toUpperCase()}</span>`;

  const grouped: Record<string, AuditFinding[]> = {};
  for (const f of result.findings) {
    (grouped[f.type] = grouped[f.type] || []).push(f);
  }

  const sections = Object.entries(grouped).map(([type, items]) => `
    <h2>${type.replace('_',' ')} (${items.length})</h2>
    <table><thead><tr><th>Severity</th><th>Value</th><th>File</th><th>Line</th></tr></thead><tbody>
    ${items.map((f,i) => `<tr style="background:${i%2?'#1e293b':'#0f172a'}">
      <td>${badge(f.severity)}</td>
      <td><code title="${f.value}">${f.value.slice(0,120)}</code></td>
      <td style="color:#94a3b8;font-size:11px">${f.assetUrl.split('/').pop() || f.assetUrl}</td>
      <td>${f.lineNumber}</td>
    </tr>`).join('')}
    </tbody></table>`).join('');

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<title>Code Audit — ${result.targetUrl}</title>
<style>
body{background:#0f172a;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:24px}
h1{color:#60a5fa}h2{text-transform:capitalize;color:#e2e8f0;border-bottom:1px solid #334155;padding-bottom:4px;margin-top:24px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px}
th{padding:6px 10px;text-align:left;color:#94a3b8;background:#1e293b}
td{padding:5px 10px}code{font-family:monospace;max-width:300px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#93c5fd}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.stat{background:#1e293b;border-radius:8px;padding:12px 20px;text-align:center}
.sv{font-size:26px;font-weight:700}.sl{font-size:11px;color:#94a3b8}
</style></head><body>
<h1>Code Audit Report</h1>
<p style="color:#94a3b8">Target: <code style="color:#60a5fa">${result.targetUrl}</code> &nbsp;|&nbsp; ${new Date(result.scannedAt).toLocaleString()}</p>
<div class="stats">
  <div class="stat"><div class="sv" style="color:#60a5fa">${result.stats.totalAssets}</div><div class="sl">Assets</div></div>
  <div class="stat"><div class="sv" style="color:#ef4444">${sev.critical||0}</div><div class="sl">Critical</div></div>
  <div class="stat"><div class="sv" style="color:#f97316">${sev.high||0}</div><div class="sl">High</div></div>
  <div class="stat"><div class="sv" style="color:#eab308">${sev.medium||0}</div><div class="sl">Medium</div></div>
  <div class="stat"><div class="sv" style="color:#64748b">${result.findings.length}</div><div class="sl">Total Findings</div></div>
</div>
${sections}
<p style="margin-top:24px;font-size:11px;color:#475569">Generated by WonderSuite Code Audit &bull; ${new Date().toISOString()}</p>
</body></html>`;
}

// ── Scoped exports (domain / type / file) ────────────────────────────

export function exportSourceConcat(assets: AuditAsset[], _label?: string): string {
  return assets
    .filter(a => a.content)
    .map(a => `/* ===== ${a.url} ===== */\n${a.content}`)
    .join('\n\n');
}

export function exportScopedFindings(findings: AuditFinding[], assetUrls: Set<string>): string {
  const f = findings.filter(x => assetUrls.has(x.assetUrl));
  return exportFindingsCsv(f);
}

export function exportScopedHtml(
  assets: AuditAsset[],
  findings: AuditFinding[],
  scopeLabel: string,
): string {
  const scopedFindings = findings.filter(f => assets.some(a => a.url === f.assetUrl));
  const label = scopeLabel;
  // Reuse full report renderer
  const color: Record<string, string> = {
    critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280',
  };
  const badge = (s: string) =>
    `<span style="background:${color[s]||'#888'};color:#fff;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600">${s.toUpperCase()}</span>`;

  const grouped: Record<string, AuditFinding[]> = {};
  for (const f of scopedFindings) (grouped[f.type] = grouped[f.type] || []).push(f);

  const sections = Object.entries(grouped).map(([type, items]) => `
    <h2>${type.replace('_',' ')} (${items.length})</h2>
    <table><thead><tr><th>Severity</th><th>Value</th><th>File</th><th>Line</th></tr></thead><tbody>
    ${items.map((f,i) => `<tr style="background:${i%2?'#1e293b':'#0f172a'}">
      <td>${badge(f.severity)}</td>
      <td><code title="${f.value}">${f.value.slice(0,120)}</code></td>
      <td style="color:#94a3b8;font-size:11px">${f.assetUrl.split('/').pop()||f.assetUrl}</td>
      <td>${f.lineNumber}</td>
    </tr>`).join('')}
    </tbody></table>`).join('');

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<title>Audit — ${label}</title>
<style>body{background:#0f172a;color:#e2e8f0;font-family:-apple-system,sans-serif;margin:0;padding:24px}
h1{color:#60a5fa}h2{text-transform:capitalize;border-bottom:1px solid #334155;padding-bottom:4px;margin-top:24px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px}
th{padding:6px 10px;text-align:left;color:#94a3b8;background:#1e293b}
td{padding:5px 10px}code{font-family:monospace;max-width:300px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#93c5fd}
</style></head><body>
<h1>Code Audit — ${label}</h1>
<p style="color:#94a3b8">${assets.length} assets &nbsp;|&nbsp; ${scopedFindings.length} findings &nbsp;|&nbsp; ${new Date().toLocaleString()}</p>
${sections}
<p style="margin-top:24px;font-size:11px;color:#475569">Generated by WonderSuite Code Audit</p>
</body></html>`;
}

// ── ZIP export ────────────────────────────────────────────────────────

/** Derive proper file extension for an asset. */
function assetExtension(a: AuditAsset): string {
  // Already has extension
  const name = a.filename || '';
  const dotIdx = name.lastIndexOf('.');
  if (dotIdx > 0 && dotIdx < name.length - 1) return '';
  // Derive from type / mime
  if (a.type === 'js')   return '.js';
  if (a.type === 'css')  return '.css';
  if (a.type === 'html') return '.html';
  if (a.type === 'font') {
    const ext = (a.mimeType || '').includes('woff2') ? '.woff2' : a.mimeType?.includes('woff') ? '.woff' : '.ttf';
    return ext;
  }
  if (a.type === 'image') {
    if (a.mimeType?.includes('svg'))  return '.svg';
    if (a.mimeType?.includes('png'))  return '.png';
    if (a.mimeType?.includes('jpeg') || a.mimeType?.includes('jpg')) return '.jpg';
    if (a.mimeType?.includes('gif'))  return '.gif';
    if (a.mimeType?.includes('webp')) return '.webp';
    if (a.mimeType?.includes('ico'))  return '.ico';
    return '.img';
  }
  if (a.mimeType?.includes('json')) return '.json';
  if (a.mimeType?.includes('xml'))  return '.xml';
  return '.txt';
}

/** Deduplicate filenames within the same folder. */
function dedupeFilename(used: Set<string>, base: string): string {
  if (!used.has(base)) { used.add(base); return base; }
  const dot = base.lastIndexOf('.');
  const stem = dot > 0 ? base.slice(0, dot) : base;
  const ext  = dot > 0 ? base.slice(dot)    : '';
  let i = 2;
  while (used.has(`${stem}_${i}${ext}`)) i++;
  const name = `${stem}_${i}${ext}`;
  used.add(name);
  return name;
}

export async function exportDomainZip(
  assets: AuditAsset[],
  findings: AuditFinding[],
  label: string,
): Promise<void> {
  const JSZip = (await import('jszip')).default;
  const zip   = new JSZip();

  const slug = label.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_').slice(0, 60);
  const root = zip.folder(slug)!;

  // ── Asset folders ──────────────────────────────────────────────────
  const folderFor: Record<string, JSZip> = {
    js:    root.folder('js')!,
    css:   root.folder('css')!,
    html:  root.folder('html')!,
    api:   root.folder('api')!,
    other: root.folder('other')!,
  } as Record<string, JSZip>;

  const imageUrls:  string[] = [];
  const fontUrls:   string[] = [];
  const usedNames: Record<string, Set<string>> = {};
  for (const k of Object.keys(folderFor)) usedNames[k] = new Set();

  for (const a of assets) {
    // Images / fonts: save URL reference (binary not available from proxy text storage)
    if (a.type === 'image') { imageUrls.push(a.url); continue; }
    if (a.type === 'font')  { fontUrls.push(a.url);  continue; }

    const folder = folderFor[a.type] || folderFor.other;
    const key    = a.type in folderFor ? a.type : 'other';
    if (!(key in usedNames)) usedNames[key] = new Set();

    if (!a.content) continue;

    // Beautify text content
    let src = a.content;
    const lang = detectHighlightLang(a.mimeType, a.filename);
    if (canBeautify(lang)) {
      try { src = beautify(a.content, lang) || a.content; } catch {}
    }

    // Build filename with proper extension
    const base = (a.filename && a.filename !== 'index' ? a.filename : (
      a.path.split('/').filter(Boolean).pop() || `file`
    )) + assetExtension(a);

    const fname = dedupeFilename(usedNames[key], base);
    folder!.file(fname, src);
  }

  // Image / font URL lists
  if (imageUrls.length > 0) root.folder('images')!.file('_image_urls.txt', imageUrls.join('\n'));
  if (fontUrls.length > 0)  root.folder('fonts')!.file('_font_urls.txt', fontUrls.join('\n'));

  // ── Findings ────────────────────────────────────────────────────────
  if (findings.length > 0) {
    const ff = root.folder('findings')!;
    const cats: Array<{ type: FindingType; ext: 'csv' | 'txt' }> = [
      { type: 'secret',       ext: 'csv' },
      { type: 'token',        ext: 'csv' },
      { type: 'api_endpoint', ext: 'txt' },
      { type: 'link',         ext: 'txt' },
      { type: 'comment',      ext: 'csv' },
    ];
    for (const { type, ext } of cats) {
      const items = findings.filter(f => f.type === type);
      if (!items.length) continue;
      const content = ext === 'txt'
        ? (type === 'api_endpoint' ? exportApiEndpointsTxt(items) : exportLinksTxt(items))
        : exportFindingsCsv(items, type);
      ff.file(`${type.replace('_', '-')}.${ext}`, content);
    }
    ff.file('all-findings.csv', exportFindingsCsv(findings));
    ff.file('report.html', exportScopedHtml(assets, findings, label));
  }

  // ── Metadata ────────────────────────────────────────────────────────
  root.file('assets.json', JSON.stringify(
    assets.map(a => ({ url: a.url, path: a.path, type: a.type, size: a.size, mimeType: a.mimeType, status: a.status })),
    null, 2,
  ));

  const critCount = findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
  root.file('README.txt', [
    'WonderSuite Code Audit Export',
    '==============================',
    `Domain  : ${label}`,
    `Exported: ${new Date().toLocaleString()}`,
    '',
    'Folder structure:',
    '  js/        JavaScript files (auto-formatted)',
    '  css/       Stylesheets (auto-formatted)',
    '  html/      HTML documents',
    '  api/       API response bodies',
    '  images/    _image_urls.txt  (binary not captured by proxy)',
    '  fonts/     _font_urls.txt',
    '  findings/  secrets.csv, tokens.csv, api-endpoints.txt, links.txt, report.html',
    '  assets.json   full asset metadata',
    '',
    'Summary:',
    `  Total assets  : ${assets.length}`,
    `  Total findings: ${findings.length}`,
    `  Critical/High : ${critCount}`,
  ].join('\n'));

  // ── Download via Tauri native save dialog ────────────────────────────
  const uint8 = await zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE', compressionOptions: { level: 6 } });

  // Convert uint8array → base64 in chunks to avoid call-stack limits
  let binary = '';
  const CHUNK = 65536;
  for (let i = 0; i < uint8.length; i += CHUNK) {
    binary += String.fromCharCode(...uint8.subarray(i, i + CHUNK));
  }
  // Tauri v2 renames Rust snake_case params to camelCase → dataBase64 not data_base64
  const dataBase64 = btoa(binary);

  try {
    const { save }   = await import('@tauri-apps/plugin-dialog');
    const { invoke } = await import('@tauri-apps/api/core');
    const path = await save({
      title: `Export Audit — ${slug}`,
      defaultPath: `${slug}_audit.zip`,
      filters: [{ name: 'ZIP Archive', extensions: ['zip'] }],
    });
    if (!path) return; // user cancelled
    await invoke('save_file_bytes_any', { path, dataBase64 });
  } catch (err) {
    console.error('[AuditExport] ZIP save failed:', err);
  }
}

// ── Export All (HTML + JSON + CSV per type) ───────────────────────────

export async function exportAll(result: AuditResult): Promise<void> {
  // Try to export as HTML report (most complete single file)
  const html = exportHtmlReport(result);
  const saved = await saveFile(html, 'audit-report.html', 'html');
  if (!saved) return;

  // Also save JSON alongside it (optional secondary export)
  try {
    const { save }   = await import('@tauri-apps/plugin-dialog');
    const { invoke } = await import('@tauri-apps/api/core');
    const jsonPath = await save({
      title: 'Also save JSON data?',
      defaultPath: 'audit-report.json',
      filters: [{ name: 'JSON', extensions: ['json'] }],
    });
    if (jsonPath) await invoke('save_file_text_any', { path: jsonPath, content: exportResultJson(result) });
  } catch {}
}
