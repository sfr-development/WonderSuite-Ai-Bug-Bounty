// v0.3.16: convert a raw HTTP request (as captured by the proxy or typed
// into Repeater) into shell / Python / Node snippets so users can drop
// requests into their own scripts.
//
// We accept the raw request because that's what Repeater stores; method+
// URL are also passed because the URL is usually a full URL (the raw
// request's request-line is just the path).

interface RawRequest {
  method: string;
  url: string;
  requestRaw: string;
}

function parseRaw(raw: string): { headers: Record<string, string>; body: string } {
  const headers: Record<string, string> = {};
  if (!raw) return { headers, body: '' };
  // Split headers/body on first blank line (\r\n\r\n or \n\n).
  const sepIdx = raw.search(/\r?\n\r?\n/);
  const headBlock = sepIdx === -1 ? raw : raw.slice(0, sepIdx);
  const body = sepIdx === -1 ? '' : raw.slice(sepIdx).replace(/^\r?\n\r?\n/, '');
  const lines = headBlock.split(/\r?\n/);
  // Skip the request-line (first line, e.g. "GET / HTTP/1.1").
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(':');
    if (idx <= 0) continue;
    const name = lines[i].slice(0, idx).trim();
    const value = lines[i].slice(idx + 1).trim();
    if (name) headers[name] = value;
  }
  return { headers, body };
}

function shellEscape(s: string): string {
  // POSIX-style single-quote escape: '\'' is a literal '. Works in bash/zsh.
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export function requestToCurl(r: RawRequest): string {
  const { headers, body } = parseRaw(r.requestRaw);
  const parts: string[] = [`curl -X ${r.method}`];
  for (const [k, v] of Object.entries(headers)) {
    // Skip Host — curl derives it from the URL.
    if (k.toLowerCase() === 'host') continue;
    parts.push(`  -H ${shellEscape(`${k}: ${v}`)}`);
  }
  if (body) parts.push(`  --data-raw ${shellEscape(body)}`);
  parts.push(`  ${shellEscape(r.url)}`);
  return parts.join(' \\\n');
}

export function requestToPython(r: RawRequest): string {
  const { headers, body } = parseRaw(r.requestRaw);
  const hLines = Object.entries(headers)
    .filter(([k]) => k.toLowerCase() !== 'host' && k.toLowerCase() !== 'content-length')
    .map(([k, v]) => `    ${JSON.stringify(k)}: ${JSON.stringify(v)},`)
    .join('\n');
  const method = r.method.toLowerCase();
  const bodyArg = body
    ? body.trimStart().startsWith('{') || body.trimStart().startsWith('[')
      ? `, json=${body}`
      : `, data=${JSON.stringify(body)}`
    : '';
  return `import requests

headers = {
${hLines}
}

resp = requests.${method}(
    ${JSON.stringify(r.url)},
    headers=headers${bodyArg},
    timeout=30,
)
print(resp.status_code)
print(resp.text)
`;
}

export function requestToNode(r: RawRequest): string {
  const { headers, body } = parseRaw(r.requestRaw);
  const headerObj = Object.fromEntries(
    Object.entries(headers).filter(([k]) => k.toLowerCase() !== 'host' && k.toLowerCase() !== 'content-length')
  );
  const init: Record<string, unknown> = {
    method: r.method,
    headers: headerObj,
  };
  if (body) init.body = body;
  return `// Node 18+ has fetch built-in.
const resp = await fetch(${JSON.stringify(r.url)}, ${JSON.stringify(init, null, 2)});
console.log(resp.status);
console.log(await resp.text());
`;
}
