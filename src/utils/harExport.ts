// v0.3.16: convert WonderSuite's TrafficEntry shape to the HTTP Archive
// (HAR 1.2) format that Burp Suite / Caido / Chrome DevTools / Charles
// all read. Spec: http://www.softwareishard.com/blog/har-12-spec/
// We do not export the response body unless it's text-ish — binary blobs
// inside HAR break a lot of viewers and we'd have to base64 them anyway.

interface TrafficEntryLite {
  id: number;
  method: string;
  url: string;
  status: number;
  response_length: number;
  response_time_ms: number;
  mime_type: string;
  timestamp: string;
  request_headers: string;
  request_body: string;
  response_headers: string;
  response_body: string;
}

function parseHeaders(raw: string): Array<{ name: string; value: string }> {
  if (!raw) return [];
  // First line in raw_headers is typically the request/status line — skip if so.
  const lines = raw.split(/\r?\n/);
  const out: Array<{ name: string; value: string }> = [];
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (name && !name.includes(' ')) out.push({ name, value });
  }
  return out;
}

function isTextMime(mime: string): boolean {
  if (!mime) return false;
  const m = mime.toLowerCase();
  return m.startsWith('text/') || m.includes('json') || m.includes('xml') ||
         m.includes('javascript') || m.includes('html') || m.includes('css') ||
         m.includes('urlencoded');
}

function getQueryString(url: string): Array<{ name: string; value: string }> {
  try {
    const u = new URL(url);
    return [...u.searchParams.entries()].map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

function getHttpVersion(headers: string): string {
  const firstLine = headers.split(/\r?\n/, 1)[0] ?? '';
  const m = firstLine.match(/HTTP\/(\d(?:\.\d)?)/);
  return m ? `HTTP/${m[1]}` : 'HTTP/1.1';
}

function getCookieHeaders(headers: Array<{ name: string; value: string }>): Array<{ name: string; value: string }> {
  const cookies: Array<{ name: string; value: string }> = [];
  for (const h of headers) {
    if (h.name.toLowerCase() !== 'cookie' && h.name.toLowerCase() !== 'set-cookie') continue;
    for (const pair of h.value.split(';')) {
      const idx = pair.indexOf('=');
      if (idx <= 0) continue;
      cookies.push({ name: pair.slice(0, idx).trim(), value: pair.slice(idx + 1).trim() });
    }
  }
  return cookies;
}

export function buildHar(entries: TrafficEntryLite[], appVersion: string = ''): object {
  return {
    log: {
      version: '1.2',
      creator: {
        name: 'WonderSuite',
        version: appVersion || 'dev',
      },
      entries: entries.map((e) => {
        const reqHeaders = parseHeaders(e.request_headers);
        const respHeaders = parseHeaders(e.response_headers);
        const reqCookies = getCookieHeaders(reqHeaders);
        const respCookies = getCookieHeaders(respHeaders);
        const respMime = e.mime_type || respHeaders.find((h) => h.name.toLowerCase() === 'content-type')?.value || '';
        const bodySize = e.response_length || (e.response_body ? new TextEncoder().encode(e.response_body).length : 0);
        const headersSize = e.response_headers ? new TextEncoder().encode(e.response_headers).length : -1;

        return {
          startedDateTime: e.timestamp || new Date().toISOString(),
          time: e.response_time_ms || 0,
          request: {
            method: e.method,
            url: e.url,
            httpVersion: getHttpVersion(e.request_headers),
            cookies: reqCookies,
            headers: reqHeaders,
            queryString: getQueryString(e.url),
            postData: e.request_body
              ? {
                  mimeType: reqHeaders.find((h) => h.name.toLowerCase() === 'content-type')?.value || 'application/octet-stream',
                  text: e.request_body,
                }
              : undefined,
            headersSize: e.request_headers ? new TextEncoder().encode(e.request_headers).length : -1,
            bodySize: e.request_body ? new TextEncoder().encode(e.request_body).length : 0,
          },
          response: {
            status: e.status,
            statusText: '',
            httpVersion: getHttpVersion(e.response_headers),
            cookies: respCookies,
            headers: respHeaders,
            content: {
              size: bodySize,
              mimeType: respMime,
              text: isTextMime(respMime) ? (e.response_body || '') : '',
            },
            redirectURL: respHeaders.find((h) => h.name.toLowerCase() === 'location')?.value || '',
            headersSize,
            bodySize,
          },
          cache: {},
          timings: {
            send: 0,
            wait: e.response_time_ms || 0,
            receive: 0,
          },
        };
      }),
    },
  };
}

export function downloadHar(entries: TrafficEntryLite[], filename = `wondersuite-${Date.now()}.har`, appVersion?: string) {
  const har = buildHar(entries, appVersion);
  const blob = new Blob([JSON.stringify(har, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
