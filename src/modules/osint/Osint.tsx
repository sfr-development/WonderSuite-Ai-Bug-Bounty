import { useState, useCallback } from 'react';
import { Fingerprint, Globe, Search, Loader2, Copy, Server, Shield, Clock } from 'lucide-react';
import { useAppStore } from '../../stores';
import './Osint.css';

type Tab = 'whois' | 'dns' | 'crt' | 'wayback' | 'headers' | 'techdetect';

interface DnsRecord { type: string; value: string; ttl?: number }
interface CrtEntry { subdomain: string; issuer: string; not_after: string }
interface WaybackUrl { url: string; timestamp: string; status: string; mime: string }
interface HeaderInfo { name: string; value: string; secure: boolean; note: string }
interface TechInfo { name: string; category: string; evidence: string }

export function Osint() {
  const { addToast } = useAppStore();
  const [tab, setTab] = useState<Tab>('whois');
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);


  const [whoisResult, setWhoisResult] = useState('');


  const [dnsRecords, setDnsRecords] = useState<DnsRecord[]>([]);


  const [crtEntries, setCrtEntries] = useState<CrtEntry[]>([]);


  const [waybackUrls, setWaybackUrls] = useState<WaybackUrl[]>([]);


  const [headerInfo, setHeaderInfo] = useState<HeaderInfo[]>([]);
  const [rawHeaders, setRawHeaders] = useState('');


  const [techs, setTechs] = useState<TechInfo[]>([]);

  const copyText = (t: string) => navigator.clipboard.writeText(t);
  const domain = () => target.replace(/^https?:\/\//, '').replace(/\/.*/, '').replace(/:\d+$/, '');

  const runWhois = useCallback(async () => {
    if (!target || loading) return;
    setLoading(true); setWhoisResult('');
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const r: any = await invoke('osint_whois', { target: domain() });
      if (!r.ok) {
        setWhoisResult(`RDAP lookup failed.\nLast server: ${r.server || '(none)'}\nLast status: ${r.status}\nNote: ${r.note || '-'}\n\nTried IANA bootstrap + ARIN + Verisign + rdap.org. The TLD may not publish RDAP, or all upstream servers are unreachable from this network.`);
      } else {
        const s = r.summary || {};
        let out = '';
        if (s.domain) out += `Domain: ${s.domain}\n`;
        if (s.status) out += `Status: ${Array.isArray(s.status) ? s.status.join(', ') : s.status}\n`;
        if (s.created) out += `Created: ${s.created}\n`;
        if (s.updated) out += `Updated: ${s.updated}\n`;
        if (s.expires) out += `Expires: ${s.expires}\n`;
        if (s.name)    out += `Name:    ${s.name}\n`;
        if (s.handle)  out += `Handle:  ${s.handle}\n`;
        if (s.country) out += `Country: ${s.country}\n`;
        if (s.start_address && s.end_address) out += `Range:   ${s.start_address} - ${s.end_address}\n`;
        if (s.nameservers && s.nameservers.length) {
          out += `\nNameservers:\n`;
          for (const ns of s.nameservers) out += `  ${ns}\n`;
        }
        if (s.entities && s.entities.length) {
          out += `\nEntities:\n`;
          for (const ent of s.entities) {
            out += `  [${(ent.roles || []).join(', ')}]`;
            if (ent.name) out += ` ${ent.name}`;
            if (ent.org) out += ` (${ent.org})`;
            out += '\n';
            if (ent.email) out += `    ${ent.email}\n`;
          }
        }
        out += `\n--- via ${r.server} ---`;
        setWhoisResult(out);
      }
    } catch (e: any) { setWhoisResult(`Error: ${e?.toString?.() ?? e}`); }
    setLoading(false);
  }, [target, loading]);

  const runDns = useCallback(async () => {
    if (!target || loading) return;
    setLoading(true); setDnsRecords([]);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const records: DnsRecord[] = [];
      const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'];
      for (const type of types) {
        try {
          const url = `https://dns.google/resolve?name=${encodeURIComponent(domain())}&type=${type}`;
          const r: { body: string; status: number } = await invoke('send_http_request', { method: 'GET', url, headers: null, body: null });
          if (r.status === 200) {
            const data = JSON.parse(r.body);
            if (data.Answer) {
              for (const ans of data.Answer) {
                records.push({ type, value: ans.data, ttl: ans.TTL });
              }
            }
          }
        } catch { /* ignore individual type failures */ }
      }
      setDnsRecords(records);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [target, loading]);

  const runCrt = useCallback(async () => {
    if (!target || loading) return;
    setLoading(true); setCrtEntries([]);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const r: any = await invoke('osint_crtsh', { target: domain(), includeExpired: false });
      if (r?.entries && r.entries.length > 0) {
        const sorted = [...r.entries].sort((a: CrtEntry, b: CrtEntry) => a.subdomain.localeCompare(b.subdomain));
        setCrtEntries(sorted);
      } else if (r?.note) {
        addToast({ title: 'crt.sh', message: r.note, type: 'warning' });
        setCrtEntries([]);
      } else {
        addToast({ title: 'crt.sh', message: `No certificates for ${domain()} (${r?.total_certificates || 0} raw entries).`, type: 'info' });
        setCrtEntries([]);
      }
    } catch (e: any) {
      addToast({ title: 'crt.sh', message: `Error: ${e?.toString?.() ?? e}`, type: 'error' });
    }
    setLoading(false);
  }, [target, loading, addToast]);

  const runWayback = useCallback(async () => {
    if (!target || loading) return;
    setLoading(true); setWaybackUrls([]);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const url = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain())}/*&output=json&limit=200&fl=timestamp,original,statuscode,mimetype`;
      const r: { body: string; status: number } = await invoke('send_http_request', { method: 'GET', url, headers: null, body: null });
      if (r.status === 200) {
        try {
          const rows: string[][] = JSON.parse(r.body);
          if (rows.length > 1) {
            const urls: WaybackUrl[] = rows.slice(1).map(row => ({
              timestamp: row[0],
              url: row[1],
              status: row[2],
              mime: row[3],
            }));
            setWaybackUrls(urls);
          }
        } catch { setWaybackUrls([]); }
      }
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [target, loading]);

  const runHeaders = useCallback(async () => {
    if (!target || loading) return;
    setLoading(true); setHeaderInfo([]); setRawHeaders('');
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const url = target.startsWith('http') ? target : `https://${target}`;
      const r: { headers: string; status: number } = await invoke('send_http_request', { method: 'GET', url, headers: null, body: null });
      setRawHeaders(r.headers);

      const secHeaders: Record<string, { required: boolean; note: string }> = {
        'strict-transport-security': { required: true, note: 'Enforces HTTPS' },
        'content-security-policy': { required: true, note: 'Prevents XSS' },
        'x-frame-options': { required: true, note: 'Prevents clickjacking' },
        'x-content-type-options': { required: true, note: 'Prevents MIME sniffing' },
        'referrer-policy': { required: true, note: 'Controls referrer leakage' },
        'permissions-policy': { required: true, note: 'Controls browser features' },
        'x-xss-protection': { required: false, note: 'Legacy XSS filter' },
        'cross-origin-opener-policy': { required: false, note: 'Isolates browsing context' },
        'cross-origin-resource-policy': { required: false, note: 'Controls resource loading' },
        'cross-origin-embedder-policy': { required: false, note: 'Controls embedding' },
      };

      const parsedHeaders = new Map<string, string>();
      for (const line of r.headers.split('\n')) {
        const idx = line.indexOf(':');
        if (idx > 0) {
          parsedHeaders.set(line.slice(0, idx).trim().toLowerCase(), line.slice(idx + 1).trim());
        }
      }

      const info: HeaderInfo[] = [];
      for (const [header, meta] of Object.entries(secHeaders)) {
        const val = parsedHeaders.get(header);
        info.push({
          name: header,
          value: val || '(missing)',
          secure: !!val,
          note: meta.note,
        });
      }
      setHeaderInfo(info);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [target, loading]);

  const runTechDetect = useCallback(async () => {
    if (!target || loading) return;
    setLoading(true); setTechs([]);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const url = target.startsWith('http') ? target : `https://${target}`;
      const r: { headers: string; body: string } = await invoke('send_http_request', { method: 'GET', url, headers: null, body: null });

      const detected: TechInfo[] = [];
      const h = r.headers.toLowerCase();
      const b = r.body.toLowerCase();


      const serverLine = r.headers.split('\n').find(l => l.toLowerCase().startsWith('server:'));
      if (serverLine) detected.push({ name: serverLine.split(':')[1].trim(), category: 'Web Server', evidence: 'Server header' });


      const powered = r.headers.split('\n').find(l => l.toLowerCase().startsWith('x-powered-by:'));
      if (powered) detected.push({ name: powered.split(':')[1].trim(), category: 'Framework', evidence: 'X-Powered-By header' });


      const patterns: [RegExp, string, string, string][] = [
        [/wp-content|wordpress/i, 'WordPress', 'CMS', 'HTML body pattern'],
        [/drupal/i, 'Drupal', 'CMS', 'HTML body pattern'],
        [/joomla/i, 'Joomla', 'CMS', 'HTML body pattern'],
        [/react/i, 'React', 'JS Framework', 'HTML/JS reference'],
        [/vue\.js|vuejs/i, 'Vue.js', 'JS Framework', 'HTML/JS reference'],
        [/angular/i, 'Angular', 'JS Framework', 'HTML/JS reference'],
        [/next\.js|__next/i, 'Next.js', 'Framework', 'HTML body pattern'],
        [/nuxt/i, 'Nuxt', 'Framework', 'HTML body pattern'],
        [/jquery/i, 'jQuery', 'JS Library', 'HTML/JS reference'],
        [/bootstrap/i, 'Bootstrap', 'CSS Framework', 'HTML/CSS reference'],
        [/tailwind/i, 'Tailwind CSS', 'CSS Framework', 'HTML/CSS reference'],
        [/cloudflare/i, 'Cloudflare', 'CDN/WAF', 'Header or body'],
        [/akamai/i, 'Akamai', 'CDN', 'Header or body'],
        [/fastly/i, 'Fastly', 'CDN', 'Header or body'],
        [/nginx/i, 'Nginx', 'Web Server', 'Server header'],
        [/apache/i, 'Apache', 'Web Server', 'Server header'],
        [/php/i, 'PHP', 'Language', 'Header or body'],
        [/asp\.net/i, 'ASP.NET', 'Framework', 'Header or body'],
        [/laravel/i, 'Laravel', 'Framework', 'Body pattern'],
        [/django/i, 'Django', 'Framework', 'Body pattern'],
        [/express/i, 'Express', 'Framework', 'Header pattern'],
        [/shopify/i, 'Shopify', 'E-Commerce', 'Body pattern'],
        [/woocommerce/i, 'WooCommerce', 'E-Commerce', 'Body pattern'],
        [/google-analytics|gtag/i, 'Google Analytics', 'Analytics', 'JS reference'],
        [/recaptcha/i, 'reCAPTCHA', 'Security', 'JS reference'],
      ];

      const combined = h + ' ' + b;
      for (const [pat, name, cat, ev] of patterns) {
        if (pat.test(combined) && !detected.find(d => d.name === name)) {
          detected.push({ name, category: cat, evidence: ev });
        }
      }

      setTechs(detected);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [target, loading]);

  const runScan = () => {
    switch (tab) {
      case 'whois': runWhois(); break;
      case 'dns': runDns(); break;
      case 'crt': runCrt(); break;
      case 'wayback': runWayback(); break;
      case 'headers': runHeaders(); break;
      case 'techdetect': runTechDetect(); break;
    }
  };

  const formatWaybackTs = (ts: string) => {
    if (ts.length < 8) return ts;
    return `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}`;
  };

  return (
    <div className="osint">
      <div className="osint-toolbar">
        <Fingerprint size={14} />
        <span className="osint-toolbar-title">OSINT Recon</span>
        <div style={{ flex: 1 }} />
        <input className="osint-target-input" value={target} onChange={e => setTarget(e.target.value)}
          placeholder="target.com or https://target.com"
          onKeyDown={e => e.key === 'Enter' && runScan()} />
        <button className="osint-scan-btn" onClick={runScan} disabled={loading || !target}>
          {loading ? <Loader2 size={10} className="spin" /> : <Search size={10} />}
          {loading ? 'Scanning...' : 'Scan'}
        </button>
      </div>

      <div className="osint-tabs">
        {([
          ['whois', 'WHOIS/RDAP', Globe],
          ['dns', 'DNS Records', Server],
          ['crt', 'Certificates', Shield],
          ['wayback', 'Wayback Machine', Clock],
          ['headers', 'Security Headers', Shield],
          ['techdetect', 'Tech Detect', Fingerprint],
        ] as const).map(([id, label, Icon]) => (
          <button key={id} className={`osint-tab ${tab === id ? 'active' : ''}`} onClick={() => setTab(id as Tab)}>
            <Icon size={10} /> {label}
          </button>
        ))}
      </div>

      <div className="osint-body">

        {tab === 'whois' && (
          <div className="osint-result-panel">
            {whoisResult ? (
              <div className="osint-result-wrap">
                <div className="osint-result-header">
                  <span>RDAP/WHOIS for <strong>{domain()}</strong></span>
                  <button className="osint-copy-btn" onClick={() => copyText(whoisResult)}><Copy size={9} /> Copy</button>
                </div>
                <pre className="osint-pre">{whoisResult}</pre>
              </div>
            ) : (
              <div className="osint-empty">
                <Globe size={24} strokeWidth={1} />
                <span>Enter a domain and click Scan to perform RDAP/WHOIS lookup</span>
                <span className="osint-dim">Returns registrar, creation date, nameservers, organization</span>
              </div>
            )}
          </div>
        )}


        {tab === 'dns' && (
          <div className="osint-result-panel">
            {dnsRecords.length > 0 ? (
              <table className="osint-table">
                <thead><tr><th>Type</th><th>Value</th><th>TTL</th><th></th></tr></thead>
                <tbody>
                  {dnsRecords.map((r, i) => (
                    <tr key={i}>
                      <td><span className={`osint-dns-type ${r.type}`}>{r.type}</span></td>
                      <td className="osint-mono">{r.value}</td>
                      <td className="osint-dim">{r.ttl}s</td>
                      <td><button className="osint-copy-btn" onClick={() => copyText(r.value)}><Copy size={9} /></button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="osint-empty">
                <Server size={24} strokeWidth={1} />
                <span>Resolve A, AAAA, CNAME, MX, TXT, NS records</span>
                <span className="osint-dim">Uses Google DNS-over-HTTPS API (no API key needed)</span>
              </div>
            )}
          </div>
        )}


        {tab === 'crt' && (
          <div className="osint-result-panel">
            {crtEntries.length > 0 ? (
              <>
                <div className="osint-result-header">
                  <span>{crtEntries.length} subdomains from Certificate Transparency</span>
                  <button className="osint-copy-btn" onClick={() => copyText(crtEntries.map(e => e.subdomain).join('\n'))}><Copy size={9} /> Copy All</button>
                </div>
                <table className="osint-table">
                  <thead><tr><th>Subdomain</th><th>Issuer</th><th>Expires</th></tr></thead>
                  <tbody>
                    {crtEntries.map((e, i) => (
                      <tr key={i}>
                        <td className="osint-mono osint-accent">{e.subdomain}</td>
                        <td className="osint-dim">{e.issuer.slice(0, 40)}</td>
                        <td className="osint-dim">{e.not_after}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            ) : (
              <div className="osint-empty">
                <Shield size={24} strokeWidth={1} />
                <span>Search Certificate Transparency logs via crt.sh</span>
                <span className="osint-dim">Finds subdomains from issued SSL certificates — no API key needed</span>
              </div>
            )}
          </div>
        )}


        {tab === 'wayback' && (
          <div className="osint-result-panel">
            {waybackUrls.length > 0 ? (
              <>
                <div className="osint-result-header">
                  <span>{waybackUrls.length} archived URLs</span>
                  <button className="osint-copy-btn" onClick={() => copyText(waybackUrls.map(u => u.url).join('\n'))}><Copy size={9} /> Copy URLs</button>
                </div>
                <table className="osint-table">
                  <thead><tr><th>URL</th><th>Date</th><th>Status</th><th>Type</th></tr></thead>
                  <tbody>
                    {waybackUrls.map((u, i) => (
                      <tr key={i}>
                        <td className="osint-mono osint-accent" style={{ maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis' }}>{u.url}</td>
                        <td className="osint-dim">{formatWaybackTs(u.timestamp)}</td>
                        <td><span className={`osint-status ${u.status.startsWith('2') ? 's2xx' : u.status.startsWith('3') ? 's3xx' : 's4xx'}`}>{u.status}</span></td>
                        <td className="osint-dim">{u.mime}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            ) : (
              <div className="osint-empty">
                <Clock size={24} strokeWidth={1} />
                <span>Query the Wayback Machine CDX API</span>
                <span className="osint-dim">Discover historical URLs, deleted endpoints, old API versions</span>
              </div>
            )}
          </div>
        )}


        {tab === 'headers' && (
          <div className="osint-result-panel">
            {headerInfo.length > 0 ? (
              <>
                <div className="osint-result-header">
                  <span>Security Headers Audit</span>
                  <span className={`osint-score ${headerInfo.filter(h => h.secure).length >= 5 ? 'good' : headerInfo.filter(h => h.secure).length >= 3 ? 'ok' : 'bad'}`}>
                    {headerInfo.filter(h => h.secure).length}/{headerInfo.length} present
                  </span>
                </div>
                <table className="osint-table">
                  <thead><tr><th>Header</th><th>Value</th><th>Status</th><th>Note</th></tr></thead>
                  <tbody>
                    {headerInfo.map((h, i) => (
                      <tr key={i} className={h.secure ? '' : 'missing'}>
                        <td className="osint-mono">{h.name}</td>
                        <td className={`osint-mono ${h.secure ? '' : 'osint-missing-val'}`} style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>{h.value}</td>
                        <td><span className={`osint-header-status ${h.secure ? 'present' : 'missing'}`}>{h.secure ? '✓ Present' : '✗ Missing'}</span></td>
                        <td className="osint-dim">{h.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {rawHeaders && (
                  <details className="osint-raw-details">
                    <summary>Raw Response Headers</summary>
                    <pre className="osint-pre">{rawHeaders}</pre>
                  </details>
                )}
              </>
            ) : (
              <div className="osint-empty">
                <Shield size={24} strokeWidth={1} />
                <span>Audit HTTP security headers</span>
                <span className="osint-dim">Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and more</span>
              </div>
            )}
          </div>
        )}


        {tab === 'techdetect' && (
          <div className="osint-result-panel">
            {techs.length > 0 ? (
              <>
                <div className="osint-result-header">
                  <span>{techs.length} technologies detected</span>
                </div>
                <div className="osint-tech-grid">
                  {techs.map((t, i) => (
                    <div key={i} className="osint-tech-card">
                      <span className="osint-tech-name">{t.name}</span>
                      <span className="osint-tech-category">{t.category}</span>
                      <span className="osint-dim">{t.evidence}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="osint-empty">
                <Fingerprint size={24} strokeWidth={1} />
                <span>Detect web technologies, frameworks, CDNs, and WAFs</span>
                <span className="osint-dim">Fingerprints server headers, HTML patterns, JS references</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
