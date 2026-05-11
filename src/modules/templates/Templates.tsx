import { useState, useMemo } from 'react';
import { Search, Grid3X3, List, Shield, FileCode2 } from 'lucide-react';
import './Templates.css';

interface Template {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  tags: string[];
  description: string;
}

const TEMPLATES: Template[] = [
  { id: 'git-config', name: 'Git Configuration Exposure', severity: 'critical', category: 'exposures', tags: ['git','config','exposure'], description: 'Detects exposed .git/config files that can leak repository URLs, credentials, and internal paths.' },
  { id: 'git-head', name: 'Git HEAD Exposure', severity: 'critical', category: 'exposures', tags: ['git','exposure'], description: 'Detects exposed .git/HEAD file indicating a fully accessible Git repository.' },
  { id: 'env-file', name: 'Environment File Exposure', severity: 'critical', category: 'exposures', tags: ['env','config','exposure'], description: 'Detects exposed .env files containing secrets, API keys, and database credentials.' },
  { id: 'docker-compose-exposure', name: 'Docker Compose Exposure', severity: 'critical', category: 'exposures', tags: ['docker','exposure'], description: 'Exposed docker-compose.yml leaking service architecture, credentials, and internal network config.' },
  { id: 'aws-credentials', name: 'AWS Credentials Exposure', severity: 'critical', category: 'exposures', tags: ['aws','cloud','credentials'], description: 'Detects exposed AWS credential files with access keys.' },
  { id: 'wp-config-backup', name: 'WordPress Config Backup', severity: 'critical', category: 'exposures', tags: ['wordpress','backup','config'], description: 'Detects backup copies of wp-config.php containing database credentials.' },
  { id: 'debug-vars', name: 'Debug Endpoint Exposure', severity: 'critical', category: 'exposures', tags: ['debug','exposure'], description: 'Detects exposed debug endpoints leaking environment variables and server internals.' },
  { id: 'tomcat-default-login', name: 'Apache Tomcat Default Credentials', severity: 'critical', category: 'default-logins', tags: ['tomcat','java','default-login'], description: 'Tests for default Apache Tomcat manager credentials (tomcat:tomcat).' },
  { id: 'jenkins-default', name: 'Jenkins Default Access', severity: 'critical', category: 'default-logins', tags: ['jenkins','ci','default-login'], description: 'Detects Jenkins instances accessible without authentication.' },
  { id: 'elasticsearch-unauthenticated', name: 'Elasticsearch Unauthenticated', severity: 'critical', category: 'default-logins', tags: ['elasticsearch','database','unauthenticated'], description: 'Detects Elasticsearch instances accessible without authentication.' },
  { id: 'CVE-2024-21887', name: 'Ivanti Connect Secure Auth Bypass', severity: 'critical', category: 'cves', tags: ['ivanti','vpn','auth-bypass','cve2024'], description: 'Detects Ivanti Connect Secure/Pulse Secure VPN auth bypass.' },
  { id: 'CVE-2023-46747', name: 'F5 BIG-IP Auth Bypass', severity: 'critical', category: 'cves', tags: ['f5','bigip','auth-bypass','cve2023'], description: 'Detects F5 BIG-IP authentication bypass via request smuggling.' },
  { id: 'CVE-2023-22515', name: 'Atlassian Confluence Auth Bypass', severity: 'critical', category: 'cves', tags: ['confluence','atlassian','auth-bypass','cve2023'], description: 'Detects Atlassian Confluence Data Center/Server auth bypass.' },
  { id: 'CVE-2023-34362', name: 'MOVEit Transfer SQLi', severity: 'critical', category: 'cves', tags: ['moveit','sqli','cve2023'], description: 'Detects MOVEit Transfer SQL injection vulnerability.' },
  { id: 'CVE-2024-3400', name: 'Palo Alto PAN-OS Command Injection', severity: 'critical', category: 'cves', tags: ['paloalto','firewall','rce','cve2024'], description: 'Detects Palo Alto Networks PAN-OS GlobalProtect command injection.' },
  { id: 'log4j-rce', name: 'Log4j RCE (CVE-2021-44228)', severity: 'critical', category: 'cves', tags: ['log4j','java','rce','cve2021'], description: 'Tests for Log4Shell (Log4j RCE) by injecting JNDI lookup patterns.' },
  { id: 'aws-metadata', name: 'AWS Metadata SSRF Check', severity: 'critical', category: 'vulnerabilities', tags: ['aws','ssrf','cloud','metadata'], description: 'Tests for SSRF via AWS EC2 instance metadata endpoint access.' },
  { id: 'rfi-test', name: 'Remote File Inclusion Test', severity: 'critical', category: 'fuzzing', tags: ['rfi','injection'], description: 'Tests for Remote File Inclusion by injecting external URL.' },
  { id: 'phpinfo', name: 'PHP Info Disclosure', severity: 'high', category: 'exposures', tags: ['php','info','disclosure'], description: 'Detects exposed phpinfo() pages leaking server configuration.' },
  { id: 'htaccess-config', name: '.htaccess Config Exposure', severity: 'high', category: 'exposures', tags: ['apache','config','exposure'], description: 'Detects exposed .htaccess files with URL rewrite rules.' },
  { id: 'ds-store', name: '.DS_Store File Exposure', severity: 'high', category: 'exposures', tags: ['macos','exposure'], description: 'Detects exposed .DS_Store files revealing directory structure.' },
  { id: 'actuator-env', name: 'Spring Boot Actuator Env', severity: 'high', category: 'exposures', tags: ['spring','java','actuator','env'], description: 'Detects exposed Spring Boot Actuator environment endpoint.' },
  { id: 'elmah-axd', name: 'ELMAH Error Log Exposure', severity: 'high', category: 'exposures', tags: ['asp.net','error','logs'], description: 'Detects exposed ELMAH error logging interface.' },
  { id: 'trace-axd', name: 'ASP.NET Trace Exposure', severity: 'high', category: 'exposures', tags: ['asp.net','trace','debug'], description: 'Detects exposed ASP.NET trace.axd debug page.' },
  { id: 'web-config', name: 'Web.config Backup Exposure', severity: 'high', category: 'exposures', tags: ['asp.net','config','backup'], description: 'Detects backup copies of ASP.NET web.config files.' },
  { id: 'cors-reflection', name: 'CORS Origin Reflection', severity: 'high', category: 'misconfiguration', tags: ['cors','headers','security'], description: 'Detects CORS that reflects the Origin header without validation.' },
  { id: 'grafana-default', name: 'Grafana Default Login', severity: 'high', category: 'default-logins', tags: ['grafana','monitoring','default-login'], description: 'Tests for default Grafana credentials (admin:admin).' },
  { id: 'kibana-unauthenticated', name: 'Kibana Unauthenticated Access', severity: 'high', category: 'default-logins', tags: ['kibana','elasticsearch','unauthenticated'], description: 'Detects Kibana instances accessible without authentication.' },
  { id: 'cname-s3-takeover', name: 'AWS S3 Subdomain Takeover', severity: 'high', category: 'takeovers', tags: ['aws','s3','takeover'], description: 'Detects dangling CNAME pointing to an unclaimed AWS S3 bucket.' },
  { id: 'cname-github-takeover', name: 'GitHub Pages Takeover', severity: 'high', category: 'takeovers', tags: ['github','takeover'], description: 'Detects dangling CNAME pointing to unclaimed GitHub Pages.' },
  { id: 'cname-heroku-takeover', name: 'Heroku Subdomain Takeover', severity: 'high', category: 'takeovers', tags: ['heroku','takeover'], description: 'Detects dangling CNAME pointing to unclaimed Heroku app.' },
  { id: 'cname-azure-takeover', name: 'Azure Subdomain Takeover', severity: 'high', category: 'takeovers', tags: ['azure','takeover'], description: 'Detects dangling CNAME pointing to unclaimed Azure resource.' },
  { id: 'firebase-db-open', name: 'Firebase Database Open Access', severity: 'high', category: 'misconfiguration', tags: ['firebase','google','database'], description: 'Detects openly accessible Firebase Realtime Database.' },
  { id: 'CVE-2023-44487', name: 'HTTP/2 Rapid Reset DoS', severity: 'high', category: 'cves', tags: ['http2','dos','cve2023'], description: 'Detects potential vulnerability to HTTP/2 Rapid Reset attack.' },
  { id: 'lfi-etc-passwd', name: 'LFI /etc/passwd', severity: 'high', category: 'fuzzing', tags: ['lfi','path-traversal','linux'], description: 'Tests for Local File Inclusion vulnerability.' },
  { id: 'lfi-windows-hosts', name: 'LFI Windows Hosts', severity: 'high', category: 'fuzzing', tags: ['lfi','path-traversal','windows'], description: 'Tests for Local File Inclusion on Windows.' },
  { id: 'sqli-error-mysql', name: 'SQL Injection Error (MySQL)', severity: 'high', category: 'fuzzing', tags: ['sqli','mysql','injection'], description: 'Tests for error-based SQL injection via MySQL errors.' },
  { id: 'sqli-error-postgres', name: 'SQL Injection Error (PostgreSQL)', severity: 'high', category: 'fuzzing', tags: ['sqli','postgres','injection'], description: 'Tests for error-based SQL injection via PostgreSQL errors.' },
  { id: 'ssti-basic', name: 'Server-Side Template Injection', severity: 'high', category: 'fuzzing', tags: ['ssti','injection','template'], description: 'Tests for SSTI by injecting a mathematical expression.' },
  { id: 'xxe-basic', name: 'XXE Injection Test', severity: 'high', category: 'fuzzing', tags: ['xxe','xml','injection'], description: 'Tests for XML External Entity injection.' },
  { id: 'swagger-ui', name: 'Swagger UI Exposure', severity: 'medium', category: 'exposures', tags: ['api','swagger','documentation'], description: 'Detects exposed Swagger/OpenAPI documentation.' },
  { id: 'swagger-json', name: 'Swagger JSON Exposure', severity: 'medium', category: 'exposures', tags: ['api','swagger','documentation'], description: 'Detects exposed Swagger/OpenAPI JSON specification.' },
  { id: 'openapi-yaml', name: 'OpenAPI YAML Exposure', severity: 'medium', category: 'exposures', tags: ['api','openapi','documentation'], description: 'Detects exposed OpenAPI YAML specification files.' },
  { id: 'graphql-playground', name: 'GraphQL Playground Exposure', severity: 'medium', category: 'exposures', tags: ['graphql','api','playground'], description: 'Detects exposed GraphQL Playground interfaces.' },
  { id: 'actuator-mappings', name: 'Spring Boot Actuator Mappings', severity: 'medium', category: 'exposures', tags: ['spring','java','actuator'], description: 'Detects exposed Actuator mappings endpoint.' },
  { id: 'server-status', name: 'Apache Server Status', severity: 'medium', category: 'exposures', tags: ['apache','status'], description: 'Detects exposed Apache server-status page.' },
  { id: 'cors-wildcard', name: 'CORS Wildcard Misconfiguration', severity: 'medium', category: 'misconfiguration', tags: ['cors','headers','misconfiguration'], description: 'Detects wildcard (*) CORS configuration.' },
  { id: 'directory-listing', name: 'Directory Listing Enabled', severity: 'medium', category: 'misconfiguration', tags: ['directory','listing','exposure'], description: 'Directory listing is enabled, revealing file structure.' },
  { id: 'admin-phpmyadmin', name: 'phpMyAdmin Detection', severity: 'medium', category: 'misconfiguration', tags: ['phpmyadmin','database','admin'], description: 'Detects exposed phpMyAdmin interface.' },
  { id: 'admin-adminer', name: 'Adminer Detection', severity: 'medium', category: 'misconfiguration', tags: ['adminer','database','admin'], description: 'Detects exposed Adminer database tool.' },
  { id: 'backup-files', name: 'Backup File Discovery', severity: 'medium', category: 'vulnerabilities', tags: ['backup','files','exposure'], description: 'Discovers common backup file patterns.' },
  { id: 'crossdomain-xml', name: 'Flash Crossdomain.xml', severity: 'medium', category: 'vulnerabilities', tags: ['flash','crossdomain','security'], description: 'Detects permissive crossdomain.xml.' },
  { id: 'clientaccesspolicy', name: 'Silverlight ClientAccessPolicy', severity: 'medium', category: 'vulnerabilities', tags: ['silverlight','crossdomain'], description: 'Detects permissive clientaccesspolicy.xml.' },
  { id: 'source-map-js', name: 'JavaScript Source Map Exposure', severity: 'medium', category: 'vulnerabilities', tags: ['javascript','sourcemap','exposure'], description: 'Detects exposed JavaScript source maps.' },
  { id: 'xss-reflected-basic', name: 'Reflected XSS Test', severity: 'medium', category: 'fuzzing', tags: ['xss','reflected','injection'], description: 'Tests for basic reflected XSS.' },
  { id: 'open-redirect-basic', name: 'Open Redirect Test', severity: 'medium', category: 'fuzzing', tags: ['redirect','open-redirect'], description: 'Tests for open redirect vulnerability.' },
  { id: 'crlf-injection', name: 'CRLF Injection Test', severity: 'medium', category: 'fuzzing', tags: ['crlf','injection','headers'], description: 'Tests for CRLF injection in HTTP headers.' },
  { id: 'missing-hsts', name: 'Missing HSTS Header', severity: 'low', category: 'misconfiguration', tags: ['headers','security','hsts'], description: 'HTTP Strict Transport Security header is missing.' },
  { id: 'missing-csp', name: 'Missing Content-Security-Policy', severity: 'low', category: 'misconfiguration', tags: ['headers','security','csp'], description: 'Content-Security-Policy header is missing.' },
  { id: 'missing-x-frame-options', name: 'Missing X-Frame-Options', severity: 'low', category: 'misconfiguration', tags: ['headers','security','clickjacking'], description: 'X-Frame-Options header is missing.' },
  { id: 'error-page-disclosure', name: 'Error Page Information Disclosure', severity: 'low', category: 'vulnerabilities', tags: ['error','information','disclosure'], description: 'Detects verbose error pages leaking info.' },
  { id: 'actuator-health', name: 'Spring Boot Actuator Health', severity: 'info', category: 'exposures', tags: ['spring','java','actuator'], description: 'Detects exposed Spring Boot Actuator health endpoint.' },
  { id: 'options-method', name: 'HTTP OPTIONS Method Enabled', severity: 'info', category: 'misconfiguration', tags: ['http','methods','options'], description: 'HTTP OPTIONS method is enabled.' },
  { id: 'tech-wordpress', name: 'WordPress Detection', severity: 'info', category: 'technologies', tags: ['wordpress','cms','tech'], description: 'Detects WordPress CMS installations.' },
  { id: 'tech-joomla', name: 'Joomla Detection', severity: 'info', category: 'technologies', tags: ['joomla','cms','tech'], description: 'Detects Joomla CMS installations.' },
  { id: 'tech-drupal', name: 'Drupal Detection', severity: 'info', category: 'technologies', tags: ['drupal','cms','tech'], description: 'Detects Drupal CMS installations.' },
  { id: 'tech-laravel', name: 'Laravel Detection', severity: 'info', category: 'technologies', tags: ['laravel','php','framework'], description: 'Detects Laravel PHP framework.' },
  { id: 'tech-nextjs', name: 'Next.js Detection', severity: 'info', category: 'technologies', tags: ['nextjs','javascript','framework'], description: 'Detects Next.js React framework.' },
  { id: 'tech-nuxtjs', name: 'Nuxt.js Detection', severity: 'info', category: 'technologies', tags: ['nuxtjs','vue','framework'], description: 'Detects Nuxt.js Vue framework.' },
  { id: 'tech-django', name: 'Django Detection', severity: 'info', category: 'technologies', tags: ['django','python','framework'], description: 'Detects Django Python framework.' },
  { id: 'tech-rails', name: 'Ruby on Rails Detection', severity: 'info', category: 'technologies', tags: ['rails','ruby','framework'], description: 'Detects Ruby on Rails framework.' },
  { id: 'waf-cloudflare', name: 'Cloudflare WAF Detection', severity: 'info', category: 'technologies', tags: ['waf','cloudflare','cdn'], description: 'Detects Cloudflare WAF/CDN protection.' },
  { id: 'waf-akamai', name: 'Akamai WAF Detection', severity: 'info', category: 'technologies', tags: ['waf','akamai','cdn'], description: 'Detects Akamai WAF/CDN protection.' },
  { id: 'sensitive-robots', name: 'Sensitive Robots.txt Entries', severity: 'info', category: 'vulnerabilities', tags: ['robots','recon','info'], description: 'Analyzes robots.txt for interesting disallowed paths.' },
  { id: 'security-txt', name: 'Security.txt Detection', severity: 'info', category: 'vulnerabilities', tags: ['security','recon'], description: 'Detects security.txt file.' },
  { id: 'sitemap-xml', name: 'Sitemap.xml Discovery', severity: 'info', category: 'vulnerabilities', tags: ['sitemap','recon'], description: 'Discovers sitemap.xml for URL enumeration.' },
  { id: 'admin-panel-login', name: 'Admin Panel Detection', severity: 'info', category: 'misconfiguration', tags: ['admin','panel','login'], description: 'Detects common admin panel login pages.' },
];

const CATEGORIES = ['all', 'exposures', 'misconfiguration', 'cves', 'vulnerabilities', 'default-logins', 'takeovers', 'technologies', 'fuzzing'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function Templates() {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('all');
  const [severity, setSeverity] = useState<string | null>(null);
  const [selected, setSelected] = useState<Template | null>(null);
  const [view, setView] = useState<'grid' | 'table'>('grid');

  const filtered = useMemo(() => {
    let list = TEMPLATES;
    if (category !== 'all') list = list.filter(t => t.category === category);
    if (severity) list = list.filter(t => t.severity === severity);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(t =>
        t.id.toLowerCase().includes(q) ||
        t.name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.tags.some(tag => tag.includes(q))
      );
    }
    return list.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  }, [search, category, severity]);

  const stats = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    TEMPLATES.forEach(t => counts[t.severity]++);
    return counts;
  }, []);

  return (
    <div className="templates">
      {/* ── Toolbar ─── */}
      <div className="templates-toolbar">
        <div className="templates-search">
          <Search size={12} />
          <input
            placeholder="Search templates (CVE, tag, name…)"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="templates-pills">
          {CATEGORIES.map(cat => (
            <button
              key={cat}
              className={`templates-pill ${category === cat ? 'active' : ''}`}
              onClick={() => setCategory(cat)}
            >
              {cat === 'all' ? 'All' : cat.replace('-', ' ')}
            </button>
          ))}
        </div>

        <div className="templates-severity-pills">
          {SEVERITIES.map(sev => (
            <button
              key={sev}
              className={`severity-pill ${severity === sev ? 'active' : ''}`}
              data-sev={sev}
              onClick={() => setSeverity(severity === sev ? null : sev)}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* ── Stats Bar ─── */}
      <div className="templates-stats">
        <span className="templates-stat">
          <FileCode2 size={10} />
          <span className="templates-stat-value">{filtered.length}</span> / {TEMPLATES.length} templates
        </span>
        <span className="templates-stat">
          <span className="templates-stat-dot" style={{ background: '#ef4444' }} />
          <span className="templates-stat-value">{stats.critical}</span> critical
        </span>
        <span className="templates-stat">
          <span className="templates-stat-dot" style={{ background: '#f97316' }} />
          <span className="templates-stat-value">{stats.high}</span> high
        </span>
        <span className="templates-stat">
          <span className="templates-stat-dot" style={{ background: '#eab308' }} />
          <span className="templates-stat-value">{stats.medium}</span> medium
        </span>
        <span className="templates-stat">
          <span className="templates-stat-dot" style={{ background: '#22c55e' }} />
          <span className="templates-stat-value">{stats.low}</span> low
        </span>
        <span className="templates-stat">
          <span className="templates-stat-dot" style={{ background: '#3b82f6' }} />
          <span className="templates-stat-value">{stats.info}</span> info
        </span>

        <div style={{ marginLeft: 'auto' }}>
          <div className="templates-view-toggle">
            <button className={`templates-view-btn ${view === 'grid' ? 'active' : ''}`} onClick={() => setView('grid')}>
              <Grid3X3 size={10} /> Grid
            </button>
            <button className={`templates-view-btn ${view === 'table' ? 'active' : ''}`} onClick={() => setView('table')}>
              <List size={10} /> Table
            </button>
          </div>
        </div>
      </div>

      {/* ── Content ─── */}
      <div className="templates-content">
        {filtered.length === 0 ? (
          <div className="templates-empty">
            <Shield size={40} />
            <div className="templates-empty-title">No templates found</div>
            <div className="templates-empty-desc">
              Try adjusting your search or filters. The template library contains {TEMPLATES.length} built-in vulnerability detection templates.
            </div>
          </div>
        ) : view === 'grid' ? (
          <div className="templates-grid">
            {filtered.map(t => (
              <div
                key={t.id}
                className="template-card"
                onClick={() => setSelected(selected?.id === t.id ? null : t)}
                style={selected?.id === t.id ? { borderColor: 'var(--accent)' } : undefined}
              >
                <div className="template-card-header">
                  <span className="template-card-severity" data-sev={t.severity}>{t.severity}</span>
                  <div className="template-card-title">{t.name}</div>
                </div>
                <div className="template-card-id">{t.id}</div>
                <div className="template-card-desc">{t.description}</div>
                <div className="template-card-footer">
                  {t.tags.slice(0, 3).map(tag => (
                    <span key={tag} className="template-card-tag">{tag}</span>
                  ))}
                  {t.tags.length > 3 && <span className="template-card-tag">+{t.tags.length - 3}</span>}
                  <span className="template-card-category">{t.category}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <table className="templates-table">
            <thead>
              <tr>
                <th className="col-severity">Severity</th>
                <th className="col-id">Template ID</th>
                <th>Name</th>
                <th className="col-category">Category</th>
                <th>Tags</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(t => (
                <tr
                  key={t.id}
                  className={selected?.id === t.id ? 'selected' : ''}
                  onClick={() => setSelected(selected?.id === t.id ? null : t)}
                >
                  <td><span className="template-card-severity" data-sev={t.severity}>{t.severity}</span></td>
                  <td className="col-id">{t.id}</td>
                  <td>{t.name}</td>
                  <td>{t.category}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                      {t.tags.slice(0, 3).map(tag => (
                        <span key={tag} className="template-card-tag">{tag}</span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Detail Panel ─── */}
      {selected && (
        <div className="template-detail">
          <div className="template-detail-header">
            <span className="template-card-severity" data-sev={selected.severity}>{selected.severity}</span>
            <div className="template-detail-title">{selected.name}</div>
            <button
              onClick={() => setSelected(null)}
              style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-3)', cursor: 'pointer', fontSize: 16 }}
            >×</button>
          </div>

          <div className="template-detail-section">
            <h4>Description</h4>
            <p>{selected.description}</p>
          </div>

          <div className="template-detail-section">
            <h4>Template ID</h4>
            <pre>{selected.id}</pre>
          </div>

          <div className="template-detail-section">
            <h4>Tags</h4>
            <div className="template-detail-tags">
              {selected.tags.map(tag => (
                <span key={tag} className="template-card-tag">{tag}</span>
              ))}
            </div>
          </div>

          <div className="template-detail-section">
            <h4>Usage via MCP</h4>
            <pre>{`// List templates by category
template_list({ category: "${selected.category}" })

template_search({ query: "${selected.id}" })

template_scan({ 
  target: "https://example.com",
  template_ids: ["${selected.id}"]
})`}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
