import type { AuditAsset, AuditFinding, AuditSettings, FindingType, Severity } from './audit.types';

interface Pattern {
  name: string;
  category: FindingType;
  severity: Severity;
  regex: RegExp;
  extractGroup?: number;
}

const PATTERNS: Pattern[] = [

  // ╔══════════════════════════════════════════════════════════════════╗
  // ║  SECRETS                                                         ║
  // ╚══════════════════════════════════════════════════════════════════╝

  // ── AWS ───────────────────────────────────────────────────────────
  { name: 'aws_access_key_id',    category: 'secret', severity: 'critical',
    regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'aws_secret_key',       category: 'secret', severity: 'critical',
    regex: /(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/gi, extractGroup: 1 },
  { name: 'aws_session_token',    category: 'secret', severity: 'critical',
    regex: /\bFwoGZXIvYXdz[A-Za-z0-9+/=]{100,}/g },
  { name: 'aws_arn_secret',       category: 'secret', severity: 'high',
    regex: /arn:aws:secretsmanager:[a-z0-9-]+:\d{12}:secret:[^\s"']+/g },

  // ── OpenAI ─────────────────────────────────────────────────────────
  { name: 'openai_api_key',       category: 'secret', severity: 'critical',
    // Old format has "T3BlbkFJ" (base64 "OpenAI") in the middle
    regex: /\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b/g },
  { name: 'openai_proj_key',      category: 'secret', severity: 'critical',
    regex: /\bsk-proj-[a-zA-Z0-9_\-]{48,}\b/g },
  { name: 'openai_org_key',       category: 'secret', severity: 'critical',
    regex: /\bsk-[oO][a-zA-Z0-9_\-]{48,}\b/g },

  // ── Anthropic ──────────────────────────────────────────────────────
  { name: 'anthropic_api_key',    category: 'secret', severity: 'critical',
    regex: /\bsk-ant-(?:api03-)?[a-zA-Z0-9_\-]{60,}\b/g },

  // ── Google / Firebase / GCP ───────────────────────────────────────
  { name: 'google_api_key',       category: 'secret', severity: 'high',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: 'firebase_config',      category: 'secret', severity: 'medium',
    // Detects Firebase config blocks with apiKey
    regex: /apiKey\s*:\s*["']AIza[0-9A-Za-z\-_]{35}["']/g },
  { name: 'gcp_service_account',  category: 'secret', severity: 'critical',
    regex: /"type"\s*:\s*"service_account"[^}]{0,200}"private_key"/gs },
  { name: 'gcp_oauth_client',     category: 'secret', severity: 'high',
    regex: /[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com/g },

  // ── Supabase ───────────────────────────────────────────────────────
  { name: 'supabase_service_key', category: 'secret', severity: 'critical',
    // Supabase service role key: JWT with "service_role" in name/vars
    regex: /(?:supabase[_-]?service[_-]?(?:role[_-]?)?key|SUPABASE_SERVICE_ROLE_KEY|service_role_key)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["']?/gi, extractGroup: 1 },
  { name: 'supabase_anon_key',    category: 'secret', severity: 'high',
    regex: /(?:supabase[_-]?(?:anon[_-]?)?key|SUPABASE_(?:ANON_)?KEY|supabaseKey|anonKey)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["']?/gi, extractGroup: 1 },
  { name: 'supabase_url',         category: 'secret', severity: 'medium',
    regex: /\bhttps:\/\/[a-z][a-z0-9]{20}\.supabase\.co\b/g },
  { name: 'supabase_createclient',category: 'secret', severity: 'critical',
    // createClient('url', 'key') inline
    regex: /createClient\(\s*["']https:\/\/[^"']+\.supabase\.co["']\s*,\s*["'](eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["']/g, extractGroup: 1 },

  // ── HuggingFace ────────────────────────────────────────────────────
  { name: 'huggingface_token',    category: 'secret', severity: 'high',
    regex: /\bhf_[a-zA-Z0-9]{34}\b/g },

  // ── Replicate ──────────────────────────────────────────────────────
  { name: 'replicate_api_key',    category: 'secret', severity: 'high',
    regex: /\br8_[a-zA-Z0-9]{40}\b/g },

  // ── GitHub ─────────────────────────────────────────────────────────
  { name: 'github_token',         category: 'secret', severity: 'critical',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g },
  { name: 'github_pat',           category: 'secret', severity: 'critical',
    regex: /github_pat_[A-Za-z0-9_]{82}/g },
  { name: 'github_actions_token', category: 'secret', severity: 'critical',
    regex: /\bgha_[A-Za-z0-9]{36}\b/g },
  { name: 'github_app_key',       category: 'secret', severity: 'critical',
    regex: /-----BEGIN RSA PRIVATE KEY-----[\s\S]{100,}-----END RSA PRIVATE KEY-----/g },

  // ── Stripe ─────────────────────────────────────────────────────────
  { name: 'stripe_live_key',      category: 'secret', severity: 'critical',
    regex: /\bsk_live_[A-Za-z0-9]{24,}\b/g },
  { name: 'stripe_test_key',      category: 'secret', severity: 'medium',
    regex: /\b(?:sk|pk)_test_[A-Za-z0-9]{24,}\b/g },
  { name: 'stripe_webhook_secret',category: 'secret', severity: 'high',
    regex: /\bwhsec_[a-zA-Z0-9]{32,}\b/g },

  // ── Slack ──────────────────────────────────────────────────────────
  { name: 'slack_token',          category: 'secret', severity: 'high',
    regex: /\bxox[baprs]-[0-9]{8,12}-[0-9A-Za-z\-]{20,}\b/g },
  { name: 'slack_webhook',        category: 'secret', severity: 'high',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24,}/g },

  // ── SendGrid / Mailgun / SMTP ──────────────────────────────────────
  { name: 'sendgrid_key',         category: 'secret', severity: 'high',
    regex: /\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43}\b/g },
  { name: 'mailgun_key',          category: 'secret', severity: 'high',
    regex: /\bkey-[0-9a-zA-Z]{32}\b/g },
  { name: 'smtp_credentials',     category: 'secret', severity: 'high',
    regex: /smtp:\/\/[^@\s"']{3,}:[^@\s"']{6,}@[a-zA-Z0-9._\-]+/g },

  // ── Twilio ─────────────────────────────────────────────────────────
  { name: 'twilio_sid',           category: 'secret', severity: 'high',
    regex: /\bAC[a-z0-9]{32}\b/g },
  { name: 'twilio_auth_token',    category: 'secret', severity: 'critical',
    regex: /(?:twilio[_-]?auth[_-]?token|TWILIO_AUTH_TOKEN)\s*[:=]\s*["']([a-zA-Z0-9]{32})["']/gi, extractGroup: 1 },

  // ── Telegram ───────────────────────────────────────────────────────
  { name: 'telegram_bot_token',   category: 'secret', severity: 'high',
    regex: /\b\d{9,10}:[A-Za-z0-9_\-]{35}\b/g },

  // ── Discord ────────────────────────────────────────────────────────
  { name: 'discord_bot_token',    category: 'secret', severity: 'high',
    regex: /\b[A-Za-z0-9]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}\b/g },
  { name: 'discord_webhook',      category: 'secret', severity: 'medium',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_\-]{68}/g },

  // ── NPM ────────────────────────────────────────────────────────────
  { name: 'npm_token',            category: 'secret', severity: 'high',
    regex: /\bnpm_[a-zA-Z0-9]{36}\b/g },

  // ── DigitalOcean ───────────────────────────────────────────────────
  { name: 'digitalocean_pat',     category: 'secret', severity: 'critical',
    regex: /\bdop_v1_[a-zA-Z0-9]{64}\b/g },

  // ── Cloudflare ─────────────────────────────────────────────────────
  { name: 'cloudflare_api_token', category: 'secret', severity: 'critical',
    regex: /\b[a-zA-Z0-9_\-]{40}\b(?=.*cloudflare)/gi },

  // ── Heroku ─────────────────────────────────────────────────────────
  { name: 'heroku_api_key',       category: 'secret', severity: 'high',
    regex: /(?:heroku[_-]?api[_-]?key|HEROKU_API_KEY)\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']?/gi, extractGroup: 1 },

  // ── Shopify ────────────────────────────────────────────────────────
  { name: 'shopify_access_token', category: 'secret', severity: 'critical',
    regex: /shpat_[a-fA-F0-9]{32}/g },
  { name: 'shopify_shared_secret',category: 'secret', severity: 'high',
    regex: /shpss_[a-fA-F0-9]{32}/g },
  { name: 'shopify_api_key',      category: 'secret', severity: 'high',
    regex: /shpca_[a-fA-F0-9]{32}/g },

  // ── Azure ──────────────────────────────────────────────────────────
  { name: 'azure_storage_key',    category: 'secret', severity: 'critical',
    regex: /DefaultEndpointsProtocol=https;AccountName=[^;]{3,50};AccountKey=[A-Za-z0-9+/]{86}==/g },
  { name: 'azure_sas_token',      category: 'secret', severity: 'high',
    regex: /(?:sv|sig|se|sp|sr)=[A-Za-z0-9%]+&(?:sv|sig|se|sp|sr)=[A-Za-z0-9%]+/g },

  // ── Databases ──────────────────────────────────────────────────────
  { name: 'mongodb_connection',   category: 'secret', severity: 'critical',
    regex: /mongodb(?:\+srv)?:\/\/[^"'\s@]+:[^"'\s@]{6,}@[A-Za-z0-9._\-/:?=&%]+/g },
  { name: 'postgres_connection',  category: 'secret', severity: 'critical',
    regex: /postgres(?:ql)?:\/\/[^"'\s@]+:[^"'\s@]{6,}@[A-Za-z0-9._\-/:?=&%]+/g },
  { name: 'mysql_connection',     category: 'secret', severity: 'critical',
    regex: /mysql(?:2)?:\/\/[^"'\s@]+:[^"'\s@]{6,}@[A-Za-z0-9._\-/:?=&%]+/g },
  { name: 'redis_auth_url',       category: 'secret', severity: 'high',
    regex: /redis(?:s)?:\/\/:[^"'\s@]{6,}@[A-Za-z0-9._\-/:?=&%]+/g },

  // ── Vault / Infrastructure ─────────────────────────────────────────
  { name: 'vault_token',          category: 'secret', severity: 'critical',
    regex: /\b(?:hvs|s)\.[A-Za-z0-9]{24,}\b/g },
  { name: 'private_key',          category: 'secret', severity: 'critical',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },

  // ── Sentry DSN ─────────────────────────────────────────────────────
  { name: 'sentry_dsn',           category: 'secret', severity: 'medium',
    regex: /https:\/\/[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/[0-9]+/g },

  // ── Square ─────────────────────────────────────────────────────────
  { name: 'square_access_token',  category: 'secret', severity: 'critical',
    regex: /\bEAAA[a-zA-Z0-9_\-]{60,}\b/g },
  { name: 'square_api_key',       category: 'secret', severity: 'high',
    regex: /\bsq0(?:atp|csp)-[a-zA-Z0-9_\-]{22,}\b/g },

  // ── PayPal / Braintree ─────────────────────────────────────────────
  { name: 'braintree_token',      category: 'secret', severity: 'critical',
    regex: /access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}/g },

  // ── Firebase ──────────────────────────────────────────────────────
  { name: 'firebase_server_key',  category: 'secret', severity: 'high',
    regex: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/g },

  // ── Generic hardcoded secrets ──────────────────────────────────────
  { name: 'hardcoded_password',   category: 'secret', severity: 'high',
    regex: /\b(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\r\n\\(){};,]{8,64})["']/gi, extractGroup: 1 },
  { name: 'hardcoded_secret',     category: 'secret', severity: 'high',
    regex: /\b(?:secret|api[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']([^"'\r\n\\(){};,]{10,128})["']/gi, extractGroup: 1 },
  { name: 'private_key_in_code',  category: 'secret', severity: 'critical',
    regex: /["']-----BEGIN [A-Z ]+ KEY-----[^"']+-----END [A-Z ]+ KEY-----["']/g },

  // ── .env-style variable patterns ───────────────────────────────────
  { name: 'env_api_key',          category: 'secret', severity: 'high',
    // NEXT_PUBLIC_, REACT_APP_, VITE_ env vars with key-like values
    regex: /(?:NEXT_PUBLIC_|REACT_APP_|VITE_)[A-Z_]+(?:KEY|TOKEN|SECRET|API)\s*=\s*["']?([^"'\r\n\s]{16,})["']?/g, extractGroup: 1 },
  { name: 'dotenv_secret',        category: 'secret', severity: 'medium',
    regex: /process\.env\.(?:[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS)[A-Z_]*)/g },


  // ╔══════════════════════════════════════════════════════════════════╗
  // ║  TOKENS                                                          ║
  // ╚══════════════════════════════════════════════════════════════════╝

  { name: 'jwt_token',            category: 'token', severity: 'medium',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: 'bearer_token',         category: 'token', severity: 'medium',
    regex: /\bBearer\s+([A-Za-z0-9\-._~+/]{20,}=*)/gi, extractGroup: 1 },
  { name: 'basic_auth',           category: 'token', severity: 'high',
    regex: /\bBasic\s+([A-Za-z0-9+/]{20,}={0,2})/gi, extractGroup: 1 },
  { name: 'oauth_token',          category: 'token', severity: 'medium',
    regex: /\b(?:oauth|access)[_-]?token\s*[:=]\s*["']([A-Za-z0-9\-._~+/]{20,})["']/gi, extractGroup: 1 },
  { name: 'id_token',             category: 'token', severity: 'medium',
    regex: /\bid_token\s*[:=]\s*["'](eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})["']/gi, extractGroup: 1 },
  { name: 'refresh_token',        category: 'token', severity: 'high',
    regex: /\brefresh_token\s*[:=]\s*["']([A-Za-z0-9\-._~+/]{20,})["']/gi, extractGroup: 1 },
  { name: 'session_cookie',       category: 'token', severity: 'medium',
    regex: /(?:__session|_session|session_id|PHPSESSID|JSESSIONID)\s*=\s*([A-Za-z0-9._\-+/]{20,})/g, extractGroup: 1 },


  // ╔══════════════════════════════════════════════════════════════════╗
  // ║  API ENDPOINTS                                                   ║
  // ╚══════════════════════════════════════════════════════════════════╝

  { name: 'fetch_call',           category: 'api_endpoint', severity: 'info',
    regex: /\bfetch\(\s*["'`]((?:https?:\/\/[^"'`\s)]+|\/[a-zA-Z0-9/_.\-?=&#%@:]{3,}))["'`]/g, extractGroup: 1 },
  { name: 'axios_request',        category: 'api_endpoint', severity: 'info',
    regex: /\baxios\.(?:get|post|put|delete|patch|head|options|request)\(\s*["'`]([^"'`\s]+)["'`]/gi, extractGroup: 1 },
  { name: 'xhr_open',             category: 'api_endpoint', severity: 'info',
    regex: /\.open\(\s*["']\w+["']\s*,\s*["']([^"'\s]+)["']/g, extractGroup: 1 },
  { name: 'api_path_string',      category: 'api_endpoint', severity: 'info',
    regex: /["'`](\/(?:api|v\d+|graphql|rest|rpc|gql)\/[a-zA-Z0-9/_.\-?=&#%]{2,})["'`]/g, extractGroup: 1 },
  { name: 'graphql_operation',    category: 'api_endpoint', severity: 'info',
    regex: /\b(?:query|mutation|subscription)\s+[A-Z][a-zA-Z0-9]+/g },
  { name: 'websocket_url',        category: 'api_endpoint', severity: 'info',
    regex: /\bnew\s+WebSocket\(\s*["'`](wss?:\/\/[^"'`\s]+)["'`]/g, extractGroup: 1 },
  { name: 'grpc_endpoint',        category: 'api_endpoint', severity: 'info',
    regex: /["'`]([a-zA-Z0-9._\-]+:\d{4,5})["'`](?=.*grpc|.*proto)/gi, extractGroup: 1 },
  { name: 'trpc_router',          category: 'api_endpoint', severity: 'info',
    regex: /router\.[a-zA-Z]+\(\s*["']([^"']+)["']/g, extractGroup: 1 },


  // ╔══════════════════════════════════════════════════════════════════╗
  // ║  LINKS                                                           ║
  // ╚══════════════════════════════════════════════════════════════════╝

  { name: 'absolute_url',         category: 'link', severity: 'info',
    regex: /\bhttps?:\/\/(?!(?:localhost|127\.0\.0\.1))[a-zA-Z0-9._\-/?=&#%+:@!,;~*'()[\]]{10,}/g },
  { name: 'relative_path',        category: 'link', severity: 'info',
    regex: /["'`](\/[a-zA-Z0-9][a-zA-Z0-9/_.\-]{6,})["'`]/g, extractGroup: 1 },


  // ╔══════════════════════════════════════════════════════════════════╗
  // ║  COMMENTS                                                        ║
  // ╚══════════════════════════════════════════════════════════════════╝

  { name: 'todo_fixme',           category: 'comment', severity: 'info',
    regex: /\/\/\s*(?:TODO|FIXME|HACK|XXX|TEMP|BUG|NOTE|DEPRECATED|WARN)[:\s][^\n]{5,}/gi },
  { name: 'sensitive_comment',    category: 'comment', severity: 'low',
    regex: /\/\/[^\n]*\b(?:password|secret|private[_-]?key|credential|auth)\b[^\n]{0,80}/gi },
];

// Values that look like code expressions → reject for secret/token
const CODE_VALUE_RE = /[(){};]|^\s*function\s*\(|=>|void\s+\d/;
const USELESS_VALUE_RE = /^[\d\s.]+$|^null$|^undefined$|^true$|^false$/i;

function getLineNumber(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

function getContext(lines: string[], lineIndex: number): string {
  const start = Math.max(0, lineIndex - 1);
  const end   = Math.min(lines.length - 1, lineIndex + 1);
  return lines.slice(start, end + 1).join('\n');
}

export function runFinders(asset: AuditAsset, settings: AuditSettings): AuditFinding[] {
  if (!asset.content) return [];
  const content = asset.content;
  const lines   = content.split('\n');
  const findings: AuditFinding[] = [];
  const seen = new Set<string>();
  const catCount: Partial<Record<FindingType, number>> = {};
  const CAT_CAP: Partial<Record<FindingType, number>> = {
    link: 150, comment: 80, api_endpoint: 200, token: 100, secret: 500,
  };

  for (const p of PATTERNS) {
    if (!settings.enabledFinders[p.category]) continue;
    const cap = CAT_CAP[p.category] ?? 500;
    p.regex.lastIndex = 0;
    let m: RegExpExecArray | null;

    while ((m = p.regex.exec(content)) !== null) {
      if ((catCount[p.category] ?? 0) >= cap) break;

      const raw = (p.extractGroup !== undefined ? m[p.extractGroup] : m[0]) ?? m[0];
      if (!raw || raw.length < 5) continue;
      const trimmed = raw.trim();
      if (!trimmed || trimmed.length < 5) continue;

      if ((p.category === 'secret' || p.category === 'token') && CODE_VALUE_RE.test(trimmed)) continue;
      if (USELESS_VALUE_RE.test(trimmed)) continue;

      const key = `${p.name}::${trimmed.slice(0, 80)}`;
      if (seen.has(key)) continue;
      seen.add(key);

      catCount[p.category] = (catCount[p.category] ?? 0) + 1;
      const line = getLineNumber(content, m.index);

      findings.push({
        id: `${asset.id}-${findings.length}`,
        type: p.category,
        value: trimmed.length > 100 ? trimmed.slice(0, 100) + '…' : trimmed,
        context: getContext(lines, line - 1),
        lineNumber: line,
        severity: p.severity,
        assetUrl: asset.url,
        patternName: p.name,
      });
    }
  }
  return findings;
}
