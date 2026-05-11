export type ModuleId =
  | 'dashboard'
  | 'intercept'
  | 'traffic'
  | 'replay'
  | 'attack'
  | 'scan'
  | 'sitemap'
  | 'tokens'
  | 'tools'
  | 'findings'
  | 'comparer'
  | 'logger'
  | 'organizer'
  | 'agent'
  | 'templates'
  | 'payloads'
  | 'session'
  | 'websocket'
  | 'oast'
  | 'osint'
  | 'discovery'
  | 'settings';

export interface HttpMessage {
  id: string;
  tool: string;
  timestamp: string;
  method: string;
  url: string;
  host: string;
  port: number;
  tls: boolean;
  httpVersion: string;
  requestHeaders: Record<string, string>;
  requestBody: string;
  statusCode: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
  responseTimeMs: number;
  notes?: string;
  color?: string;
}

export interface ReplayTab {
  id: string;
  name: string;
  method: string;
  url: string;
  requestRaw: string;
  responseRaw: string;
  statusCode: number | null;
  responseTimeMs: number | null;
  responseSize: number | null;
  isLoading: boolean;
}

export interface DecoderState {
  input: string;
  output: string;
  operation: string;
  format: string;
}

export interface ScanIssue {
  id: string;
  type: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'certain' | 'firm' | 'tentative';
  url: string;
  description: string;
  remediation: string;
}


export type ProjectType = 'pentest' | 'bounty' | 'research' | 'ctf' | 'custom';

export interface ProjectInfo {
  id: string;
  name: string;
  path: string;
  created_at: string;
  last_opened: string;
  description: string;
  target_url: string;
  request_count: number;
  finding_count: number;
  project_type: ProjectType;
  is_temporary: boolean;
  tags: string[];
}

export interface ProjectConfig {
  name: string;
  description: string;
  target_url: string;
  proxy_port: number;
  intercept_enabled: boolean;
  project_type: ProjectType;
  client_name: string;
  tags: string[];
  is_temporary: boolean;
  temp_ttl_hours: number | null;
  auto_start_proxy: boolean;
  auto_launch_browser: boolean;
  initial_scope: string[];
  max_traffic_entries: number;
  max_traffic_ram_mb: number;
  auto_save_interval_s: number;
  notes_template: string;
}

export interface CreateProjectOpts {
  name: string;
  description: string;
  target_url: string;
  project_type: ProjectType;
  is_temporary: boolean;
  temp_ttl_hours?: number;
  proxy_port: number;
  auto_start_proxy: boolean;
  auto_launch_browser: boolean;
  initial_scope: string[];
  intercept_enabled: boolean;
  client_name: string;
  tags: string[];
  max_traffic_entries: number;
  notes_template: string;
}

export interface MemoryStats {
  process_rss_mb: number;
  traffic_entries: number;
  traffic_ram_mb: number;
  scanner_count: number;
  intruder_count: number;
  cert_cache_size: number;
  ws_messages: number;
  mcp_activity_count: number;
}
