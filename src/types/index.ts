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
