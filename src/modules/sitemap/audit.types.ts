export type AssetType = 'html' | 'js' | 'css' | 'image' | 'font' | 'media' | 'api' | 'other';
export type FindingType = 'link' | 'token' | 'secret' | 'api_endpoint' | 'comment' | 'library';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface AuditAsset {
  id: string;
  url: string;
  path: string;
  filename: string;
  type: AssetType;
  size?: number;
  mimeType?: string;
  content?: string;
  loadedDynamically: boolean;
  status?: number;
  responseTime?: number;
}

export interface AuditFinding {
  id: string;
  type: FindingType;
  value: string;
  context: string;
  lineNumber: number;
  severity: Severity;
  assetUrl: string;
  patternName: string;
}

export interface AuditStats {
  totalAssets: number;
  byType: Record<AssetType, number>;
  totalSize: number;
  findingsBySeverity: Record<Severity, number>;
  findingsByType: Record<FindingType, number>;
}

export interface AuditSettings {
  enabledTypes: Record<AssetType, boolean>;
  browserMode: 'proxy' | 'headless' | 'browser';
  enabledFinders: Record<FindingType, boolean>;
  beautifyByDefault: boolean;
}

export const DEFAULT_SETTINGS: AuditSettings = {
  enabledTypes: {
    html: true, js: true, css: true,
    image: true, font: false, media: false,
    api: true, other: false,
  },
  browserMode: 'proxy',
  enabledFinders: {
    link: true, token: true, secret: true,
    api_endpoint: true, comment: true, library: true,
  },
  beautifyByDefault: false,
};

export interface AuditResult {
  targetUrl: string;
  scannedAt: string;
  durationMs: number;
  assets: AuditAsset[];
  findings: AuditFinding[];
  stats: AuditStats;
}

export function computeStats(assets: AuditAsset[], findings: AuditFinding[]): AuditStats {
  const byType = { html: 0, js: 0, css: 0, image: 0, font: 0, media: 0, api: 0, other: 0 } as Record<AssetType, number>;
  const findingsBySeverity = { info: 0, low: 0, medium: 0, high: 0, critical: 0 } as Record<Severity, number>;
  const findingsByType = { link: 0, token: 0, secret: 0, api_endpoint: 0, comment: 0, library: 0 } as Record<FindingType, number>;
  let totalSize = 0;
  for (const a of assets) { byType[a.type] = (byType[a.type] || 0) + 1; totalSize += a.size || 0; }
  for (const f of findings) {
    findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;
    findingsByType[f.type] = (findingsByType[f.type] || 0) + 1;
  }
  return { totalAssets: assets.length, byType, totalSize, findingsBySeverity, findingsByType };
}

export function detectAssetType(path: string, mime?: string): AssetType {
  const ext = (path.split('?')[0].split('.').pop() || '').toLowerCase();
  if (['js', 'mjs', 'jsx', 'cjs'].includes(ext) || mime?.includes('javascript')) return 'js';
  if (['css', 'scss', 'less'].includes(ext) || mime?.includes('css')) return 'css';
  if (['html', 'htm'].includes(ext) || mime?.includes('html')) return 'html';
  if (['ttf', 'woff', 'woff2', 'eot', 'otf'].includes(ext) || mime?.includes('font')) return 'font';
  if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'bmp', 'avif'].includes(ext) || mime?.includes('image')) return 'image';
  if (['mp4', 'webm', 'mp3', 'ogg', 'wav'].includes(ext) || mime?.includes('video') || mime?.includes('audio')) return 'media';
  if (/\/(api|v\d|graphql|rest|rpc|gql)\b/.test(path)) return 'api';
  return 'other';
}
