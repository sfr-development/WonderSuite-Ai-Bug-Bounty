import { lazy } from 'react';
import { Loader2 } from 'lucide-react';

export const moduleMap: Record<string, React.LazyExoticComponent<React.ComponentType>> = {
  dashboard:  lazy(() => import('../../modules/dashboard/Dashboard').then(m => ({ default: m.Dashboard }))),
  intercept:  lazy(() => import('../../modules/intercept/Intercept').then(m => ({ default: m.Intercept }))),
  traffic:    lazy(() => import('../../modules/traffic/Traffic').then(m => ({ default: m.Traffic }))),
  replay:     lazy(() => import('../../modules/replay/Replay').then(m => ({ default: m.Replay }))),
  attack:     lazy(() => import('../../modules/attack/Attack').then(m => ({ default: m.Attack }))),
  scan:       lazy(() => import('../../modules/scan/Scan').then(m => ({ default: m.Scan }))),
  ports:      lazy(() => import('../../modules/ports/Ports').then(m => ({ default: m.Ports }))),
  sitemap:    lazy(() => import('../../modules/sitemap/Sitemap').then(m => ({ default: m.Sitemap }))),
  tokens:     lazy(() => import('../../modules/tokens/Tokens').then(m => ({ default: m.Tokens }))),
  tools:      lazy(() => import('../../modules/tools/Tools').then(m => ({ default: m.Tools }))),
  findings:   lazy(() => import('../../modules/findings/Findings').then(m => ({ default: m.Findings }))),
  comparer:   lazy(() => import('../../modules/comparer/Comparer').then(m => ({ default: m.Comparer }))),
  logger:     lazy(() => import('../../modules/logger/Logger').then(m => ({ default: m.Logger }))),
  organizer:  lazy(() => import('../../modules/organizer/Organizer').then(m => ({ default: m.Organizer }))),
  agent:      lazy(() => import('../../modules/agent/Agent').then(m => ({ default: m.Agent }))),
  templates:  lazy(() => import('../../modules/templates/Templates').then(m => ({ default: m.Templates }))),
  payloads:   lazy(() => import('../../modules/payloads/Payloads').then(m => ({ default: m.Payloads }))),
  session:    lazy(() => import('../../modules/session/Session').then(m => ({ default: m.Session }))),
  websocket:  lazy(() => import('../../modules/websocket/WebSocket').then(m => ({ default: m.WebSocket }))),
  oast:       lazy(() => import('../../modules/oast/Oast').then(m => ({ default: m.Oast }))),
  discovery:  lazy(() => import('../../modules/discovery/Discovery').then(m => ({ default: m.Discovery }))),
  osint:      lazy(() => import('../../modules/osint/Osint').then(m => ({ default: m.Osint }))),
  docs:       lazy(() => import('../../modules/docs/Docs').then(m => ({ default: m.Docs }))),
  settings:   lazy(() => import('../../modules/settings/Settings').then(m => ({ default: m.Settings }))),
};

export const moduleLabels: Record<string, string> = {
  dashboard: 'Dashboard', intercept: 'Intercept', traffic: 'Traffic',
  replay: 'Repeater', attack: 'Intruder', scan: 'Scanner', ports: 'Ports',
  sitemap: 'Sitemap', tokens: 'Sequencer', tools: 'Tools',
  findings: 'Findings', comparer: 'Comparer', logger: 'Logger',
  organizer: 'Organizer', agent: 'Agent', templates: 'Templates',
  payloads: 'Payloads', session: 'Session', websocket: 'WebSocket',
  oast: 'OAST', discovery: 'Discovery', osint: 'OSINT',
  docs: 'Documentation', settings: 'Settings',
};

export function ModuleSkeleton() {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      flex: 1, color: 'var(--text-3)', gap: 8,
    }}>
      <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
      <span style={{ fontSize: 12 }}>Loading module…</span>
    </div>
  );
}
