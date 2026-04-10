import { useState, useCallback } from 'react';
import { Titlebar } from './Titlebar';
import { Sidebar } from './Sidebar';
import { StatusBar } from './StatusBar';
import { Splash } from './Splash';
import { ProjectLauncher } from './ProjectLauncher';
import { useAppStore } from '../../stores';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';
import { Dashboard } from '../../modules/dashboard/Dashboard';
import { Intercept } from '../../modules/intercept/Intercept';
import { Traffic } from '../../modules/traffic/Traffic';
import { Replay } from '../../modules/replay/Replay';
import { Attack } from '../../modules/attack/Attack';
import { Scan } from '../../modules/scan/Scan';
import { Sitemap } from '../../modules/sitemap/Sitemap';
import { Tokens } from '../../modules/tokens/Tokens';
import { Tools } from '../../modules/tools/Tools';
import { Findings } from '../../modules/findings/Findings';
import { Comparer } from '../../modules/comparer/Comparer';
import { Logger } from '../../modules/logger/Logger';
import { Organizer } from '../../modules/organizer/Organizer';
import { Settings } from '../../modules/settings/Settings';
import { Agent } from '../../modules/agent/Agent';
import { Templates } from '../../modules/templates/Templates';
import { Session } from '../../modules/session/Session';
import { WebSocket as WsModule } from '../../modules/websocket/WebSocket';
import { Oast } from '../../modules/oast/Oast';
import { Discovery } from '../../modules/discovery/Discovery';
import { Osint } from '../../modules/osint/Osint';
import './Shell.css';

interface ProjectInfo {
  id: string;
  name: string;
  path: string;
  created_at: string;
  last_opened: string;
  description: string;
  target_url: string;
  request_count: number;
  finding_count: number;
}

const moduleComponents: Record<string, React.FC> = {
  dashboard: Dashboard,
  intercept: Intercept,
  traffic: Traffic,
  replay: Replay,
  attack: Attack,
  scan: Scan,
  sitemap: Sitemap,
  tokens: Tokens,
  tools: Tools,
  findings: Findings,
  comparer: Comparer,
  logger: Logger,
  organizer: Organizer,
  agent: Agent,
  templates: Templates,
  session: Session,
  websocket: WsModule,
  oast: Oast,
  discovery: Discovery,
  osint: Osint,
  settings: Settings,
};

export function Shell() {
  const [splashDone, setSplashDone] = useState(false);
  const [activeProject, setActiveProject] = useState<ProjectInfo | null>(null);
  const activeModule = useAppStore((s) => s.activeModule);
  const handleSplashFinish = useCallback(() => setSplashDone(true), []);
  useKeyboardShortcuts();

  if (!splashDone) {
    return (
      <div className="shell">
        <Splash onFinish={handleSplashFinish} />
      </div>
    );
  }

  if (!activeProject) {
    return (
      <ProjectLauncher
        onOpen={(project) => setActiveProject(project)}
        onTempProject={() => setActiveProject({
          id: 'temp',
          name: 'Temporary Project',
          path: '',
          created_at: new Date().toISOString(),
          last_opened: new Date().toISOString(),
          description: 'In-memory session, data will not be saved',
          target_url: '',
          request_count: 0,
          finding_count: 0,
        })}
      />
    );
  }

  return (
    <div className="shell">
      <Titlebar />
      <div className="shell-body">
        <Sidebar />
        <div className="shell-main">
          <div className="shell-content-container">
            {Object.entries(moduleComponents).map(([id, Mod]) => (
              <div
                key={id}
                className="shell-content"
                style={{ display: activeModule === id ? 'flex' : 'none' }}
              >
                <Mod />
              </div>
            ))}
          </div>
          <StatusBar projectName={activeProject?.name} />
        </div>
      </div>
    </div>
  );
}
