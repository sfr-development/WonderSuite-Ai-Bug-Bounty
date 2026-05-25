import { useState, useEffect } from 'react';
import { Lightbulb } from 'lucide-react';
import './Splash.css';

interface Props {
  onFinish: () => void;
}

const PENTEST_TIPS = [
  'Set the project scope first. The in-scope filter saves hours of noise later.',
  'Press F1 anywhere in WonderSuite to open the in-app Documentation tab.',
  'Right-click any captured request to send it to Repeater, Intruder or Findings.',
  'WonderBrowser is fully isolated from your system Chrome — different profile, cache and cookies.',
  'Stealth profile "Human" defeats most fraud SDKs out of the box. Bump to "Paranoid" only for Akamai-class targets.',
  'OAST callbacks confirm blind vulns. Generate a payload, inject it, watch the Interactions tab.',
  'The Sitemap builds itself from proxy traffic — no separate crawl step needed.',
  'Intruder Pitchfork mode advances payload sets in parallel — perfect for username + password lists.',
  'Quick Sessions live in memory only. Save a project if you want the traffic to survive a restart.',
  'Plug any MCP-compatible AI client into http://127.0.0.1:3100/mcp to let it drive the whole tool surface.',
  'Browser MCP clicks/keystrokes have event.isTrusted === true — invisible to bot-detection that drops programmatic input.',
  'Templates run dozens of detection probes in one click. Send each hit to Findings for the report.',
  'Match & Replace rules rewrite traffic in flight — strip auth headers, inject scope tags, mass-rewrite hosts.',
  'JWT in a response? Tools → JWT decodes header + payload and flags alg:none / expired tokens instantly.',
  'analyze_jwt (MCP tool) catches kid-as-SQLi, jku/x5u SSRF and HS/RS key-confusion in a single call.',
  'crt.sh + Discovery → Subdomains is more thorough than DNS brute-force alone. Both run in one click.',
  'Sequencer + 100 captured session tokens gives you a FIPS 140-2 randomness verdict in seconds.',
  'Project scope accepts wildcards. Add both target.com and *.target.com for full coverage.',
  'Turbo Intruder fires N requests at the same microsecond — race conditions show up as a status-code spread.',
  'Findings aggregates Scanner + Templates hits. One JSON export = the basis of your final report.',
  'Right-click a Discovery result → Add to scope. Faster than typing the hostname back into Settings.',
  'Impersonate Chrome TLS (Settings → Browser) defeats Cloudflare, Akamai Bot Manager, DataDome and PerimeterX at the TLS layer.',
  'browser_storage_full dumps cookies + localStorage + sessionStorage + IDB + ServiceWorker caches in a single MCP call.',
  'robots.txt and /.well-known are high-priority leads. The operator marked those paths as "hide-me", so they tend to be juicy.',
  'Comparer takes two responses side-by-side — perfect for "did my payload actually change anything?" checks.',
  'Use the project Notes field for engagement context. The MCP server hands those notes to the AI as part of every session.',
] as const;

export function Splash({ onFinish }: Props) {
  const [status, setStatus] = useState('Initializing core...');
  const [fading, setFading] = useState(false);
  const [tip] = useState(() => PENTEST_TIPS[Math.floor(Math.random() * PENTEST_TIPS.length)]);

  useEffect(() => {
    const steps = [
      [400, 'Loading modules...'],
      [900, 'Starting engine...'],
      [1400, 'Connecting services...'],
      [1800, 'Ready'],
    ] as const;

    const timers = steps.map(([ms, text]) =>
      setTimeout(() => setStatus(text as string), ms)
    );

    const fadeTimer = setTimeout(() => setFading(true), 2000);
    const doneTimer = setTimeout(onFinish, 2400);

    return () => {
      timers.forEach(clearTimeout);
      clearTimeout(fadeTimer);
      clearTimeout(doneTimer);
    };
  }, [onFinish]);

  return (
    <div className={`splash ${fading ? 'fade-out' : ''}`}>
      <div className="splash-logo">
        <img src="/wondersuite_logo.png" alt="WonderSuite" className="splash-logo-img" />
      </div>
      <div className="splash-bar">
        <div className="splash-bar-fill" />
      </div>
      <div className="splash-status">{status}</div>
      <div className="splash-tip">
        <Lightbulb size={11} className="splash-tip-icon" />
        <span>{tip}</span>
      </div>
    </div>
  );
}
