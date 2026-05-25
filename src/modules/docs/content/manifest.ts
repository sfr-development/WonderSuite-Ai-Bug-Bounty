export interface DocPage {
  /** matches the markdown filename without extension, e.g. "intercept" -> content/intercept.md */
  slug: string;
  title: string;
}

export interface DocGroup {
  title: string;
  pages: DocPage[];
}

/**
 * Defines the order and grouping of the documentation table of contents.
 * Each page's `slug` must have a matching `content/<slug>.md` file.
 */
export const DOC_GROUPS: DocGroup[] = [
  {
    title: 'Getting Started',
    pages: [
      { slug: 'overview', title: 'Overview' },
      { slug: 'projects', title: 'Projects & Launcher' },
      { slug: 'workspace', title: 'The Workspace' },
      { slug: 'shortcuts', title: 'Keyboard Shortcuts' },
    ],
  },
  {
    title: 'Core',
    pages: [
      { slug: 'dashboard', title: 'Dashboard' },
      { slug: 'intercept', title: 'Intercept' },
      { slug: 'traffic', title: 'Traffic' },
    ],
  },
  {
    title: 'Testing',
    pages: [
      { slug: 'repeater', title: 'Repeater' },
      { slug: 'intruder', title: 'Intruder' },
      { slug: 'scanner', title: 'Scanner' },
      { slug: 'ports', title: 'Ports' },
      { slug: 'websocket', title: 'WebSocket' },
      { slug: 'oast', title: 'OAST' },
    ],
  },
  {
    title: 'Recon',
    pages: [
      { slug: 'sitemap', title: 'Sitemap' },
      { slug: 'discovery', title: 'Discovery' },
      { slug: 'osint', title: 'OSINT' },
    ],
  },
  {
    title: 'Analysis',
    pages: [
      { slug: 'sequencer', title: 'Sequencer' },
      { slug: 'comparer', title: 'Comparer' },
      { slug: 'logger', title: 'Logger' },
      { slug: 'templates', title: 'Templates' },
      { slug: 'payloads', title: 'Payloads' },
    ],
  },
  {
    title: 'Workflow',
    pages: [
      { slug: 'organizer', title: 'Organizer' },
      { slug: 'session', title: 'Session' },
      { slug: 'agent', title: 'Agent' },
      { slug: 'tools', title: 'Tools' },
      { slug: 'findings', title: 'Findings' },
    ],
  },
  {
    title: 'Settings',
    pages: [
      { slug: 'settings-general', title: 'General' },
      { slug: 'settings-mcp', title: 'MCP Server' },
      { slug: 'settings-proxy', title: 'Proxy' },
      { slug: 'settings-appearance', title: 'Appearance' },
      { slug: 'settings-browser', title: 'Browser' },
      { slug: 'settings-skill', title: 'AI Skill' },
    ],
  },
  {
    title: 'Reference',
    pages: [
      { slug: 'mcp-tools', title: 'MCP Tools Reference' },
      { slug: 'glossary', title: 'Glossary' },
    ],
  },
];

/** Flat list of every page in TOC order. */
export const DOC_PAGES: DocPage[] = DOC_GROUPS.flatMap((g) => g.pages);

/** Resolve which group a slug belongs to. */
export function groupOf(slug: string): string {
  for (const g of DOC_GROUPS) {
    if (g.pages.some((p) => p.slug === slug)) return g.title;
  }
  return '';
}

/** Resolve the display title for a slug. */
export function titleOf(slug: string): string {
  for (const g of DOC_GROUPS) {
    const p = g.pages.find((p) => p.slug === slug);
    if (p) return p.title;
  }
  return slug;
}
