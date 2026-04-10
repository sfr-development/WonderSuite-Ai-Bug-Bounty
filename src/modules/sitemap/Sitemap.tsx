import { useState, useEffect } from 'react';
import { ChevronRight, ChevronDown, Globe, Folder, FileText, Network } from 'lucide-react';
import './Sitemap.css';

interface TreeNode {
  name: string;
  type: 'host' | 'dir' | 'file';
  children?: TreeNode[];
  status?: number;
  method?: string;
  issues?: number;
}

function TreeItem({ node, depth, selected, onSelect }: { node: TreeNode; depth: number; selected: string; onSelect: (n: TreeNode) => void }) {
  const [open, setOpen] = useState(depth < 2);
  const hasChildren = node.children && node.children.length > 0;
  const Icon = node.type === 'host' ? Globe : node.type === 'dir' ? Folder : FileText;

  return (
    <>
      <div
        className={`sitemap-node ${selected === node.name ? 'active' : ''}`}
        style={{ paddingLeft: 8 + depth * 16 }}
        onClick={() => { if (hasChildren) setOpen(!open); onSelect(node); }}
      >
        <span className="sitemap-node-toggle">
          {hasChildren ? (open ? <ChevronDown size={12} /> : <ChevronRight size={12} />) : <span style={{ width: 12 }} />}
        </span>
        <Icon size={13} className={`sitemap-node-icon ${node.type}`} />
        <span className="sitemap-node-name">{node.name}</span>
        {node.method && (
          <span className="sitemap-node-badge" style={{ background: 'var(--bg-3)', color: 'var(--method-get)' }}>{node.method}</span>
        )}
        {node.status && (
          <span className="sitemap-node-badge" style={{ color: node.status < 300 ? 'var(--green)' : node.status < 400 ? 'var(--accent)' : 'var(--red)' }}>{node.status}</span>
        )}
        {(node.issues || 0) > 0 && (
          <span className="sitemap-node-badge" style={{ background: 'rgba(239,68,68,0.15)', color: 'var(--red)' }}>{node.issues}</span>
        )}
      </div>
      {open && hasChildren && node.children!.map((child, i) => (
        <TreeItem key={i} node={child} depth={depth + 1} selected={selected} onSelect={onSelect} />
      ))}
    </>
  );
}

/** Build sitemap tree from traffic entries */
function buildTreeFromTraffic(entries: any[]): TreeNode[] {
  const hostMap = new Map<string, TreeNode>();

  for (const entry of entries) {
    try {
      const url = new URL(entry.url || entry.host || '');
      const hostKey = `${url.protocol}//${url.host}`;

      if (!hostMap.has(hostKey)) {
        hostMap.set(hostKey, {
          name: hostKey,
          type: 'host',
          children: [],
          issues: 0,
        });
      }

      const host = hostMap.get(hostKey)!;
      const path = url.pathname || '/';

      // Check if path already exists
      const existing = host.children?.find((c) => c.name === path);
      if (!existing) {
        host.children!.push({
          name: path,
          type: 'file',
          method: entry.method || 'GET',
          status: entry.status || 200,
        });
      }
    } catch {}
  }

  return Array.from(hostMap.values());
}

export function Sitemap() {
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [selected, setSelected] = useState('');
  const [selectedNode, setSelectedNode] = useState<TreeNode | null>(null);
  const [detailTab, setDetailTab] = useState<'requests' | 'issues'>('requests');
  const [filter, setFilter] = useState('');

  // Build sitemap from proxy traffic
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    (async () => {
      try {
        // Load existing traffic
        const { invoke } = await import('@tauri-apps/api/core');
        const traffic = await invoke<any[]>('proxy_get_traffic');
        if (traffic?.length) {
          setTree(buildTreeFromTraffic(traffic));
        }

        // Listen for new traffic
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen<any>('proxy-event', (event) => {
          if (event.payload?.type === 'traffic') {
            const entry = event.payload.entry;
            setTree((prev) => {
              const all = [...prev];
              // Quick merge
              try {
                const url = new URL(entry.url || entry.host || '');
                const hostKey = `${url.protocol}//${url.host}`;
                let host = all.find((h) => h.name === hostKey);
                if (!host) {
                  host = { name: hostKey, type: 'host', children: [], issues: 0 };
                  all.push(host);
                }
                const path = url.pathname || '/';
                if (!host.children?.find((c) => c.name === path)) {
                  host.children = host.children || [];
                  host.children.push({
                    name: path,
                    type: 'file',
                    method: entry.method || 'GET',
                    status: entry.status || 200,
                  });
                }
              } catch {}
              return all;
            });
          }
        });
      } catch {}
    })();

    return () => { unlisten?.(); };
  }, []);

  const handleSelect = (n: TreeNode) => { setSelected(n.name); setSelectedNode(n); };

  const totalEndpoints = tree.reduce((sum, h) => sum + (h.children?.length || 0), 0);

  return (
    <div className="sitemap">
      <div className="sitemap-tree">
        <div className="sitemap-tree-header">
          <span>Site Map</span>
          <span style={{ color: 'var(--text-2)', fontWeight: 400, textTransform: 'none' }}>{totalEndpoints} endpoints</span>
        </div>
        <input
          className="sitemap-tree-filter"
          placeholder="Filter..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <div className="sitemap-tree-list">
          {tree.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-3)', gap: 8 }}>
              <Network size={24} />
              <span style={{ fontSize: 11 }}>No sites discovered</span>
              <span style={{ fontSize: 10 }}>Start the proxy and browse to populate</span>
            </div>
          ) : (
            tree.map((node, i) => (
              <TreeItem key={i} node={node} depth={0} selected={selected} onSelect={handleSelect} />
            ))
          )}
        </div>
      </div>

      <div className="sitemap-detail">
        {selectedNode ? (
          <>
            <div className="sitemap-detail-header">
              <Network size={14} style={{ color: 'var(--accent)' }} />
              <span className="sitemap-detail-url">{selectedNode.name}</span>
            </div>
            <div className="sitemap-detail-tabs">
              <button className={`sitemap-detail-tab ${detailTab === 'requests' ? 'active' : ''}`} onClick={() => setDetailTab('requests')}>Requests</button>
              <button className={`sitemap-detail-tab ${detailTab === 'issues' ? 'active' : ''}`} onClick={() => setDetailTab('issues')}>Issues ({selectedNode.issues || 0})</button>
            </div>
            <div className="sitemap-detail-content">
              {detailTab === 'requests' && (
                <table className="sitemap-issues-table">
                  <thead><tr><th>Method</th><th>URL</th><th>Status</th></tr></thead>
                  <tbody>
                    {selectedNode.type === 'host' && selectedNode.children?.map((child, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 600, color: 'var(--method-get)' }}>{child.method || 'GET'}</td>
                        <td style={{ fontFamily: 'monospace' }}>{child.name}</td>
                        <td style={{ color: (child.status || 200) < 300 ? 'var(--green)' : 'var(--red)' }}>{child.status || 200}</td>
                      </tr>
                    ))}
                    {selectedNode.type === 'file' && (
                      <tr>
                        <td style={{ fontWeight: 600, color: 'var(--method-get)' }}>{selectedNode.method || 'GET'}</td>
                        <td style={{ fontFamily: 'monospace' }}>{selectedNode.name}</td>
                        <td style={{ color: (selectedNode.status || 200) < 300 ? 'var(--green)' : 'var(--red)' }}>{selectedNode.status || 200}</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              )}
              {detailTab === 'issues' && (
                <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-3)', fontSize: 11 }}>
                  No issues found for this endpoint
                </div>
              )}
            </div>
          </>
        ) : (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)' }}>
            <div style={{ textAlign: 'center' }}>
              <Network size={32} style={{ marginBottom: 8 }} />
              <div style={{ fontSize: 12 }}>{tree.length === 0 ? 'Start proxy to build sitemap' : 'Select an endpoint from the sitemap'}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
