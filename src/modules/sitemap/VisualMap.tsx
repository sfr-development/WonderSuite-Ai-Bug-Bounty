import { useEffect, useCallback } from 'react';
import {
  ReactFlow, Background, MiniMap,
  useNodesState, useEdgesState, Handle, Position,
  Node, Edge, MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from 'dagre';
import { Globe, Folder, FileText, FileCode, Palette, Type, Image, Zap, Lock } from 'lucide-react';
import { TreeNode } from './Sitemap';
import { useAppStore } from '../../stores';

const typeColors: Record<string, string> = {
  host: '#e8a145', dir: '#6e6e6e', file: '#a0a0a0', js: '#e8a145',
  css: '#5b9fd6', font: '#a78bda', image: '#4ec58a', api: '#e8a145', media: '#56c5c5',
};

const TypeIcons: Record<string, typeof FileText> = {
  host: Globe, dir: Folder, file: FileText, js: FileCode,
  css: Palette, font: Type, image: Image, api: Zap, media: FileText,
};

const mc = (m: string) => {
  const c: Record<string,string> = { GET:'#4ec58a', POST:'#5b9fd6', PUT:'#e8873c', DELETE:'#d95757', PATCH:'#a78bda' };
  return c[m] || '#6e6e6e';
};

/* ── Node Components ── */

const HostNode = ({ data }: { data: any }) => (
  <div style={{
    background: 'var(--bg-2)', border: `2px solid ${typeColors.host}`, borderRadius: 'var(--radius-l)',
    padding: '12px 16px', minWidth: 180, display: 'flex', flexDirection: 'column', gap: 6,
    boxShadow: 'var(--shadow-md)', color: 'var(--text-0)', backdropFilter: 'blur(8px)'
  }}>
    <Handle type="target" position={Position.Left} style={{ background: 'var(--text-2)', border: 'none' }} />
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <Globe size={16} style={{ color: typeColors.host }} />
      <span style={{ fontWeight: 700, fontSize: 11, fontFamily: 'monospace', maxWidth: 170, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.label}</span>
      {data.tls && <Lock size={10} style={{ color: '#4ec58a' }} />}
    </div>
    {data.childCount > 0 && (
      <div style={{ fontSize: 9, color: 'var(--text-2)' }}>{data.childCount} endpoints</div>
    )}
    <Handle type="source" position={Position.Right} style={{ background: 'var(--text-2)', border: 'none' }} />
  </div>
);

const DirNode = ({ data }: { data: any }) => (
  <div style={{
    background: 'var(--bg-1)', border: `1px solid #6e6e6e`, borderRadius: 'var(--radius-m)',
    padding: '6px 10px', minWidth: 100, display: 'flex', alignItems: 'center', gap: 6,
    boxShadow: 'var(--shadow-sm)', color: 'var(--text-1)'
  }}>
    <Handle type="target" position={Position.Left} style={{ background: '#6e6e6e', border: 'none' }} />
    <Folder size={12} style={{ color: '#6e6e6e' }} />
    <span style={{ fontWeight: 600, fontSize: 10, fontFamily: 'monospace' }}>{data.label}</span>
    <span style={{ fontSize: 8, color: 'var(--text-3)', marginLeft: 2 }}>{data.count}</span>
    <Handle type="source" position={Position.Right} style={{ background: '#6e6e6e', border: 'none' }} />
  </div>
);

const PathNode = ({ data }: { data: any }) => {
  const Icon = TypeIcons[data.resType] || FileText;
  const borderColor = typeColors[data.resType] || '#6e6e6e';
  return (
    <div style={{
      background: 'var(--bg-1)', border: `1px solid ${borderColor}`, borderRadius: 'var(--radius-m)',
      padding: '6px 10px', minWidth: 120, maxWidth: 200, display: 'flex', flexDirection: 'column', gap: 3,
      boxShadow: 'var(--shadow-sm)', color: 'var(--text-0)'
    }}>
      <Handle type="target" position={Position.Left} style={{ background: borderColor, border: 'none' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
        <Icon size={11} style={{ color: borderColor, flexShrink: 0 }} />
        <span style={{ fontWeight: 500, fontSize: 10, fontFamily: 'monospace', maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.label}</span>
      </div>
      <div style={{ display: 'flex', gap: 3, alignItems: 'center' }}>
        {data.method && (
          <span style={{ fontSize: 8, padding: '1px 3px', background: 'var(--bg-3)', borderRadius: 2, color: mc(data.method), fontWeight: 600 }}>{data.method}</span>
        )}
        {data.status && (
          <span style={{ fontSize: 8, padding: '1px 3px', borderRadius: 2, fontWeight: 600,
            background: data.status < 300 ? 'rgba(78,197,138,0.15)' : 'rgba(217,87,87,0.15)',
            color: data.status < 300 ? '#4ec58a' : '#d95757'
          }}>{data.status}</span>
        )}
        {data.size > 0 && <span style={{ fontSize: 7, color: 'var(--text-3)' }}>{data.size > 1024 ? `${(data.size/1024).toFixed(0)}KB` : `${data.size}B`}</span>}
      </div>
      <Handle type="source" position={Position.Right} style={{ background: borderColor, border: 'none' }} />
    </div>
  );
};

const nodeTypes = { host: HostNode, path: PathNode, dir: DirNode };

/* ── Dagre Layout ── */

const getLayoutedElements = (nodes: Node[], edges: Edge[]) => {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'LR', ranksep: 100, nodesep: 16, edgesep: 10, marginx: 20, marginy: 20 });
  const dims: Record<string, { w: number; h: number }> = {
    host: { w: 220, h: 65 },
    dir:  { w: 140, h: 36 },
    path: { w: 180, h: 50 },
  };
  nodes.forEach(n => {
    const d = dims[n.type || 'path'] || dims.path;
    g.setNode(n.id, { width: d.w, height: d.h });
  });
  edges.forEach(e => { g.setEdge(e.source, e.target); });
  dagre.layout(g);
  nodes.forEach(n => {
    const p = g.node(n.id);
    const d = dims[n.type || 'path'] || dims.path;
    n.targetPosition = Position.Left;
    n.sourcePosition = Position.Right;
    n.position = { x: p.x - d.w / 2, y: p.y - d.h / 2 };
  });
  return { nodes, edges };
};

/* ── Build graph with directory grouping ── */

function buildGraph(tree: TreeNode[]): { nodes: Node[]; edges: Edge[] } {
  const iN: Node[] = []; const iE: Edge[] = [];

  for (const host of tree) {
    const hostId = host.name;
    iN.push({ id: hostId, type: 'host', data: { label: host.name, tls: host.tls, childCount: host.children?.length || 0, rawData: host }, position: { x: 0, y: 0 } });

    if (!host.children || host.children.length === 0) continue;

    const dirGroups = new Map<string, TreeNode[]>();
    const rootFiles: TreeNode[] = [];

    for (const child of host.children) {
      const segments = child.name.split('/').filter(Boolean);
      if (segments.length > 1) {
        const dirKey = '/' + segments[0];
        if (!dirGroups.has(dirKey)) dirGroups.set(dirKey, []);
        dirGroups.get(dirKey)!.push(child);
      } else {
        rootFiles.push(child);
      }
    }

    for (const file of rootFiles) {
      const fId = `${hostId}::${file.name}`;
      const fullUrl = `${host.name}${file.name === '/' ? '' : file.name}`;
      iN.push({ id: fId, type: 'path', data: { label: file.name || '/', resType: file.type, method: file.method, status: file.status, size: file.response_length || 0, url: fullUrl, rawData: file }, position: { x: 0, y: 0 } });
      iE.push({ id: `e-${fId}`, source: hostId, target: fId, type: 'smoothstep', animated: false,
        style: { stroke: mc(file.method || 'GET'), strokeWidth: 1.2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: mc(file.method || 'GET'), width: 10, height: 10 },
      });
    }

    for (const [dir, files] of dirGroups) {
      const dirId = `${hostId}::dir::${dir}`;
      iN.push({ id: dirId, type: 'dir', data: { label: dir, count: files.length }, position: { x: 0, y: 0 } });
      iE.push({ id: `e-${dirId}`, source: hostId, target: dirId, type: 'smoothstep', animated: false,
        style: { stroke: '#6e6e6e', strokeWidth: 1.2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#6e6e6e', width: 8, height: 8 },
      });

      for (const file of files) {
        const segments = file.name.split('/').filter(Boolean);
        const shortName = segments.slice(1).join('/') || file.name;
        const fId = `${hostId}::${file.name}`;
        const fullUrl = `${host.name}${file.name}`;
        iN.push({ id: fId, type: 'path', data: { label: shortName, resType: file.type, method: file.method, status: file.status, size: file.response_length || 0, url: fullUrl, rawData: file }, position: { x: 0, y: 0 } });
        iE.push({ id: `e-${fId}`, source: dirId, target: fId, type: 'smoothstep', animated: false,
          style: { stroke: mc(file.method || 'GET'), strokeWidth: 1 },
          markerEnd: { type: MarkerType.ArrowClosed, color: mc(file.method || 'GET'), width: 8, height: 8 },
        });
      }
    }
  }

  return { nodes: iN, edges: iE };
}

/* ── Component ── */

interface VisualMapProps { tree: TreeNode[]; onNodeSelect: (n: TreeNode) => void; }

export function VisualMap({ tree, onNodeSelect }: VisualMapProps) {
  const { openContextMenu } = useAppStore();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    const { nodes: rawN, edges: rawE } = buildGraph(tree);
    const { nodes: ln, edges: le } = getLayoutedElements(rawN, rawE);
    setNodes(ln); setEdges(le);
  }, [tree, setNodes, setEdges]);

  const onNodeClick = useCallback((_: any, node: Node) => {
    if (node.data?.rawData) onNodeSelect(node.data.rawData as TreeNode);
  }, [onNodeSelect]);

  const onNodeContextMenu = useCallback((e: React.MouseEvent, node: Node) => {
    e.preventDefault();
    openContextMenu(e.clientX, e.clientY, {
      method: (node.data.method || 'GET') as string, url: (node.data.url || node.data.label) as string,
      requestRaw: `${node.data.method||'GET'} ${node.data.label} HTTP/1.1\r\nHost: target\r\n\r\n`,
      responseRaw: 'HTTP/1.1 200 OK\r\n\r\n',
    });
  }, [openContextMenu]);

  return (
    <div style={{ width: '100%', height: '100%', background: 'var(--bg-0)' }}>
      <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes} onNodeClick={onNodeClick} onNodeContextMenu={onNodeContextMenu}
        fitView minZoom={0.1} maxZoom={2} proOptions={{ hideAttribution: true }}>
        <Background color="var(--border-2)" gap={20} size={1} />
        <MiniMap style={{ background: 'var(--bg-1)', border: '1px solid var(--border-0)' }}
          nodeColor={(n: Node) => typeColors[(n.data as any)?.resType || (n.data as any)?.type || 'file'] || '#6e6e6e'}
          maskColor="rgba(0,0,0,0.6)" />
      </ReactFlow>
    </div>
  );
}
