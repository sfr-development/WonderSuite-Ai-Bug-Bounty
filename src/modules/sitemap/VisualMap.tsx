import { useEffect, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  Node,
  Edge,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from 'dagre';
import { Globe, Folder, FileText } from 'lucide-react';
import { TreeNode } from './Sitemap';
import { useAppStore } from '../../stores';

// --- Custom Nodes ---

const HostNode = ({ data }: { data: any }) => {
  return (
    <div style={{
      background: 'var(--bg-2)', border: '2px solid var(--border-0)', borderRadius: 'var(--radius-l)',
      padding: '12px 16px', minWidth: 200, display: 'flex', flexDirection: 'column', gap: 8,
      boxShadow: 'var(--shadow-md)', color: 'var(--text-0)', backdropFilter: 'blur(8px)'
    }}>
      <Handle type="target" position={Position.Left} style={{ background: 'var(--text-2)', border: 'none' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Globe size={18} style={{ color: 'var(--accent)' }} />
        <span style={{ fontWeight: 700, fontSize: 13, fontFamily: 'monospace' }}>{data.label}</span>
      </div>
      {(data.issues || 0) > 0 && (
        <div style={{ 
          background: 'rgba(239,68,68,0.15)', color: 'var(--red)', 
          padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600, alignSelf: 'flex-start'
        }}>
          {data.issues} Issues
        </div>
      )}
      <Handle type="source" position={Position.Right} style={{ background: 'var(--text-2)', border: 'none' }} />
    </div>
  );
};

const PathNode = ({ data }: { data: any }) => {
  return (
    <div style={{
      background: 'var(--bg-1)', border: '1px solid var(--border-0)', borderRadius: 'var(--radius-m)',
      padding: '8px 12px', minWidth: 150, display: 'flex', flexDirection: 'column', gap: 4,
      boxShadow: 'var(--shadow-sm)', color: 'var(--text-0)'
    }}>
      <Handle type="target" position={Position.Left} style={{ background: 'var(--text-2)', border: 'none' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {data.type === 'dir' ? <Folder size={14} style={{ color: 'var(--text-2)' }} /> : <FileText size={14} style={{ color: 'var(--text-2)' }} />}
        <span style={{ fontWeight: 500, fontSize: 11, fontFamily: 'monospace' }}>{data.label}</span>
      </div>
      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
        {data.method && (
          <span style={{ fontSize: 9, padding: '2px 4px', background: 'var(--bg-3)', borderRadius: 2, color: 'var(--method-get)', fontWeight: 600 }}>
            {data.method}
          </span>
        )}
        {data.status && (
          <span style={{ fontSize: 9, padding: '2px 4px', borderRadius: 2, fontWeight: 600,
            background: data.status < 300 ? 'rgba(78,197,138,0.15)' : 'rgba(217,87,87,0.15)',
            color: data.status < 300 ? 'var(--green)' : 'var(--red)'
          }}>
            {data.status}
          </span>
        )}
      </div>
      <Handle type="source" position={Position.Right} style={{ background: 'var(--text-2)', border: 'none' }} />
    </div>
  );
};

const nodeTypes = {
  host: HostNode,
  path: PathNode,
};

// --- DAGRE Layout Engine ---
const dagreGraph = new dagre.graphlib.Graph();
dagreGraph.setDefaultEdgeLabel(() => ({}));

const getLayoutedElements = (nodes: Node[], edges: Edge[], direction = 'LR') => {
  const isHorizontal = direction === 'LR';
  dagreGraph.setGraph({ rankdir: direction, ranksep: 80, nodesep: 40 });

  nodes.forEach((node) => {
    const isHost = node.type === 'host';
    dagreGraph.setNode(node.id, { width: isHost ? 220 : 160, height: isHost ? 80 : 50 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  nodes.forEach((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    node.targetPosition = isHorizontal ? Position.Left : Position.Top;
    node.sourcePosition = isHorizontal ? Position.Right : Position.Bottom;

    node.position = {
      x: nodeWithPosition.x - (node.type === 'host' ? 220 : 160) / 2,
      y: nodeWithPosition.y - (node.type === 'host' ? 80 : 50) / 2,
    };
  });

  return { nodes, edges };
};

// --- Main Map Component ---
interface VisualMapProps {
  tree: TreeNode[];
  onNodeSelect: (nodeData: TreeNode) => void;
}

export function VisualMap({ tree, onNodeSelect }: VisualMapProps) {
  const { openContextMenu } = useAppStore();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    const initialNodes: Node[] = [];
    const initialEdges: Edge[] = [];

    tree.forEach((host) => {
      initialNodes.push({
        id: host.name,
        type: 'host',
        data: { label: host.name, type: 'host', issues: host.issues, rawData: host },
        position: { x: 0, y: 0 }
      });

      if (host.children) {
        host.children.forEach((child) => {
          const childId = `${host.name}-${child.name}`;
          const fullUrl = `${host.name}${child.name === '/' ? '' : child.name}`;
          initialNodes.push({
            id: childId,
            type: 'path',
            data: { label: child.name, type: child.type, method: child.method, status: child.status, url: fullUrl, rawData: child },
            position: { x: 0, y: 0 }
          });
          initialEdges.push({
            id: `e-${host.name}-${childId}`,
            source: host.name,
            target: childId,
            type: 'smoothstep',
            animated: true,
            style: { stroke: 'var(--text-3)', strokeWidth: 1.5 },
            markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--text-3)' }
          });
        });
      }
    });

    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(initialNodes, initialEdges, 'LR');
    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
  }, [tree, setNodes, setEdges]);

  const onNodeClick = useCallback((_: any, node: Node) => {
    if (node.data && node.data.rawData) {
      onNodeSelect(node.data.rawData as TreeNode);
    }
  }, [onNodeSelect]);

  const onNodeContextMenu = useCallback((e: React.MouseEvent, node: Node) => {
    e.preventDefault();
    const url = node.data.url || node.data.label;
    const method = node.data.method || 'GET';
    openContextMenu(e.clientX, e.clientY, {
      method: method as string,
      url: url as string,
      requestRaw: `${method} ${node.data.label} HTTP/1.1\r\nHost: target\r\n\r\n`,
      responseRaw: 'HTTP/1.1 200 OK\r\n\r\n'
    });
  }, [openContextMenu]);

  return (
    <div style={{ width: '100%', height: '100%', background: 'var(--bg-0)' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        onNodeContextMenu={onNodeContextMenu}
        fitView
        minZoom={0.2}
      >
        <Background color="var(--border-2)" gap={20} size={1.5} />
      </ReactFlow>
    </div>
  );
}
