import dagre from 'dagre';
import { DependencyNode as DependencyNodeType, DependencyEdge as DependencyEdgeType, SimulateResponse } from '../types/api';
import { CustomNodeType } from '../components/graph/DependencyNode';
import { CustomEdgeType } from '../components/graph/PropagationEdge';

const NODE_WIDTH = 270;
const NODE_HEIGHT = 92;

export function buildGraphElements(
  nodes: DependencyNodeType[],
  edges: DependencyEdgeType[],
  selectedNodeId: string | null,
  simulation: SimulateResponse | null,
  onSelectNode: (nodeId: string) => void,
  isAnimatingSimulation = false
): { nodes: CustomNodeType[]; edges: CustomEdgeType[] } {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: 'TB',
    nodesep: 45,
    ranksep: 75,
    marginx: 40,
    marginy: 40,
  });

  // Collect simulation affected map
  const affectedMap = new Map<string, { impactType: 'direct' | 'indirect'; depth: number }>();
  let compromisedId: string | null = null;
  let rootImpacted = false;
  let rootId: string | null = null;

  interface PropEdgeInfo {
    hopIndex: number;
    totalHops: number;
  }
  const propEdgeInfoMap = new Map<string, PropEdgeInfo>();

  if (simulation) {
    compromisedId = simulation.compromised_node.node_id;
    rootImpacted = simulation.application_impact.affected;
    rootId = simulation.application_impact.root_node_id;

    for (const aff of simulation.affected_nodes) {
      affectedMap.set(aff.node_id, {
        impactType: aff.impact_type,
        depth: aff.depth,
      });
    }

    // Identify propagation edges from actual backend propagation_paths
    for (const path of simulation.propagation_paths) {
      const totalHops = path.length - 1;
      for (let i = 0; i < totalHops; i++) {
        const fromNode = path[i];     // e.g. body-parser (hop i)
        const toNode = path[i + 1];   // e.g. express (hop i+1)
        // In dependency graph, toNode depends on fromNode (toNode -> fromNode)
        const depEdgeKey = `${toNode}->${fromNode}`;
        propEdgeInfoMap.set(depEdgeKey, { hopIndex: i, totalHops });
        propEdgeInfoMap.set(`${fromNode}->${toNode}`, { hopIndex: i, totalHops });
      }
    }
  }

  // Register nodes with dagre
  for (const n of nodes) {
    g.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }

  // Register edges with dagre
  for (const e of edges) {
    if (g.hasNode(e.source) && g.hasNode(e.target)) {
      g.setEdge(e.source, e.target);
    }
  }

  // Calculate layout
  dagre.layout(g);

  // Convert to React Flow nodes
  const flowNodes: CustomNodeType[] = nodes.map((n) => {
    const dagreNode = g.node(n.id) || { x: 0, y: 0 };
    const isSelected = selectedNodeId === n.id;
    const isCompromised = simulation ? n.id === compromisedId : false;
    const isRootAffected = simulation && rootImpacted && n.id === rootId;
    const aff = affectedMap.get(n.id);
    const isAffected = Boolean(aff);

    const isDimmed = Boolean(
      simulation && !isCompromised && !isAffected && !isRootAffected
    );

    return {
      id: n.id,
      type: 'dependencyNode',
      position: {
        x: dagreNode.x - NODE_WIDTH / 2,
        y: dagreNode.y - NODE_HEIGHT / 2,
      },
      data: {
        node: n,
        isSelected,
        isCompromised,
        isAffected,
        impactType: aff?.impactType,
        impactDepth: aff?.depth,
        isRootAffected: Boolean(isRootAffected),
        isDimmed,
        onSelectNode,
      },
    };
  });

  // Convert to React Flow edges
  const flowEdges: CustomEdgeType[] = edges.map((e, idx) => {
    const edgeKey = `${e.source}->${e.target}`;
    const propInfo = propEdgeInfoMap.get(edgeKey);
    const isPropagationPath = Boolean(propInfo);

    return {
      id: `edge-${idx}-${e.source}-${e.target}`,
      source: e.source,
      target: e.target,
      type: 'propagationEdge',
      data: {
        isPropagationPath,
        isAnimating: isPropagationPath && isAnimatingSimulation,
        hopIndex: propInfo?.hopIndex ?? 0,
        totalHops: propInfo?.totalHops ?? 1,
      },
      style: isPropagationPath
        ? { stroke: '#f43f5e', strokeWidth: 2.5 }
        : { stroke: '#334155', strokeWidth: 1.5 },
      markerStart: isPropagationPath
        ? {
            type: 'arrowclosed' as any,
            color: '#f43f5e',
            width: 14,
            height: 14,
          }
        : undefined,
      markerEnd: isPropagationPath
        ? undefined
        : {
            type: 'arrowclosed' as any,
            color: '#475569',
            width: 14,
            height: 14,
          },
    };
  });

  return { nodes: flowNodes, edges: flowEdges };
}
