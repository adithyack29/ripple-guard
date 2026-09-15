import React, { useMemo, useEffect, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  BackgroundVariant,
  NodeTypes,
  EdgeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { DependencyNode as DependencyNodeType, DependencyEdge as DependencyEdgeType, SimulateResponse } from '../../types/api';
import { DependencyNode, CustomNodeType } from './DependencyNode';
import { PropagationEdge, CustomEdgeType } from './PropagationEdge';
import { buildGraphElements } from '../../utils/graphLayout';

interface DependencyGraphProps {
  nodes: DependencyNodeType[];
  edges: DependencyEdgeType[];
  selectedNodeId: string | null;
  simulation: SimulateResponse | null;
  isAnimatingSimulation: boolean;
  onSelectNode: (nodeId: string) => void;
}

const nodeTypes: NodeTypes = {
  dependencyNode: DependencyNode as any,
};

const edgeTypes: EdgeTypes = {
  propagationEdge: PropagationEdge as any,
};

export const DependencyGraphContent: React.FC<DependencyGraphProps> = ({
  nodes,
  edges,
  selectedNodeId,
  simulation,
  isAnimatingSimulation,
  onSelectNode,
}) => {
  const { fitView, setCenter } = useReactFlow();

  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    return buildGraphElements(
      nodes,
      edges,
      selectedNodeId,
      simulation,
      onSelectNode,
      isAnimatingSimulation
    );
  }, [nodes, edges, selectedNodeId, simulation, onSelectNode, isAnimatingSimulation]);

  const [flowNodes, setFlowNodes, onNodesChange] = useNodesState<CustomNodeType>(initialNodes);
  const [flowEdges, setFlowEdges, onEdgesChange] = useEdgesState<CustomEdgeType>(initialEdges);

  // Sync state whenever elements update
  useEffect(() => {
    setFlowNodes(initialNodes);
    setFlowEdges(initialEdges);
  }, [initialNodes, initialEdges, setFlowNodes, setFlowEdges]);

  // Auto-fit on initial render or when node count changes
  useEffect(() => {
    const timer = setTimeout(() => {
      fitView({ padding: 0.15, duration: 400 });
    }, 100);
    return () => clearTimeout(timer);
  }, [nodes.length, fitView]);

  // Center on selected node or compromised node
  useEffect(() => {
    const targetId = simulation ? simulation.compromised_node.node_id : selectedNodeId;
    if (!targetId) return;

    const node = flowNodes.find((n) => n.id === targetId);
    if (node) {
      setCenter(node.position.x + 135, node.position.y + 46, { zoom: 1.1, duration: 500 });
    }
  }, [selectedNodeId, simulation, flowNodes, setCenter]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: any) => {
      onSelectNode(node.id);
    },
    [onSelectNode]
  );

  return (
    <div className="graph-canvas-container">
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        minZoom={0.2}
        maxZoom={2.0}
        defaultEdgeOptions={{ type: 'propagationEdge' }}
        fitView
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1.5}
          color="#1e293b"
          className="graph-background"
        />
        <Controls showInteractive={false} className="graph-controls-panel" />
        <MiniMap
          nodeColor={(node: any) => {
            if (node.data?.isCompromised) return '#ef4444';
            if (node.data?.isRootAffected) return '#ec4899';
            if (node.data?.isAffected) return '#f97316';
            if (node.data?.node?.relation === 'root') return '#a855f7';
            if (node.data?.node?.vulnerabilities?.length > 0) return '#eab308';
            return '#334155';
          }}
          maskColor="rgba(6, 9, 17, 0.75)"
          className="graph-minimap-panel"
        />
      </ReactFlow>
    </div>
  );
};
