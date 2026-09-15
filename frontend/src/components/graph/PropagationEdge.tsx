import { memo } from 'react';
import { BaseEdge, EdgeProps, getSmoothStepPath, Edge } from '@xyflow/react';

export interface PropagationEdgeData extends Record<string, unknown> {
  isPropagationPath?: boolean;
  isAnimating?: boolean;
  hopIndex?: number;
  totalHops?: number;
  propagationDirection?: 'forward' | 'reverse';
  pathIndex?: number;
}

export type CustomEdgeType = Edge<PropagationEdgeData, 'propagationEdge'>;

export const PropagationEdge = memo(({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  markerStart,
  data,
}: EdgeProps<CustomEdgeType>) => {
  const [edgePath] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: 8,
  });

  const isProp = Boolean(data?.isPropagationPath);
  const isAnimating = Boolean(data?.isAnimating);
  const hopIndex = Number(data?.hopIndex ?? 0);
  const totalHops = Math.max(1, Number(data?.totalHops ?? 1));

  // Sequence finite animation for each hop:
  // Single-hop: ~2.5s total travel time from compromised node to root
  // Two-hop / multi-hop: ~1.75s per hop (approx 3.5s total for 2 hops)
  const hopDur = totalHops > 1 ? 1.75 : 2.5;
  const beginTime = totalHops > 1 ? `${(hopIndex * hopDur).toFixed(2)}s` : '0s';
  const durTime = `${hopDur.toFixed(2)}s`;

  const edgeStyle = isProp
    ? {
        ...style,
        stroke: '#f43f5e',
        strokeWidth: 2.5,
      }
    : {
        ...style,
        stroke: '#334155',
        strokeWidth: 1.5,
      };

  const edgeClassName = isProp
    ? isAnimating
      ? 'edge-propagating edge-propagating-active'
      : 'edge-propagating edge-propagating-static'
    : '';

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={edgeStyle}
        markerEnd={isProp ? undefined : markerEnd}
        markerStart={isProp ? markerStart : undefined}
        className={edgeClassName}
      />

      {/* Finite moving particle: plays ONCE along propagation path, then unmounts */}
      {isProp && isAnimating && (
        <circle r="4" fill="#f43f5e" opacity="0">
          <animateMotion
            path={edgePath}
            begin={beginTime}
            dur={durTime}
            repeatCount="1"
            fill="freeze"
            keyPoints="1;0"
            keyTimes="0;1"
            calcMode="linear"
          />
          <animate
            attributeName="opacity"
            values="0;1;1;0"
            keyTimes="0;0.08;0.92;1"
            begin={beginTime}
            dur={durTime}
            fill="freeze"
          />
        </circle>
      )}
    </>
  );
});

PropagationEdge.displayName = 'PropagationEdge';
