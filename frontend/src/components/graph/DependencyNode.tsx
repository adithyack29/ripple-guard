import { memo } from 'react';
import { Handle, Position, NodeProps, Node } from '@xyflow/react';
import { DependencyNode as DependencyNodeType, RiskLevel } from '../../types/api';
import { Shield, ShieldAlert, AlertTriangle, Radio, AppWindow } from 'lucide-react';

export interface DependencyNodeData extends Record<string, unknown> {
  node: DependencyNodeType;
  isSelected: boolean;
  // Simulation states
  isCompromised?: boolean;
  isAffected?: boolean;
  impactType?: 'direct' | 'indirect';
  impactDepth?: number;
  isRootAffected?: boolean;
  isDimmed?: boolean;
  onSelectNode: (nodeId: string) => void;
}

export type CustomNodeType = Node<DependencyNodeData, 'dependencyNode'>;

export const DependencyNode = memo(({ data }: NodeProps<CustomNodeType>) => {
  const {
    node,
    isSelected,
    isCompromised,
    isAffected,
    impactType,
    impactDepth,
    isRootAffected,
    isDimmed,
    onSelectNode,
  } = data;

  const isRoot = node.relation === 'root';
  const hasVulnerabilities = node.vulnerabilities.length > 0;
  const risk = node.risk_assessment;

  // Determine border and accent styling
  let borderClass = 'node-border-default';
  let statusBadge = null;

  if (isCompromised) {
    borderClass = 'node-border-compromised beacon-pulse';
    statusBadge = (
      <span className="node-sim-tag compromised">
        <Radio size={10} className="spin-slow" /> SIMULATED COMPROMISE
      </span>
    );
  } else if (isRootAffected) {
    borderClass = 'node-border-app-impact';
    statusBadge = (
      <span className="node-sim-tag app-impact">
        <AlertTriangle size={10} /> ROOT BREACHED (DEPTH {impactDepth})
      </span>
    );
  } else if (isAffected) {
    borderClass = impactType === 'direct' ? 'node-border-affected-direct' : 'node-border-affected-indirect';
    statusBadge = (
      <span className="node-sim-tag affected">
        <AlertTriangle size={10} /> AFFECTED ({impactType}, +{impactDepth})
      </span>
    );
  } else if (hasVulnerabilities) {
    const highestSev = risk?.highest_severity || node.vulnerabilities[0]?.severity || 'MEDIUM';
    if (highestSev === 'CRITICAL') borderClass = 'node-border-critical';
    else if (highestSev === 'HIGH') borderClass = 'node-border-high';
    else if (highestSev === 'MEDIUM') borderClass = 'node-border-medium';
    else borderClass = 'node-border-low';
  } else if (isRoot) {
    borderClass = 'node-border-root';
  }

  const getRiskClass = (level?: RiskLevel) => {
    switch (level) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      case 'UNDETERMINED': return 'badge-undetermined';
      default: return 'badge-neutral';
    }
  };

  return (
    <div
      className={`dep-node-card ${borderClass} ${isSelected ? 'is-selected' : ''} ${isDimmed ? 'is-dimmed' : ''}`}
      onClick={() => onSelectNode(node.id)}
      role="button"
      tabIndex={0}
      title={`${node.name}${node.version ? '@' + node.version : ''} (${node.relation})`}
    >
      {/* React Flow handles for hierarchical connection */}
      <Handle type="target" position={Position.Top} className="flow-handle" />

      {statusBadge && <div className="node-sim-banner">{statusBadge}</div>}

      <div className="node-header">
        <div className="node-icon-title">
          {isRoot ? (
            <AppWindow size={14} className="icon-root" />
          ) : hasVulnerabilities ? (
            <ShieldAlert size={14} className="icon-vuln" />
          ) : (
            <Shield size={14} className="icon-safe" />
          )}
          <span className="node-name mono" title={node.name}>
            {node.name}
          </span>
        </div>

        {node.version && (
          <span className="node-version mono">v{node.version}</span>
        )}
        {!node.version && node.declared_range && (
          <span className="node-version mono range">{node.declared_range}</span>
        )}
      </div>

      <div className="node-body">
        <div className="node-tags">
          <span className={`badge badge-${node.relation}`}>{node.relation}</span>
        </div>

        <div className="node-metrics">
          {hasVulnerabilities ? (
            <span className="badge badge-vuln-count" title={`${node.vulnerabilities.length} known OSV vulnerabilities`}>
              <ShieldAlert size={10} /> {node.vulnerabilities.length} vuln{node.vulnerabilities.length > 1 ? 's' : ''}
            </span>
          ) : node.vulnerability_lookup_status === 'ok' && !isRoot ? (
            <span className="badge badge-clean" title="Checked with OSV: clean">
              clean
            </span>
          ) : null}

          {risk && (
            <span
              className={`badge ${getRiskClass(risk.level)}`}
              title={`Contextual Risk: ${risk.level}${risk.score !== null ? ` (${risk.score}/100)` : ''}`}
            >
              {risk.level} {risk.score !== null ? `· ${risk.score}` : ''}
            </span>
          )}
        </div>
      </div>

      <Handle type="source" position={Position.Bottom} className="flow-handle" />
    </div>
  );
});

DependencyNode.displayName = 'DependencyNode';
