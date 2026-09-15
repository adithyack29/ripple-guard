import React, { useState } from 'react';
import { MitigationPriority, RiskLevel } from '../../types/api';
import {
  ShieldAlert,
  ChevronUp,
  ChevronDown,
  CheckCircle2,
  ArrowUpRight,
  Flame,
  AlertTriangle,
  Clock,
  Eye,
  HelpCircle,
  Star,
} from 'lucide-react';

interface PriorityTableProps {
  priorities: MitigationPriority[];
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}

export const PriorityTable: React.FC<PriorityTableProps> = ({
  priorities,
  selectedNodeId,
  onSelectNode,
}) => {
  const [isOpen, setIsOpen] = useState(true);

  const getRiskBadgeClass = (lvl: RiskLevel) => {
    switch (lvl) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      case 'UNDETERMINED': return 'badge-undetermined';
      default: return 'badge-neutral';
    }
  };

  const renderActionBadge = (action: string) => {
    switch (action) {
      case 'investigate_immediately':
        return (
          <span className="action-pill act-critical">
            <Flame size={11} /> INVESTIGATE IMMEDIATELY
          </span>
        );
      case 'prioritize_remediation':
        return (
          <span className="action-pill act-high">
            <AlertTriangle size={11} /> PRIORITIZE REMEDIATION
          </span>
        );
      case 'plan_remediation':
        return (
          <span className="action-pill act-medium">
            <Clock size={11} /> PLAN REMEDIATION
          </span>
        );
      case 'monitor':
        return (
          <span className="action-pill act-low">
            <Eye size={11} /> MONITOR
          </span>
        );
      default:
        return (
          <span className="action-pill act-undetermined">
            <HelpCircle size={11} /> INVESTIGATE DATA
          </span>
        );
    }
  };

  return (
    <div className={`priority-drawer ${isOpen ? 'is-open' : 'is-collapsed'}`}>
      <div className="drawer-header" onClick={() => setIsOpen(!isOpen)} role="button" tabIndex={0}>
        <div className="drawer-title-area">
          <ShieldAlert size={16} className="drawer-icon" />
          <span className="drawer-title">Mitigation Prioritization</span>
          <span className="drawer-count-badge">
            {priorities.length} Action Item{priorities.length === 1 ? '' : 's'}
          </span>
          <span className="drawer-subtitle">
            Ranked by contextual risk and downstream reachability
          </span>
        </div>

        <button
          className="drawer-toggle-btn"
          aria-label={isOpen ? 'Collapse panel' : 'Expand panel'}
        >
          {isOpen ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
        </button>
      </div>

      {isOpen && (
        <div className="drawer-content">
          {priorities.length === 0 ? (
            <div className="priority-empty-state">
              <CheckCircle2 size={20} className="text-emerald" />
              <span>
                No active mitigation priorities found. All resolved dependencies are clean or unassessed.
              </span>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="priority-table">
                <thead>
                  <tr>
                    <th style={{ width: '75px' }}>Rank</th>
                    <th>Package</th>
                    <th>Contextual Risk</th>
                    <th>Vulnerabilities</th>
                    <th>Affected Deps</th>
                    <th>App Impact</th>
                    <th>Recommended Action</th>
                    <th>Rationale</th>
                    <th style={{ width: '40px' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {priorities.map((item) => {
                    const isSelected = selectedNodeId === item.node_id;
                    return (
                      <tr
                        key={item.node_id}
                        className={`priority-row priority-row-${item.risk_level.toLowerCase()} ${
                          isSelected ? 'is-selected' : ''
                        }`}
                        onClick={() => onSelectNode(item.node_id)}
                        role="button"
                        tabIndex={0}
                        title="Click to focus node in dependency graph"
                      >
                        <td>
                          {item.priority === 1 ? (
                            <span className="priority-rank-badge rank-top mono">
                              <Star size={10} className="rank-star" /> #1 TOP
                            </span>
                          ) : (
                            <span className="priority-rank-badge mono">#{item.priority}</span>
                          )}
                        </td>
                        <td>
                          <div className="priority-pkg-cell">
                            <span className="priority-pkg-name mono">{item.name}</span>
                            {item.version && (
                              <span className="priority-pkg-ver mono">v{item.version}</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="priority-risk-cell">
                            <span className={`badge ${getRiskBadgeClass(item.risk_level)}`}>
                              {item.risk_level}
                            </span>
                            {item.risk_score !== null && (
                              <span className="priority-score mono">{item.risk_score}/100</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span className="mono">{item.vulnerability_count} OSV</span>
                        </td>
                        <td>
                          <span className="mono">{item.affected_dependencies} downstream</span>
                        </td>
                        <td>
                          {item.affected_applications > 0 ? (
                            <span className="app-impact-pill reached">
                              <AlertTriangle size={10} /> Reaches App
                            </span>
                          ) : (
                            <span className="app-impact-pill safe">Unreached</span>
                          )}
                        </td>
                        <td>{renderActionBadge(item.recommended_action)}</td>
                        <td>
                          <div className="priority-reason" title={item.reason}>
                            {item.reason}
                          </div>
                        </td>
                        <td>
                          <ArrowUpRight size={14} className="priority-row-arrow" />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
