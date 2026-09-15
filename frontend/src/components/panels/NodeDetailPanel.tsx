import React from 'react';
import {
  DependencyNode,
  SimulateResponse,
  RiskLevel,
  SeverityLevel,
} from '../../types/api';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  ExternalLink,
  Info,
  Calendar,
  Layers,
  ArrowRight,
  RotateCcw,
  AlertOctagon,
  TrendingUp,
  Ban,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react';

interface NodeDetailPanelProps {
  node: DependencyNode | null;
  simulation: SimulateResponse | null;
  simulationPhase: 'idle' | 'simulating' | 'complete';
  isSimulating: boolean;
  onSimulate: (nodeId: string) => void;
  onClearSimulation: () => void;
  onSelectNode: (nodeId: string) => void;
}

export const NodeDetailPanel: React.FC<NodeDetailPanelProps> = ({
  node,
  simulation,
  simulationPhase,
  isSimulating,
  onSimulate,
  onClearSimulation,
  onSelectNode,
}) => {
  if (!node) {
    return (
      <div className="detail-panel-empty">
        <Info size={24} className="text-muted" />
        <p>Select any node in the dependency graph to inspect security details and simulate compromise impact.</p>
      </div>
    );
  }

  const isRoot = node.relation === 'root';
  const hasVersion = Boolean(node.version);

  const isCurrentSimulatedTarget = simulation?.compromised_node.node_id === node.id;
  const isDownstreamAffected =
    simulation &&
    !isCurrentSimulatedTarget &&
    simulation.affected_nodes.some((n) => n.node_id === node.id);
  const risk = isCurrentSimulatedTarget && simulation ? simulation.risk_assessment : node.risk_assessment;
  const mitigation = isCurrentSimulatedTarget && simulation ? simulation.mitigation : null;

  const getSeverityBadgeClass = (sev: SeverityLevel | string) => {
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      case 'UNDETERMINED': return 'badge-undetermined';
      default: return 'badge-neutral';
    }
  };

  const getRiskBadgeClass = (lvl: RiskLevel | string) => {
    switch (lvl) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      case 'UNDETERMINED': return 'badge-undetermined';
      default: return 'badge-clean';
    }
  };

  const getActionBadgeClass = (action: string) => {
    switch (action) {
      case 'investigate_immediately': return 'badge-critical';
      case 'prioritize_remediation': return 'badge-high';
      case 'plan_remediation': return 'badge-medium';
      case 'monitor': return 'badge-low';
      default: return 'badge-undetermined';
    }
  };

  const formatAction = (action: string) => {
    return action.replace(/_/g, ' ').toUpperCase();
  };

  return (
    <div className="node-detail-panel">
      {/* Panel Header */}
      <div className="panel-header">
        <div className="panel-title-area">
          <div className="panel-node-name mono" title={node.name}>
            {node.name}
          </div>
          <div className="panel-version-row">
            {node.version ? (
              <span className="panel-ver-badge mono">v{node.version}</span>
            ) : node.declared_range ? (
              <span className="panel-range-badge mono">{node.declared_range}</span>
            ) : null}
            <span className={`badge badge-${node.relation}`}>{node.relation}</span>
            {node.category && <span className="badge badge-neutral">{node.category}</span>}
          </div>
        </div>

        {/* Simulation Trigger / Reset */}
        <div className="panel-actions">
          {simulation ? (
            <button
              className="sim-exit-btn-panel"
              onClick={onClearSimulation}
              title="Reset simulation and return to standard graph"
            >
              <RotateCcw size={13} /> Exit Simulation
            </button>
          ) : isRoot ? (
            <button
              className="btn-action-unavailable"
              disabled
              title="The root project cannot be a compromise target."
            >
              <Ban size={13} />
              <span>Cannot Simulate Root</span>
            </button>
          ) : !hasVersion ? (
            <button
              className="btn-action-unavailable"
              disabled
              title="Simulation requires an exact resolved version."
            >
              <AlertCircle size={13} />
              <span>Version Unresolved</span>
            </button>
          ) : (
            <button
              className="btn-action-simulate"
              disabled={isSimulating}
              onClick={() => onSimulate(node.id)}
              title="Simulate downstream compromise propagation"
            >
              <Zap size={14} className={isSimulating ? 'spin-fast' : ''} />
              <span>{isSimulating ? 'Simulating...' : 'Simulate Compromise'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Downstream affected notice if inspecting another node during active simulation */}
      {isDownstreamAffected && (
        <div className="sim-downstream-notice">
          <AlertCircle size={13} className="text-amber" />
          <span>This dependency is affected downstream by <strong>{simulation?.compromised_node.name}</strong></span>
        </div>
      )}

      {/* Concise explanation when simulation is unavailable */}
      {!simulation && isRoot && (
        <div className="sim-disabled-notice root-notice">
          <Info size={13} />
          <span>The root project cannot be a compromise target.</span>
        </div>
      )}

      {!simulation && !isRoot && !hasVersion && (
        <div className="sim-disabled-notice unversioned-notice">
          <AlertCircle size={13} />
          <span>Simulation is unavailable because no exact version was resolved (package-lock.json missing).</span>
        </div>
      )}

      {/* COMPROMISE SIMULATION RESULTS (When this node is the simulated target) */}
      {isCurrentSimulatedTarget && simulation && (
        <div className="simulation-results-section">
          {simulationPhase === 'simulating' ? (
            /* During animation: Tracing in progress */
            <div className="sim-tracing-banner">
              <div className="sim-tracing-banner-header">
                <span className="sim-pulse-dot" />
                <span className="sim-tracing-banner-title">Tracing compromise propagation...</span>
              </div>
              <p className="sim-tracing-banner-sub">
                Tracing dynamic propagation chain to application root...
              </p>
            </div>
          ) : (
            /* After animation: Clear Completion Summary */
            <div className="sim-completion-summary-card">
              <div className="sim-completion-badge-row">
                <CheckCircle2 size={16} className="text-emerald" />
                <span className="sim-completion-badge-text">SIMULATION COMPLETE</span>
              </div>
              <div className="sim-completion-message">
                Compromise traced successfully.
              </div>
              <div className="sim-completion-stats-row">
                <div className="sim-completion-stat-pill">
                  <span className="stat-num mono">{simulation.blast_radius.affected_nodes}</span>
                  <span className="stat-lbl">affected node{simulation.blast_radius.affected_nodes === 1 ? '' : 's'}</span>
                </div>
                <div className="sim-completion-stat-pill">
                  <span className="stat-num mono">{simulation.blast_radius.max_propagation_depth}</span>
                  <span className="stat-lbl">propagation hop{simulation.blast_radius.max_propagation_depth === 1 ? '' : 's'}</span>
                </div>
                <div className={`sim-completion-impact-pill ${simulation.application_impact.affected ? 'breach' : 'safe'}`}>
                  {simulation.application_impact.affected ? 'APPLICATION ROOT BREACHED' : 'APPLICATION ROOT SAFE'}
                </div>
              </div>
            </div>
          )}

          {/* Section Heading */}
          <div className="section-title">
            {simulationPhase === 'simulating' ? (
              <>
                <AlertOctagon size={14} className="text-rose" /> Tracing compromise propagation...
              </>
            ) : (
              <>
                <CheckCircle2 size={14} className="text-emerald" /> Simulation Complete
              </>
            )}
          </div>

          {/* Prominent blast radius metrics */}
          <div className="blast-metrics-grid">
            <div className="metric-box">
              <div className="metric-box-label">Affected Nodes</div>
              <div className="metric-box-val mono">
                {simulation.blast_radius.affected_nodes}
              </div>
            </div>
            <div className="metric-box">
              <div className="metric-box-label">Affected Dependencies</div>
              <div className="metric-box-val mono">
                {simulation.blast_radius.affected_dependencies}
              </div>
            </div>
            <div className="metric-box">
              <div className="metric-box-label">Max Depth</div>
              <div className="metric-box-val mono">
                {simulation.blast_radius.max_propagation_depth} {simulation.blast_radius.max_propagation_depth === 1 ? 'hop' : 'hops'}
              </div>
            </div>
            <div className="metric-box">
              <div className="metric-box-label">App Root Reachable</div>
              <div
                className={`metric-box-val mono ${
                  simulation.application_impact.affected ? 'text-rose' : 'text-emerald'
                }`}
              >
                {simulation.application_impact.affected ? 'YES' : 'NO'}
              </div>
            </div>
          </div>

          {/* Mitigation Recommendation */}
          {mitigation && (
            <div className="mitigation-callout">
              <div className="mitigation-callout-header">
                <span className="mitigation-label">RECOMMENDED MITIGATION:</span>
                <span className={`badge ${getActionBadgeClass(mitigation.recommended_action)}`}>
                  {formatAction(mitigation.recommended_action)}
                </span>
              </div>
              <p className="mitigation-reason">{mitigation.reason}</p>
            </div>
          )}

          {/* Propagation Paths list */}
          {simulation.propagation_paths.length > 0 && (
            <div className="propagation-paths-card">
              <div className="paths-title">
                <TrendingUp size={13} />
                <span>
                  Downstream Impact Chains ({simulation.blast_radius.propagation_path_count})
                </span>
              </div>
              <div className="paths-list">
                {simulation.propagation_paths.map((path, pIdx) => (
                  <div key={pIdx} className="path-item">
                    {path.map((stepId, sIdx) => {
                      const isTarget = sIdx === 0;
                      const isRootStep = sIdx === path.length - 1;
                      return (
                        <React.Fragment key={sIdx}>
                          <span
                            className={`path-node mono ${
                              isTarget ? 'path-target' : isRootStep ? 'path-root' : 'path-intermediate'
                            }`}
                            onClick={() => onSelectNode(stepId)}
                            role="button"
                            tabIndex={0}
                            title={`Inspect ${stepId}`}
                          >
                            {stepId}
                          </span>
                          {sIdx < path.length - 1 && (
                            <ArrowRight size={11} className="path-arrow" />
                          )}
                        </React.Fragment>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* DUAL RISK COMPARISON (Crucial differentiator!) */}
      <div className="panel-section risk-dual-section">
        <div className="section-title">
          <Layers size={14} /> Risk Analysis
        </div>

        <div className="dual-risk-grid">
          {/* Box 1: Vulnerability Severity */}
          <div className="risk-metric-card">
            <div className="risk-card-label">Highest Vuln Severity</div>
            <div className="risk-card-value">
              {risk?.highest_severity ? (
                <span className={`badge ${getSeverityBadgeClass(risk.highest_severity)}`}>
                  {risk.highest_severity}
                </span>
              ) : node.vulnerabilities.length > 0 ? (
                <span className={`badge ${getSeverityBadgeClass(node.vulnerabilities[0].severity)}`}>
                  {node.vulnerabilities[0].severity}
                </span>
              ) : (
                <span className="badge badge-clean">NONE</span>
              )}
            </div>
            <div className="risk-card-hint">From public OSV advisories</div>
          </div>

          {/* Box 2: Contextual Ripple Risk */}
          <div className="risk-metric-card highlight">
            <div className="risk-card-label">Contextual Ripple Risk</div>
            <div className="risk-card-value">
              {risk ? (
                <>
                  <span className={`badge ${getRiskBadgeClass(risk.level)}`}>
                    {risk.level}
                  </span>
                  {risk.score !== null && (
                    <span className="risk-score-num mono">{risk.score}/100</span>
                  )}
                </>
              ) : (
                <span className="badge badge-clean">UNSCORED · CLEAN</span>
              )}
            </div>
            <div className="risk-card-hint">
              {risk ? `Basis: ${risk.basis}` : 'No known issues or clean'}
            </div>
          </div>
        </div>

        {/* Contextual Factor Breakdown */}
        {risk?.breakdown && (
          <div className="breakdown-card">
            <div className="breakdown-title">Contextual Factor Breakdown</div>
            <div className="breakdown-bars">
              <div className="factor-row">
                <div className="factor-meta">
                  <span>OSV Severity (40%):</span>
                  <span className="mono">
                    {risk.breakdown.severity !== null ? `${risk.breakdown.severity}/100` : 'N/A'}
                  </span>
                </div>
                <div className="factor-bar-bg">
                  <div
                    className="factor-bar-fill fill-sev"
                    style={{ width: `${risk.breakdown.severity || 0}%` }}
                  />
                </div>
              </div>

              <div className="factor-row">
                <div className="factor-meta">
                  <span>Reachability to App (25%):</span>
                  <span className="mono">{risk.breakdown.reachability}/100</span>
                </div>
                <div className="factor-bar-bg">
                  <div
                    className="factor-bar-fill fill-reach"
                    style={{ width: `${risk.breakdown.reachability}%` }}
                  />
                </div>
              </div>

              <div className="factor-row">
                <div className="factor-meta">
                  <span>Blast Radius (20%):</span>
                  <span className="mono">{risk.breakdown.blast_radius}/100</span>
                </div>
                <div className="factor-bar-bg">
                  <div
                    className="factor-bar-fill fill-blast"
                    style={{ width: `${risk.breakdown.blast_radius}%` }}
                  />
                </div>
              </div>

              <div className="factor-row">
                <div className="factor-meta">
                  <span>Propagation Paths (15%):</span>
                  <span className="mono">{risk.breakdown.propagation}/100</span>
                </div>
                <div className="factor-bar-bg">
                  <div
                    className="factor-bar-fill fill-prop"
                    style={{ width: `${risk.breakdown.propagation}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Explainable Reasoning */}
        {risk?.explanation && (
          <div className="risk-explanation-box">
            <div className="explanation-title">Contextual Assessment Rationale:</div>
            <p className="explanation-text">{risk.explanation}</p>
          </div>
        )}
      </div>

      {/* OSV VULNERABILITIES LIST */}
      <div className="panel-section">
        <div className="section-title">
          <ShieldAlert size={14} className={node.vulnerabilities.length > 0 ? 'text-amber' : ''} />
          <span>Known OSV Advisories ({node.vulnerabilities.length})</span>
        </div>

        {node.vulnerabilities.length === 0 ? (
          <div className="vulns-empty-card">
            <ShieldCheck size={16} className="text-emerald" />
            <span>
              {node.vulnerability_lookup_status === 'ok'
                ? 'No known OSV vulnerabilities found for this version.'
                : node.vulnerability_lookup_status === 'not_checked'
                ? 'Vulnerabilities not checked (requires resolved lockfile version).'
                : 'No advisories registered.'}
            </span>
          </div>
        ) : (
          <div className="vuln-list">
            {node.vulnerabilities.map((vuln) => (
              <div key={vuln.id} className="vuln-card">
                <div className="vuln-card-header">
                  <span className="vuln-id mono">{vuln.id}</span>
                  <span className={`badge ${getSeverityBadgeClass(vuln.severity)}`}>
                    {vuln.severity}
                  </span>
                </div>

                {vuln.summary && <div className="vuln-summary">{vuln.summary}</div>}

                {vuln.severity_vector && (
                  <div className="vuln-cvss mono" title="CVSS Vector">
                    Vector: {vuln.severity_vector}
                  </div>
                )}

                {vuln.aliases.length > 0 && (
                  <div className="vuln-aliases">
                    <span className="alias-label">Aliases:</span>
                    {vuln.aliases.map((alias) => (
                      <span key={alias} className="alias-tag mono">
                        {alias}
                      </span>
                    ))}
                  </div>
                )}

                <div className="vuln-meta-row">
                  {vuln.published && (
                    <span className="vuln-date">
                      <Calendar size={11} /> Published: {vuln.published.slice(0, 10)}
                    </span>
                  )}
                </div>

                {vuln.references.length > 0 && (
                  <div className="vuln-refs">
                    <div className="refs-label">References:</div>
                    <div className="refs-links">
                      {vuln.references.slice(0, 3).map((ref, rIdx) => (
                        <a
                          key={rIdx}
                          href={ref.url}
                          target="_blank"
                          rel="noreferrer"
                          className="ref-link"
                          title={ref.url}
                        >
                          <span>{ref.type || 'Advisory'}</span>
                          <ExternalLink size={10} />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Package Metadata Info */}
      <div className="panel-section metadata-section">
        <div className="section-title">Package Details</div>
        <div className="metadata-table">
          <div className="metadata-row">
            <span className="meta-k">Depth from Root:</span>
            <span className="meta-v mono">{node.depth} hops</span>
          </div>
          {node.install_path && (
            <div className="metadata-row">
              <span className="meta-k">Install Path:</span>
              <span className="meta-v mono path-truncate" title={node.install_path}>
                {node.install_path}
              </span>
            </div>
          )}
          <div className="metadata-row">
            <span className="meta-k">OSV Lookup:</span>
            <span className="meta-v mono">
              {node.vulnerability_lookup_status || 'not_checked'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
