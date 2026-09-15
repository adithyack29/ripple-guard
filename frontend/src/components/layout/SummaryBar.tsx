import React from 'react';
import { AnalyzeResponse, SimulateResponse } from '../../types/api';
import {
  Layers,
  ShieldAlert,
  Flame,
  FileCheck2,
  FileQuestion,
  XCircle,
  ArrowRight,
  CheckCircle2,
} from 'lucide-react';

interface SummaryBarProps {
  analysis: AnalyzeResponse;
  simulation: SimulateResponse | null;
  simulationPhase: 'idle' | 'simulating' | 'complete';
  onClearSimulation: () => void;
}

export const SummaryBar: React.FC<SummaryBarProps> = ({
  analysis,
  simulation,
  simulationPhase,
  onClearSimulation,
}) => {
  const { statistics, vulnerability_summary, risk_summary, resolution_status } = analysis;

  const isSimActive = Boolean(simulation) && simulationPhase !== 'idle';

  return (
    <div className={`summary-bar ${isSimActive ? 'is-simulating' : ''}`}>
      {isSimActive && simulation ? (
        simulationPhase === 'simulating' ? (
          <div className="simulation-banner sim-banner-simulating">
            <div className="sim-banner-left">
              <span className="sim-pulse-dot" />
              <span className="sim-status-label text-rose">SIMULATING COMPROMISE</span>
              <span className="sim-target mono">
                {simulation.compromised_node.name}
                {simulation.compromised_node.version ? `@${simulation.compromised_node.version}` : ''}
              </span>
              <ArrowRight size={14} className="sim-arrow" />
              <span className="sim-tracing-hint">
                Tracing propagation...
              </span>
            </div>

            <button
              className="sim-exit-btn"
              onClick={onClearSimulation}
              title="Exit simulation and return to standard dependency view"
            >
              <XCircle size={14} /> Exit Simulation
            </button>
          </div>
        ) : (
          <div className="simulation-banner sim-banner-complete">
            <div className="sim-banner-left">
              <CheckCircle2 size={16} className="text-emerald sim-complete-check" />
              <span className="sim-status-label text-emerald">SIMULATION COMPLETE</span>
              <span className="sim-divider">·</span>
              <span className="sim-stat">
                <strong>{simulation.blast_radius.affected_nodes}</strong> affected node
                {simulation.blast_radius.affected_nodes === 1 ? '' : 's'}
              </span>
              <span className="sim-divider">·</span>
              <span className="sim-stat">
                <strong>{simulation.blast_radius.max_propagation_depth}</strong> hop
                {simulation.blast_radius.max_propagation_depth === 1 ? '' : 's'}
              </span>
              <span className="sim-divider">·</span>
              <span
                className={`sim-app-impact ${
                  simulation.application_impact.affected ? 'impact-breached' : 'impact-safe'
                }`}
              >
                App Root {simulation.application_impact.affected ? 'BREACHED' : 'UNREACHED'}
              </span>
            </div>

            <button
              className="sim-exit-btn"
              onClick={onClearSimulation}
              title="Exit simulation and return to standard dependency view"
            >
              <XCircle size={14} /> Exit Simulation
            </button>
          </div>
        )
      ) : (
        <div className="summary-metrics-grid">
          {/* Metric 1: Dependencies */}
          <div className="summary-card">
            <div className="summary-icon">
              <Layers size={16} />
            </div>
            <div className="summary-data">
              <div className="summary-label">Total Dependencies</div>
              <div className="summary-value">
                <span className="val-main">{statistics.total_dependencies}</span>
                <span className="val-sub">
                  ({statistics.direct_dependencies} direct, {statistics.transitive_dependencies} transitive)
                </span>
              </div>
            </div>
          </div>

          {/* Metric 2: Vulnerabilities */}
          <div className="summary-card">
            <div className="summary-icon vuln">
              <ShieldAlert size={16} />
            </div>
            <div className="summary-data">
              <div className="summary-label">OSV Vulnerabilities</div>
              <div className="summary-value">
                <span className="val-main">
                  {vulnerability_summary.total_vulnerabilities}
                </span>
                <span className="val-sub">
                  across {vulnerability_summary.vulnerable_dependencies} package{vulnerability_summary.vulnerable_dependencies === 1 ? '' : 's'}
                </span>
              </div>
              <div className="summary-breakdown">
                {vulnerability_summary.severity_breakdown['CRITICAL'] ? (
                  <span className="badge badge-critical">
                    {vulnerability_summary.severity_breakdown['CRITICAL']} Crit
                  </span>
                ) : null}
                {vulnerability_summary.severity_breakdown['HIGH'] ? (
                  <span className="badge badge-high">
                    {vulnerability_summary.severity_breakdown['HIGH']} High
                  </span>
                ) : null}
                {vulnerability_summary.severity_breakdown['MEDIUM'] ? (
                  <span className="badge badge-medium">
                    {vulnerability_summary.severity_breakdown['MEDIUM']} Med
                  </span>
                ) : null}
                {vulnerability_summary.severity_breakdown['LOW'] ? (
                  <span className="badge badge-low">
                    {vulnerability_summary.severity_breakdown['LOW']} Low
                  </span>
                ) : null}
              </div>
            </div>
          </div>

          {/* Metric 3: Highest Contextual Risk */}
          <div className="summary-card">
            <div className="summary-icon risk">
              <Flame size={16} />
            </div>
            <div className="summary-data">
              <div className="summary-label">Highest Contextual Risk</div>
              <div className="summary-value">
                {risk_summary.highest_risk_level ? (
                  <>
                    <span className={`badge badge-${risk_summary.highest_risk_level.toLowerCase()}`}>
                      {risk_summary.highest_risk_level}
                    </span>
                    {risk_summary.highest_risk_score !== null && (
                      <span className="val-score mono">{risk_summary.highest_risk_score}/100</span>
                    )}
                  </>
                ) : (
                  <span className="badge badge-clean">LOW · CLEAN</span>
                )}
              </div>
            </div>
          </div>

          {/* Metric 4: Resolution Status */}
          <div className="summary-card">
            <div className="summary-icon status">
              {resolution_status === 'lockfile_resolved' ? (
                <FileCheck2 size={16} className="text-emerald" />
              ) : (
                <FileQuestion size={16} className="text-amber" />
              )}
            </div>
            <div className="summary-data">
              <div className="summary-label">Resolution Mode</div>
              <div className="summary-value">
                <span className="resolution-text">
                  {resolution_status === 'lockfile_resolved'
                    ? 'Lockfile Resolved'
                    : resolution_status === 'lockfile_partial'
                    ? 'Partial Lockfile'
                    : 'Direct Only (No Lockfile)'}
                </span>
                <span className="val-sub">
                  Max Depth: {statistics.max_depth}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
