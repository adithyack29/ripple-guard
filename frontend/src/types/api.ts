/**
 * Exact TypeScript representations of RippleGuard's backend API contracts.
 * Matches backend/app/schemas/ exactly.
 */

export type Ecosystem = 'npm';

export type ResolutionStatus =
  | 'lockfile_resolved'
  | 'lockfile_partial'
  | 'direct_dependencies_only';

export type DependencyRelation = 'root' | 'direct' | 'transitive';

export type DependencyCategory = 'runtime' | 'development' | 'optional';

export type VulnerabilityLookupStatus =
  | 'ok'
  | 'unavailable'
  | 'not_checked'
  | 'not_applicable';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNDETERMINED';

export type RiskBasis =
  | 'known_vulnerability'
  | 'simulated_no_vulnerability'
  | 'undetermined';

export type RecommendedAction =
  | 'investigate_immediately'
  | 'prioritize_remediation'
  | 'plan_remediation'
  | 'monitor'
  | 'investigate_vulnerability_data';

export interface HealthResponse {
  status: string;
  app_name: string;
  version: string;
  environment: string;
}

export interface VulnerabilityReference {
  url: string;
  type: string | null;
}

export interface Vulnerability {
  id: string;
  source: string;
  summary: string | null;
  severity: SeverityLevel;
  severity_vector: string | null;
  aliases: string[];
  references: VulnerabilityReference[];
  published: string | null;
  modified: string | null;
}

export interface RiskBreakdown {
  severity: number | null; // null if undetermined, 0 if clean
  reachability: number;
  blast_radius: number;
  propagation: number;
  structural_importance: number; // informational only, not in weighted score
}

export interface RiskAssessment {
  score: number | null; // null when level is UNDETERMINED
  level: RiskLevel;
  basis: RiskBasis;
  breakdown: RiskBreakdown;
  explanation: string;
  vulnerability_count: number;
  highest_severity: SeverityLevel | null;
}

export interface DependencyNode {
  id: string;
  name: string;
  version: string | null;
  declared_range: string | null;
  ecosystem: string;
  relation: DependencyRelation;
  category: DependencyCategory | null;
  depth: number;
  install_path: string | null;
  vulnerabilities: Vulnerability[];
  vulnerability_lookup_status: VulnerabilityLookupStatus | null;
  risk_assessment: RiskAssessment | null;
}

export interface DependencyEdge {
  source: string;
  target: string;
}

export interface Statistics {
  total_dependencies: number;
  direct_dependencies: number;
  transitive_dependencies: number;
  max_depth: number;
  category_breakdown: Record<string, number>;
}

export interface VulnerabilitySummary {
  status: 'ok' | 'partial' | 'unavailable';
  vulnerable_dependencies: number;
  total_vulnerabilities: number;
  direct_vulnerable_dependencies: number;
  transitive_vulnerable_dependencies: number;
  severity_breakdown: Record<string, number>;
  nodes_checked: number;
  nodes_skipped_no_version: number;
  nodes_failed: number;
}

export interface RiskRankEntry {
  node_id: string;
  name: string;
  version: string | null;
  score: number | null;
  level: RiskLevel;
}

export interface RiskSummary {
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  undetermined_count: number;
  highest_risk_score: number | null;
  highest_risk_level: RiskLevel | null;
  ranked_risks: RiskRankEntry[];
}

export interface MitigationPriority {
  priority: number;
  node_id: string;
  name: string;
  version: string | null;
  risk_level: RiskLevel;
  risk_score: number | null;
  vulnerability_count: number;
  affected_dependencies: number;
  affected_applications: number;
  recommended_action: RecommendedAction;
  reason: string;
}

export interface AnalyzeResponse {
  analysis_id: string;
  project: {
    name: string;
    version: string | null;
  };
  ecosystem: string;
  resolution_status: ResolutionStatus;
  statistics: Statistics;
  vulnerability_summary: VulnerabilitySummary;
  risk_summary: RiskSummary;
  mitigation_priorities: MitigationPriority[];
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  unresolved_dependencies: string[];
  warnings: string[];
}

export interface SimulateRequest {
  analysis_id: string;
  node_id: string;
}

export interface AffectedNode {
  node_id: string;
  name: string;
  version: string | null;
  relation: DependencyRelation;
  impact_type: 'direct' | 'indirect';
  depth: number;
}

export interface BlastRadius {
  affected_nodes: number;
  affected_dependencies: number;
  affected_applications: number;
  max_propagation_depth: number;
  propagation_path_count: number;
  propagation_paths_truncated: boolean;
}

export interface ApplicationImpact {
  affected: boolean;
  root_node_id: string;
  shortest_path_depth: number | null;
}

export interface MitigationRecommendation {
  recommended_action: RecommendedAction;
  reason: string;
}

export interface SimulateResponse {
  analysis_id: string;
  compromised_node: {
    node_id: string;
    name: string;
    version: string | null;
  };
  blast_radius: BlastRadius;
  affected_nodes: AffectedNode[];
  propagation_paths: string[][]; // In IMPACT direction: [compromised_id, ..., root_id]
  application_impact: ApplicationImpact;
  risk_assessment: RiskAssessment;
  mitigation: MitigationRecommendation;
  warnings: string[];
}

export interface ApiErrorDetail {
  error_type?: string;
  message?: string;
}

export interface FastApiValidationError {
  loc: (string | number)[];
  msg: string;
  type: string;
}
