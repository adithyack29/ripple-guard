"""Deterministic, explainable component-score functions for Phase 4
contextual risk.

Every function here is pure (no I/O, no graph traversal, no randomness)
and takes plain scalar/list inputs — the caller (`app.risk.risk_service`)
is responsible for extracting those from vulnerability/impact data. This
keeps the scoring math independently testable and auditable: a reader
(or a judge) can see the entire formula in this one file.

**This is a deliberately simple, explainable hackathon heuristic — not a
validated industry-standard risk score, and not machine-learned.** See
docs/ARCHITECTURE.md, "Phase 4", for the full rationale behind every
constant below.
"""

from typing import List

from app.models.risk import RiskLevel
from app.models.vulnerability import Vulnerability, VulnerabilitySeverityLevel

# --- Severity component -----------------------------------------------
#
# Maps Phase 2's normalized severity label to a 0-100 score. UNKNOWN is
# deliberately mapped ABOVE LOW: an unlabeled vulnerability must never be
# scored as if it were confirmed low-severity, but we also have no
# positive evidence to justify a HIGH/CRITICAL-level score. 50 is a
# documented, defensible midpoint — not derived from any external data.
SEVERITY_SCORE_MAP = {
    VulnerabilitySeverityLevel.CRITICAL: 100,
    VulnerabilitySeverityLevel.HIGH: 80,
    VulnerabilitySeverityLevel.MEDIUM: 60,
    VulnerabilitySeverityLevel.LOW: 30,
    VulnerabilitySeverityLevel.UNKNOWN: 50,
}


def severity_score(vulnerabilities: List[Vulnerability]) -> int:
    """The single MOST severe known vulnerability drives this score.

    Averaging would let several LOW-severity findings dilute one
    CRITICAL one — actively misleading for a security tool. Returns 0
    for an empty list (no known vulnerability contributes no severity).
    """
    if not vulnerabilities:
        return 0
    return max(SEVERITY_SCORE_MAP[v.severity] for v in vulnerabilities)


# --- Reachability component --------------------------------------------
#
# Deliberately NOT `affected_nodes / total_nodes` (see docs/ARCHITECTURE.md,
# "why not a raw ratio"): that would let a huge dependency graph
# automatically dilute every package's risk regardless of what it can
# actually reach. Whether the compromise reaches the analyzed
# application is the dominant signal (a fixed base score, not scaled by
# graph size); breadth of affected dependencies is a secondary,
# explicitly capped bonus.
_REACHABILITY_BASE_IF_APP_AFFECTED = 70
_REACHABILITY_BASE_IF_NOT_AFFECTED = 15
_REACHABILITY_DEPENDENCY_BONUS_PER_NODE = 3
_REACHABILITY_DEPENDENCY_BONUS_CAP = 10  # affected_dependencies beyond this add no further bonus


def reachability_score(application_affected: bool, affected_dependencies: int) -> int:
    base = _REACHABILITY_BASE_IF_APP_AFFECTED if application_affected else _REACHABILITY_BASE_IF_NOT_AFFECTED
    bonus = min(affected_dependencies, _REACHABILITY_DEPENDENCY_BONUS_CAP) * _REACHABILITY_DEPENDENCY_BONUS_PER_NODE
    return min(100, base + bonus)


# --- Blast radius component ---------------------------------------------
#
# Emphasizes raw scale of the affected set plus path redundancy (multiple
# independent propagation routes), as a complement to reachability's
# app-reach-first framing. Both capped bucket components, no ratios.
_BLAST_RADIUS_NODE_POINTS_PER_NODE = 5
_BLAST_RADIUS_NODE_CAP = 15  # affected_nodes beyond this add no further points
_BLAST_RADIUS_PATH_POINTS_PER_PATH = 5
_BLAST_RADIUS_PATH_CAP = 5  # propagation_path_count beyond this adds no further points


def blast_radius_score(affected_nodes: int, propagation_path_count: int) -> int:
    node_component = min(affected_nodes, _BLAST_RADIUS_NODE_CAP) * _BLAST_RADIUS_NODE_POINTS_PER_NODE
    path_component = min(propagation_path_count, _BLAST_RADIUS_PATH_CAP) * _BLAST_RADIUS_PATH_POINTS_PER_PATH
    return min(100, node_component + path_component)


# --- Propagation depth component ----------------------------------------
#
# A deeper propagation chain suggests broader structural exposure, but
# depth alone must not automatically mean "critical" (it's one component
# among four). Simple linear scale, capped at depth 5+.
_PROPAGATION_POINTS_PER_DEPTH_LEVEL = 20


def propagation_score(max_propagation_depth: int) -> int:
    return min(100, max_propagation_depth * _PROPAGATION_POINTS_PER_DEPTH_LEVEL)


# --- Structural importance (informational only, not weighted) -----------
#
# A lightweight, purely-graph-structural signal (count of direct
# dependents — see `DependencyGraph.dependents_of`), deliberately NOT a
# centrality algorithm. Surfaced in the breakdown and used in the
# explanation, but excluded from the weighted composite score — see
# docs/ARCHITECTURE.md for why.
_STRUCTURAL_IMPORTANCE_POINTS_PER_DEPENDENT = 25


def structural_importance_score(direct_dependents: int) -> int:
    return min(100, direct_dependents * _STRUCTURAL_IMPORTANCE_POINTS_PER_DEPENDENT)


# --- Composite score & level ---------------------------------------------
#
# Weights are an explainable hackathon heuristic, not a scientifically
# validated model — see docs/ARCHITECTURE.md for the full discussion.
# Because severity is 40% of the total, a node with NO known vulnerability
# (severity contributes 0) is mathematically capped at 60/100 — it can
# never reach HIGH or CRITICAL from structural exposure alone. This is a
# deliberate emergent property, not a special case: RippleGuard must
# never label a clean dependency as critical purely because of graph
# structure.
SEVERITY_WEIGHT = 0.40
REACHABILITY_WEIGHT = 0.25
BLAST_RADIUS_WEIGHT = 0.20
PROPAGATION_WEIGHT = 0.15

# Thresholds are inclusive lower bounds, checked from highest to lowest.
# Documented, round numbers — not derived from any external calibration.
RISK_LEVEL_THRESHOLDS = (
    (85, RiskLevel.CRITICAL),
    (65, RiskLevel.HIGH),
    (40, RiskLevel.MEDIUM),
)  # anything below the lowest threshold (40) is LOW


def composite_score(severity: int, reachability: int, blast_radius: int, propagation: int) -> int:
    raw = (
        SEVERITY_WEIGHT * severity
        + REACHABILITY_WEIGHT * reachability
        + BLAST_RADIUS_WEIGHT * blast_radius
        + PROPAGATION_WEIGHT * propagation
    )
    return round(raw)


def risk_level_for_score(score: int) -> RiskLevel:
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.LOW
