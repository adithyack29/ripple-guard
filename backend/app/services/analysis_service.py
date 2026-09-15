"""Orchestrates dependency ingestion (Phase 1), vulnerability enrichment
(Phase 2), baseline contextual risk scoring (Phase 4), and mitigation
prioritization (Phase 5).

This is the only module the API route (`app.api.routes.analyze`) calls
directly: it wires together manifest parsing, optional lockfile
resolution (or the no-lockfile fallback), statistics computation, OSV
vulnerability enrichment, baseline risk scoring, and mitigation ranking
into a single AnalysisResult.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app.core.config import get_settings
from app.graph.dependency_graph import DependencyGraph
from app.graph.fallback_resolver import resolve_direct_only_graph
from app.graph.lockfile_parser import parse_lockfile
from app.graph.lockfile_resolver import resolve_dependency_graph
from app.mitigation.prioritization import build_mitigation_priorities, sort_mitigation_candidates
from app.models.dependency import DependencyRelation, Ecosystem, ResolutionStatus
from app.models.mitigation import MitigationCandidate, MitigationPriority
from app.models.risk import RiskLevel
from app.models.vulnerability import VulnerabilityEnrichmentStatus, VulnerabilityLookupStatus
from app.risk.risk_service import compute_risk_assessment
from app.services.manifest_parser import parse_package_json
from app.simulation.propagation import (
    build_application_impact,
    build_blast_radius,
    compute_affected_depths,
    find_propagation_paths,
)
from app.vulnerability.vulnerability_service import PackageQuery, fetch_vulnerabilities


@dataclass
class AnalysisStatistics:
    total_dependencies: int
    direct_dependencies: int
    transitive_dependencies: int
    max_depth: int
    category_breakdown: Dict[str, int] = field(default_factory=dict)


@dataclass
class VulnerabilitySummary:
    """Aggregate, descriptive-only vulnerability statistics for a response.

    Deliberately does NOT compute or imply a risk level — see
    docs/ARCHITECTURE.md, "why OSV is an enrichment layer, not the risk
    engine". `total_dependencies` is not repeated here; read it from the
    sibling `AnalysisStatistics`.
    """

    status: VulnerabilityEnrichmentStatus
    vulnerable_dependencies: int
    total_vulnerabilities: int
    direct_vulnerable_dependencies: int
    transitive_vulnerable_dependencies: int
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    nodes_checked: int = 0
    nodes_skipped_no_version: int = 0
    nodes_failed: int = 0
    warnings: List[str] = field(default_factory=list)


@dataclass
class RiskRankEntry:
    node_id: str
    name: str
    version: Optional[str]
    score: Optional[int]
    level: RiskLevel


@dataclass
class RiskSummary:
    """Analysis-level rollup of the per-node baseline risk assessments.

    The primary unit of contextual risk is the dependency NODE
    (`DependencyNode.risk_assessment`) — this is only a convenience
    rollup for a dashboard, not a separate scoring model.
    """

    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    undetermined_count: int
    highest_risk_score: Optional[int]
    highest_risk_level: Optional[RiskLevel]
    ranked_risks: List[RiskRankEntry] = field(default_factory=list)


@dataclass
class AnalysisResult:
    project_name: str
    project_version: Optional[str]
    ecosystem: Ecosystem
    resolution_status: ResolutionStatus
    graph: DependencyGraph
    statistics: AnalysisStatistics
    vulnerability_summary: VulnerabilitySummary
    risk_summary: RiskSummary
    mitigation_priorities: List[MitigationPriority]
    unresolved_dependencies: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


async def analyze_project(manifest_bytes: bytes, lockfile_bytes: Optional[bytes]) -> AnalysisResult:
    """Run dependency ingestion, OSV vulnerability enrichment, then
    baseline contextual risk scoring for vulnerable/uncertain nodes.

    Raises ManifestParseError / LockfileParseError /
    UnsupportedLockfileVersionError (all in `app.core.exceptions`) on
    unusable input; the API route lets these propagate to a global
    exception handler that converts them into structured HTTP errors.
    OSV failures never raise from here — they are represented in the
    returned `vulnerability_summary` / per-node `vulnerability_lookup_status`
    instead (see `_enrich_with_vulnerabilities`), and in turn drive an
    `UNDETERMINED` risk level rather than a fabricated score (see
    `_compute_baseline_risk`).
    """
    manifest = parse_package_json(manifest_bytes)
    warnings = list(manifest.warnings)
    unresolved: List[str] = []

    if lockfile_bytes is not None:
        parsed_lockfile = parse_lockfile(lockfile_bytes)
        graph, unresolved = resolve_dependency_graph(
            project_name=manifest.project_name,
            project_version=manifest.project_version,
            declared_dependencies=manifest.declared_dependencies,
            packages=parsed_lockfile.packages,
        )
        if unresolved:
            resolution_status = ResolutionStatus.LOCKFILE_PARTIAL
            warnings.append(
                f"{len(unresolved)} declared dependency(ies) could not be found in "
                "package-lock.json and were excluded from the graph: " + ", ".join(unresolved)
            )
        else:
            resolution_status = ResolutionStatus.LOCKFILE_RESOLVED
    else:
        graph = resolve_direct_only_graph(
            project_name=manifest.project_name,
            project_version=manifest.project_version,
            declared_dependencies=manifest.declared_dependencies,
        )
        resolution_status = ResolutionStatus.DIRECT_DEPENDENCIES_ONLY
        warnings.append(
            "No package-lock.json was provided: only direct dependencies declared in "
            "package.json are represented. Transitive dependencies are unknown and not "
            "fabricated."
        )

    statistics = _compute_statistics(graph)

    vulnerability_summary = await _enrich_with_vulnerabilities(graph)
    warnings.extend(vulnerability_summary.warnings)

    risk_summary, mitigation_priorities = _compute_baseline_risk(graph)

    return AnalysisResult(
        project_name=manifest.project_name,
        project_version=manifest.project_version,
        ecosystem=Ecosystem.NPM,
        resolution_status=resolution_status,
        graph=graph,
        statistics=statistics,
        vulnerability_summary=vulnerability_summary,
        risk_summary=risk_summary,
        mitigation_priorities=mitigation_priorities,
        unresolved_dependencies=unresolved,
        warnings=warnings,
    )


def _compute_statistics(graph: DependencyGraph) -> AnalysisStatistics:
    direct = 0
    transitive = 0
    max_depth = 0
    category_breakdown: Dict[str, int] = {}

    for node in graph.nodes:
        if node.relation == DependencyRelation.DIRECT:
            direct += 1
        elif node.relation == DependencyRelation.TRANSITIVE:
            transitive += 1

        if node.relation != DependencyRelation.ROOT:
            max_depth = max(max_depth, node.depth)
            if node.category is not None:
                key = node.category.value
                category_breakdown[key] = category_breakdown.get(key, 0) + 1

    return AnalysisStatistics(
        total_dependencies=direct + transitive,
        direct_dependencies=direct,
        transitive_dependencies=transitive,
        max_depth=max_depth,
        category_breakdown=category_breakdown,
    )


async def _enrich_with_vulnerabilities(graph: DependencyGraph) -> VulnerabilitySummary:
    """Query OSV for every graph node that has a resolved exact version,
    write the results (and a per-node lookup status) back onto each
    `DependencyNode` in place, and compute the aggregate summary.

    The root node is never queried (`NOT_APPLICABLE` — it is the analyzed
    application, not a dependency package). A node with no resolved
    version (no-lockfile fallback mode) is never queried either
    (`NOT_CHECKED`) — RippleGuard only looks up exact installed versions,
    never a semver range (see docs/ARCHITECTURE.md).
    """
    queryable_nodes = [
        node
        for node in graph.nodes
        if node.relation != DependencyRelation.ROOT and node.version is not None
    ]
    skipped_nodes = [
        node
        for node in graph.nodes
        if node.relation != DependencyRelation.ROOT and node.version is None
    ]

    for node in graph.nodes:
        if node.relation == DependencyRelation.ROOT:
            node.vulnerability_lookup_status = VulnerabilityLookupStatus.NOT_APPLICABLE
    for node in skipped_nodes:
        node.vulnerability_lookup_status = VulnerabilityLookupStatus.NOT_CHECKED

    queries = [
        PackageQuery(name=node.name, version=node.version, ecosystem=node.ecosystem.value)
        for node in queryable_nodes
        if node.version is not None
    ]
    results = await fetch_vulnerabilities(queries)

    nodes_checked = 0
    nodes_failed = 0
    failed_node_ids: List[str] = []

    for node in queryable_nodes:
        outcome = results.get((node.name, node.version))
        if outcome is None or not outcome.success:
            node.vulnerabilities = []
            node.vulnerability_lookup_status = VulnerabilityLookupStatus.UNAVAILABLE
            nodes_failed += 1
            failed_node_ids.append(node.id)
        else:
            node.vulnerabilities = outcome.vulnerabilities
            node.vulnerability_lookup_status = VulnerabilityLookupStatus.OK
            nodes_checked += 1

    direct_vulnerable = 0
    transitive_vulnerable = 0
    total_vulnerabilities = 0
    severity_breakdown: Dict[str, int] = {}

    for node in graph.nodes:
        if node.relation == DependencyRelation.ROOT or not node.vulnerabilities:
            continue
        if node.relation == DependencyRelation.DIRECT:
            direct_vulnerable += 1
        elif node.relation == DependencyRelation.TRANSITIVE:
            transitive_vulnerable += 1
        for vulnerability in node.vulnerabilities:
            total_vulnerabilities += 1
            key = vulnerability.severity.value
            severity_breakdown[key] = severity_breakdown.get(key, 0) + 1

    if nodes_failed == 0:
        status = VulnerabilityEnrichmentStatus.OK
    elif nodes_checked > 0:
        status = VulnerabilityEnrichmentStatus.PARTIAL
    else:
        status = VulnerabilityEnrichmentStatus.UNAVAILABLE

    warnings: List[str] = []
    if failed_node_ids:
        warnings.append(
            f"OSV vulnerability lookup failed for {len(failed_node_ids)} package(s): "
            + ", ".join(failed_node_ids)
        )
    if skipped_nodes:
        warnings.append(
            f"{len(skipped_nodes)} dependency(ies) had no resolved version (no lockfile "
            "supplied) and were not checked against OSV."
        )

    return VulnerabilitySummary(
        status=status,
        vulnerable_dependencies=direct_vulnerable + transitive_vulnerable,
        total_vulnerabilities=total_vulnerabilities,
        direct_vulnerable_dependencies=direct_vulnerable,
        transitive_vulnerable_dependencies=transitive_vulnerable,
        severity_breakdown=severity_breakdown,
        nodes_checked=nodes_checked,
        nodes_skipped_no_version=len(skipped_nodes),
        nodes_failed=nodes_failed,
        warnings=warnings,
    )


def _compute_baseline_risk(graph: DependencyGraph) -> Tuple[RiskSummary, List[MitigationPriority]]:
    """Compute a baseline contextual risk assessment for every node with
    a known vulnerability OR an inconclusive vulnerability lookup
    (`UNAVAILABLE`/`NOT_CHECKED`), writing `node.risk_assessment` on each
    in place. A node that was genuinely checked and found clean (`OK`
    with zero vulnerabilities) gets no risk assessment at all — see
    docs/ARCHITECTURE.md, "Phase 4", "no vulnerability case". Because
    `needs_assessment` below only ever admits a known vulnerability or an
    inconclusive lookup, the resulting `RiskAssessment.basis` is always
    `KNOWN_VULNERABILITY` or `UNDETERMINED` here — never
    `SIMULATED_NO_VULNERABILITY` — so clean dependencies never appear in
    the mitigation-priority list either (see docs/ARCHITECTURE.md, "Phase 5").

    This reuses `app.simulation.propagation`'s pure, network-free
    traversal — the same algorithm `/api/simulate` uses — to compute
    each assessed node's impact, so "baseline risk" and "post-simulation
    risk" are always derived identically, never two different formulas.
    Runs one bounded graph traversal per assessed node: acceptable at
    hackathon scale (see docs/ARCHITECTURE.md for the scaling note).

    Both the returned `RiskSummary.ranked_risks` and the returned
    `mitigation_priorities` are projections of the SAME deterministically
    sorted candidate list (`app.mitigation.prioritization.
    sort_mitigation_candidates`) — one sort, two views, never two
    different orderings for what is conceptually the same ranking.
    """
    settings = get_settings()
    root = graph.root
    empty_summary = RiskSummary(
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        undetermined_count=0,
        highest_risk_score=None,
        highest_risk_level=None,
        ranked_risks=[],
    )
    if root is None:
        return empty_summary, []

    counts = {level: 0 for level in RiskLevel}
    candidates: List[MitigationCandidate] = []

    for node in graph.nodes:
        if node.relation == DependencyRelation.ROOT:
            continue
        needs_assessment = bool(node.vulnerabilities) or node.vulnerability_lookup_status in (
            VulnerabilityLookupStatus.UNAVAILABLE,
            VulnerabilityLookupStatus.NOT_CHECKED,
        )
        if not needs_assessment:
            continue

        depths = compute_affected_depths(graph, node.id)
        paths, truncated = find_propagation_paths(
            graph,
            node.id,
            root.id,
            max_paths=settings.simulation_max_propagation_paths,
            max_path_length=settings.simulation_max_path_length,
        )
        blast_radius = build_blast_radius(depths, root.id, paths, truncated)
        application_impact = build_application_impact(depths, root.id)

        assessment = compute_risk_assessment(
            vulnerabilities=node.vulnerabilities,
            lookup_status=node.vulnerability_lookup_status,
            application_affected=application_impact.affected,
            affected_dependencies=blast_radius.affected_dependencies,
            affected_nodes=blast_radius.affected_nodes,
            propagation_path_count=blast_radius.propagation_path_count,
            max_propagation_depth=blast_radius.max_propagation_depth,
            direct_dependents=len(graph.dependents_of(node.id)),
        )
        node.risk_assessment = assessment
        counts[assessment.level] += 1
        candidates.append(
            MitigationCandidate(
                node_id=node.id,
                name=node.name,
                version=node.version,
                assessment=assessment,
                affected_dependencies=blast_radius.affected_dependencies,
                affected_applications=blast_radius.affected_applications,
            )
        )

    sorted_candidates = sort_mitigation_candidates(candidates)
    capped = sorted_candidates[: settings.risk_ranked_list_max_size]

    ranked_risks = [
        RiskRankEntry(
            node_id=c.node_id,
            name=c.name,
            version=c.version,
            score=c.assessment.score,
            level=c.assessment.level,
        )
        for c in capped
    ]
    mitigation_priorities = build_mitigation_priorities(
        sorted_candidates, settings.risk_ranked_list_max_size
    )

    scored_scores = [c.assessment.score for c in candidates if c.assessment.score is not None]
    highest_score = max(scored_scores, default=None)
    highest_level = None
    if highest_score is not None:
        highest_level = next(c.assessment.level for c in candidates if c.assessment.score == highest_score)

    risk_summary = RiskSummary(
        critical_count=counts[RiskLevel.CRITICAL],
        high_count=counts[RiskLevel.HIGH],
        medium_count=counts[RiskLevel.MEDIUM],
        low_count=counts[RiskLevel.LOW],
        undetermined_count=counts[RiskLevel.UNDETERMINED],
        highest_risk_score=highest_score,
        highest_risk_level=highest_level,
        ranked_risks=ranked_risks,
    )
    return risk_summary, mitigation_priorities
