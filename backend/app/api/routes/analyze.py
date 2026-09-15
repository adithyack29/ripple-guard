"""POST /api/analyze — dependency ingestion (Phase 1), OSV vulnerability
enrichment (Phase 2), baseline contextual risk scoring (Phase 4), and
mitigation prioritization (Phase 5).

Accepts an NPM project's package.json (required) and package-lock.json
(optional) as multipart file uploads, and returns a structured
direct/transitive dependency graph whose nodes carry normalized OSV
vulnerability data and (for vulnerable/uncertain nodes) a baseline
contextual risk assessment, a project-wide `mitigation_priorities`
ranking, plus an `analysis_id` (see `app.services.analysis_store`) that
`POST /api/simulate` uses to run a compromise simulation against this
same graph.

Does NOT return compromise-simulation or blast-radius data directly —
call `/api/simulate` for that (Phase 3).
"""

from typing import Optional

from fastapi import APIRouter, File, UploadFile

from app.models.risk import RiskAssessment
from app.schemas.analyze import (
    AnalyzeResponse,
    DependencyEdgeSchema,
    DependencyNodeSchema,
    ProjectInfo,
    StatisticsSchema,
    VulnerabilityReferenceSchema,
    VulnerabilitySchema,
    VulnerabilitySummarySchema,
)
from app.schemas.mitigation import MitigationPrioritySchema
from app.schemas.risk import RiskAssessmentSchema, RiskBreakdownSchema, RiskRankEntrySchema, RiskSummarySchema
from app.services.analysis_service import AnalysisResult, analyze_project
from app.services.analysis_store import get_analysis_store

router = APIRouter(tags=["analyze"])


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    package_json: UploadFile = File(..., description="Project's package.json"),
    package_lock_json: Optional[UploadFile] = File(
        None, description="Optional package-lock.json (lockfileVersion 2 or 3)"
    ),
) -> AnalyzeResponse:
    manifest_bytes = await package_json.read()
    lockfile_bytes = await package_lock_json.read() if package_lock_json is not None else None

    result = await analyze_project(manifest_bytes, lockfile_bytes)
    analysis_id = get_analysis_store().put(result)
    return _to_response(result, analysis_id)


def _to_response(result: AnalysisResult, analysis_id: str) -> AnalyzeResponse:
    nodes = [
        DependencyNodeSchema(
            id=node.id,
            name=node.name,
            version=node.version,
            declared_range=node.declared_range,
            ecosystem=node.ecosystem.value,
            relation=node.relation.value,
            category=node.category.value if node.category is not None else None,
            depth=node.depth,
            install_path=node.install_path,
            vulnerabilities=[
                VulnerabilitySchema(
                    id=vuln.id,
                    source=vuln.source,
                    summary=vuln.summary,
                    severity=vuln.severity.value,
                    severity_vector=vuln.severity_vector,
                    aliases=vuln.aliases,
                    references=[
                        VulnerabilityReferenceSchema(url=ref.url, type=ref.type)
                        for ref in vuln.references
                    ],
                    published=vuln.published,
                    modified=vuln.modified,
                )
                for vuln in node.vulnerabilities
            ],
            vulnerability_lookup_status=(
                node.vulnerability_lookup_status.value
                if node.vulnerability_lookup_status is not None
                else None
            ),
            risk_assessment=_risk_assessment_schema(node.risk_assessment),
        )
        for node in result.graph.nodes
    ]
    edges = [
        DependencyEdgeSchema(source=edge.source, target=edge.target) for edge in result.graph.edges
    ]

    return AnalyzeResponse(
        analysis_id=analysis_id,
        project=ProjectInfo(name=result.project_name, version=result.project_version),
        ecosystem=result.ecosystem.value,
        resolution_status=result.resolution_status.value,
        statistics=StatisticsSchema(
            total_dependencies=result.statistics.total_dependencies,
            direct_dependencies=result.statistics.direct_dependencies,
            transitive_dependencies=result.statistics.transitive_dependencies,
            max_depth=result.statistics.max_depth,
            category_breakdown=result.statistics.category_breakdown,
        ),
        vulnerability_summary=VulnerabilitySummarySchema(
            status=result.vulnerability_summary.status.value,
            vulnerable_dependencies=result.vulnerability_summary.vulnerable_dependencies,
            total_vulnerabilities=result.vulnerability_summary.total_vulnerabilities,
            direct_vulnerable_dependencies=result.vulnerability_summary.direct_vulnerable_dependencies,
            transitive_vulnerable_dependencies=result.vulnerability_summary.transitive_vulnerable_dependencies,
            severity_breakdown=result.vulnerability_summary.severity_breakdown,
            nodes_checked=result.vulnerability_summary.nodes_checked,
            nodes_skipped_no_version=result.vulnerability_summary.nodes_skipped_no_version,
            nodes_failed=result.vulnerability_summary.nodes_failed,
        ),
        risk_summary=RiskSummarySchema(
            critical_count=result.risk_summary.critical_count,
            high_count=result.risk_summary.high_count,
            medium_count=result.risk_summary.medium_count,
            low_count=result.risk_summary.low_count,
            undetermined_count=result.risk_summary.undetermined_count,
            highest_risk_score=result.risk_summary.highest_risk_score,
            highest_risk_level=(
                result.risk_summary.highest_risk_level.value
                if result.risk_summary.highest_risk_level is not None
                else None
            ),
            ranked_risks=[
                RiskRankEntrySchema(
                    node_id=entry.node_id,
                    name=entry.name,
                    version=entry.version,
                    score=entry.score,
                    level=entry.level.value,
                )
                for entry in result.risk_summary.ranked_risks
            ],
        ),
        mitigation_priorities=[
            MitigationPrioritySchema(
                priority=entry.priority,
                node_id=entry.node_id,
                name=entry.name,
                version=entry.version,
                risk_level=entry.risk_level.value,
                risk_score=entry.risk_score,
                vulnerability_count=entry.vulnerability_count,
                affected_dependencies=entry.affected_dependencies,
                affected_applications=entry.affected_applications,
                recommended_action=entry.recommended_action.value,
                reason=entry.reason,
            )
            for entry in result.mitigation_priorities
        ],
        nodes=nodes,
        edges=edges,
        unresolved_dependencies=result.unresolved_dependencies,
        warnings=result.warnings,
    )


def _risk_assessment_schema(assessment: Optional[RiskAssessment]) -> Optional[RiskAssessmentSchema]:
    if assessment is None:
        return None
    return RiskAssessmentSchema(
        score=assessment.score,
        level=assessment.level.value,
        basis=assessment.basis.value,
        breakdown=RiskBreakdownSchema(
            severity=assessment.breakdown.severity,
            reachability=assessment.breakdown.reachability,
            blast_radius=assessment.breakdown.blast_radius,
            propagation=assessment.breakdown.propagation,
            structural_importance=assessment.breakdown.structural_importance,
        ),
        explanation=assessment.explanation,
        vulnerability_count=assessment.vulnerability_count,
        highest_severity=(
            assessment.highest_severity.value if assessment.highest_severity is not None else None
        ),
    )
