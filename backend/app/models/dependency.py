"""Internal domain model for a resolved NPM dependency graph (Phase 1).

These types describe RippleGuard's understanding of a project's
dependencies after ingestion. They are independent of the public API
shape defined in `app.schemas.analyze` — see that module for the
JSON contract actually returned to callers.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from app.models.risk import RiskAssessment
from app.models.vulnerability import Vulnerability, VulnerabilityLookupStatus


class Ecosystem(str, Enum):
    """Package ecosystem. Only NPM is supported in Phase 1."""

    NPM = "npm"


class DependencyRelation(str, Enum):
    """A node's structural relationship to the project root."""

    ROOT = "root"
    DIRECT = "direct"
    TRANSITIVE = "transitive"


class DependencyCategory(str, Enum):
    """Which package.json list a *direct* dependency was declared in.

    A transitive dependency inherits the category of the nearest direct
    dependency it descends from — see `app.graph.lockfile_resolver`. This
    means a transitive dependency reached only through an optionalDependency
    is still categorized by the ancestor that pulled it in, not re-derived
    per edge; documented as a deliberate MVP simplification.
    """

    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    OPTIONAL = "optional"


class ResolutionStatus(str, Enum):
    """How confidently a dependency graph reflects real installed packages."""

    LOCKFILE_RESOLVED = "lockfile_resolved"
    LOCKFILE_PARTIAL = "lockfile_partial"
    DIRECT_DEPENDENCIES_ONLY = "direct_dependencies_only"


@dataclass
class DependencyNode:
    """One package (or the project root) in the dependency graph.

    Node identity is `name@version` (see `id`), not just name: two
    different versions of the same package name must never collapse into
    one node, since they may carry different vulnerabilities in later
    phases. If the lockfile places the exact same name+version at
    multiple node_modules paths (npm hoisting/dedup), RippleGuard treats
    that as one logical node with multiple incoming edges rather than
    duplicating it — `install_path` then reflects only the first path
    discovered.
    """

    name: str
    version: Optional[str]
    ecosystem: Ecosystem
    relation: DependencyRelation
    depth: int
    category: Optional[DependencyCategory] = None
    install_path: Optional[str] = None
    # Raw semver range from package.json (e.g. "^4.18.2"); set only in the
    # no-lockfile fallback path where `version` is None. This is a range,
    # never a resolved version.
    declared_range: Optional[str] = None

    # Populated by Phase 2 vulnerability enrichment (app.vulnerability +
    # app.services.analysis_service). Always a list, never None — a node
    # with no known vulnerabilities has vulnerabilities == [], and
    # `vulnerability_lookup_status` says *why* (checked-and-clean vs.
    # not actually checked) so the two states are never confused.
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    vulnerability_lookup_status: Optional[VulnerabilityLookupStatus] = None

    # Populated by Phase 4 baseline risk scoring (app.risk +
    # app.services.analysis_service) for nodes with a known vulnerability
    # or an inconclusive vulnerability lookup. Left None for the root and
    # for genuinely clean nodes (checked, zero known vulnerabilities) —
    # see docs/ARCHITECTURE.md, "Phase 4", for exactly which nodes get one.
    risk_assessment: Optional[RiskAssessment] = None

    @property
    def id(self) -> str:
        """The root/application node is identified by name alone (it is
        not a package instance that needs version-based identity for
        vulnerability matching) — every other node is `name@version`, or
        bare `name` when no version was resolved.
        """
        if self.relation == DependencyRelation.ROOT or self.version is None:
            return self.name
        return f"{self.name}@{self.version}"


@dataclass
class DependencyEdge:
    """A directed "depends on" relationship: source requires target."""

    source: str
    target: str
