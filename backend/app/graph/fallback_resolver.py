"""Builds a direct-dependencies-only graph when no lockfile is available.

No transitive resolution is attempted: doing so would require guessing at
which versions of a direct dependency's own dependencies would actually
be installed, and RippleGuard will not fabricate that (see
docs/ARCHITECTURE.md, "package.json-only fallback").
"""

from typing import List, Optional

from app.graph.dependency_graph import DependencyGraph
from app.models.dependency import DependencyNode, DependencyRelation, Ecosystem
from app.models.manifest import DeclaredDependency


def resolve_direct_only_graph(
    project_name: str,
    project_version: Optional[str],
    declared_dependencies: List[DeclaredDependency],
) -> DependencyGraph:
    """Build a graph containing only the root and its direct dependencies.

    Without a lockfile there is no resolved exact version, so each direct
    node's `version` is left as None and its declared semver range is
    discarded from identity (id falls back to bare `name` — see
    `DependencyNode.id`). Do not mistake this for a resolved-version id.
    """
    graph = DependencyGraph()
    root = DependencyNode(
        name=project_name,
        version=project_version,
        ecosystem=Ecosystem.NPM,
        relation=DependencyRelation.ROOT,
        depth=0,
    )
    graph.add_node(root)

    for declared in declared_dependencies:
        node = DependencyNode(
            name=declared.name,
            version=None,
            ecosystem=Ecosystem.NPM,
            relation=DependencyRelation.DIRECT,
            depth=1,
            category=declared.category,
            declared_range=declared.version_range,
        )
        stored = graph.add_node(node)
        graph.add_edge(root.id, stored.id)

    return graph
