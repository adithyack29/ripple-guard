"""Resolves a full dependency graph from a parsed package-lock.json.

Simulates Node.js's node_modules resolution algorithm against the
lockfile's `packages` map (keyed by install path, e.g.
"node_modules/express" or "node_modules/express/node_modules/body-parser")
instead of guessing relationships from package names. This mirrors how
npm lockfileVersion 2/3 files actually represent installed packages, and
how Node.js itself resolves a `require()` by walking node_modules
directories outward from the requiring package toward the project root.

package.json (not the lockfile's own root entry) is treated as the source
of truth for *which* packages are direct dependencies and what category
they belong to; the lockfile is used purely to resolve exact versions and
transitive edges. This also makes resolution robust to a lockfile whose
root ("") entry is missing or inconsistent, since that entry is never read.
"""

from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from app.graph.dependency_graph import DependencyGraph
from app.models.dependency import (
    DependencyNode,
    DependencyRelation,
    Ecosystem,
)
from app.models.manifest import DeclaredDependency

_NODE_MODULES_PREFIX = "node_modules/"


def path_segments(path: str) -> List[str]:
    """Split a lockfile package path into ordered package-name segments.

    "" -> []
    "node_modules/express" -> ["express"]
    "node_modules/express/node_modules/body-parser" -> ["express", "body-parser"]
    "node_modules/@babel/core/node_modules/@babel/types" -> ["@babel/core", "@babel/types"]

    Scoped package names (containing their own "/") are preserved intact
    as a single segment since we split on the "/node_modules/" delimiter,
    not on every "/".
    """
    if path == "" or not path.startswith(_NODE_MODULES_PREFIX):
        return []
    remainder = path[len(_NODE_MODULES_PREFIX):]
    return remainder.split("/node_modules/")


def build_path(segments: List[str]) -> str:
    if not segments:
        return ""
    return _NODE_MODULES_PREFIX + "/node_modules/".join(segments)


def resolve_install_path(from_path: str, dep_name: str, packages: Dict[str, Any]) -> Optional[str]:
    """Emulate node_modules resolution: search from the nearest node_modules
    outward to the root, exactly mirroring how Node.js resolves a require().

    Returns the matching key into `packages`, or None if the dependency is
    not present anywhere in the lockfile (e.g. an optional dependency that
    was skipped for the platform the lockfile was generated on).
    """
    segments = path_segments(from_path)
    for i in range(len(segments), -1, -1):
        candidate = build_path(segments[:i] + [dep_name])
        if candidate in packages:
            return candidate
    return None


def _entry_dependencies(entry: Dict[str, Any]) -> Dict[str, str]:
    """Names a lockfile package entry requires at install time.

    Only "dependencies" and "optionalDependencies" are followed.
    "peerDependencies" are intentionally NOT traversed: a peer dependency
    describes a compatibility constraint the *parent* must already
    satisfy, not a distinct package this entry pulls in, and naively
    walking them risks false edges/cycles that Phase 1 does not need to
    resolve correctly. This is a deliberate MVP simplification — see
    docs/ARCHITECTURE.md.
    """
    deps: Dict[str, str] = {}
    for field_name in ("dependencies", "optionalDependencies"):
        value = entry.get(field_name)
        if isinstance(value, dict):
            for name, version in value.items():
                if isinstance(version, str):
                    deps[name] = version
    return deps


def resolve_dependency_graph(
    project_name: str,
    project_version: Optional[str],
    declared_dependencies: List[DeclaredDependency],
    packages: Dict[str, Any],
) -> Tuple[DependencyGraph, List[str]]:
    """Build the full DependencyGraph by walking the lockfile from the root.

    Traversal is breadth-first, so each node's `depth` and `category` end
    up reflecting the shortest path from the root (see
    `DependencyGraph.add_node`). Node identity is `name@version`
    (`DependencyNode.id`): if two different lockfile paths resolve to the
    exact same name+version, they are treated as one logical node with
    edges from every parent that needed it, rather than duplicated.
    Genuinely different versions of the same name always remain distinct
    nodes (this is exercised by `tests/fixtures/duplicate_versions`).

    Returns (graph, unresolved_names): unresolved_names lists
    package.json-declared dependencies that could not be found anywhere
    in the lockfile — not fatal, just excluded from the graph.
    """
    graph = DependencyGraph()
    root = DependencyNode(
        name=project_name,
        version=project_version,
        ecosystem=Ecosystem.NPM,
        relation=DependencyRelation.ROOT,
        depth=0,
        install_path="",
    )
    graph.add_node(root)

    unresolved: List[str] = []
    queue: Deque[Tuple[str, DependencyNode]] = deque()

    for declared in declared_dependencies:
        target_path = resolve_install_path("", declared.name, packages)
        if target_path is None:
            unresolved.append(declared.name)
            continue

        entry = packages[target_path]
        version = entry.get("version")
        node = DependencyNode(
            name=declared.name,
            version=version if isinstance(version, str) else None,
            ecosystem=Ecosystem.NPM,
            relation=DependencyRelation.DIRECT,
            depth=1,
            category=declared.category,
            install_path=target_path,
        )
        stored = graph.add_node(node)
        graph.add_edge(root.id, stored.id)
        if stored is node:  # first time this id has been seen -> expand its own deps
            queue.append((target_path, stored))

    while queue:
        parent_path, parent_node = queue.popleft()
        entry = packages.get(parent_path, {})
        for child_name in _entry_dependencies(entry):
            child_path = resolve_install_path(parent_path, child_name, packages)
            if child_path is None:
                # Declared by the lockfile entry but not actually present
                # (e.g. an optional dependency skipped for this platform).
                continue

            child_entry = packages[child_path]
            child_version = child_entry.get("version")
            child_node = DependencyNode(
                name=child_name,
                version=child_version if isinstance(child_version, str) else None,
                ecosystem=Ecosystem.NPM,
                relation=DependencyRelation.TRANSITIVE,
                depth=parent_node.depth + 1,
                category=parent_node.category,
                install_path=child_path,
            )
            stored_child = graph.add_node(child_node)
            graph.add_edge(parent_node.id, stored_child.id)
            if stored_child is child_node:
                queue.append((child_path, stored_child))

    return graph, unresolved
