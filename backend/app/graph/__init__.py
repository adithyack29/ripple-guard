"""Dependency graph construction from NPM manifests/lockfiles.

Implemented (Phase 1):
    dependency_graph.py  -> DependencyGraph, a NetworkX-backed in-memory
                             graph of DependencyNode/DependencyEdge
    lockfile_parser.py    -> loads + validates package-lock.json (v2/v3)
    lockfile_resolver.py  -> walks node_modules resolution to build the
                              full direct+transitive graph from a lockfile
    fallback_resolver.py  -> direct-dependencies-only graph when no
                              lockfile is available

Planned (Phase 2+, not yet implemented): downstream-dependent lookups,
structural/centrality metrics, and the traversal helpers compromise
simulation will need.
"""
