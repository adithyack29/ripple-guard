import json

from app.graph.lockfile_parser import parse_lockfile
from app.graph.lockfile_resolver import (
    build_path,
    path_segments,
    resolve_dependency_graph,
    resolve_install_path,
)
from app.models.dependency import DependencyCategory, DependencyRelation
from app.models.manifest import DeclaredDependency
from tests.conftest import read_fixture


def test_path_segments_root():
    assert path_segments("") == []


def test_path_segments_simple():
    assert path_segments("node_modules/express") == ["express"]


def test_path_segments_nested():
    assert path_segments("node_modules/express/node_modules/body-parser") == [
        "express",
        "body-parser",
    ]


def test_path_segments_scoped_package():
    assert path_segments("node_modules/@babel/core/node_modules/@babel/types") == [
        "@babel/core",
        "@babel/types",
    ]


def test_build_path_round_trip():
    segments = ["@babel/core", "@babel/types"]
    assert build_path(segments) == "node_modules/@babel/core/node_modules/@babel/types"
    assert path_segments(build_path(segments)) == segments


def test_resolve_install_path_prefers_nested_override():
    packages = {
        "node_modules/lodash": {"version": "4.17.21"},
        "node_modules/package-b/node_modules/lodash": {"version": "4.17.20"},
    }
    assert (
        resolve_install_path("node_modules/package-b", "lodash", packages)
        == "node_modules/package-b/node_modules/lodash"
    )
    assert resolve_install_path("node_modules/package-a", "lodash", packages) == "node_modules/lodash"


def test_resolve_install_path_walks_up_to_root():
    packages = {"node_modules/lodash": {"version": "4.17.21"}}
    assert resolve_install_path("node_modules/a/node_modules/b", "lodash", packages) == (
        "node_modules/lodash"
    )


def test_resolve_install_path_returns_none_when_absent():
    assert resolve_install_path("", "does-not-exist", {}) is None


def test_scoped_package_resolves_correctly():
    packages = {
        "node_modules/@babel/core": {"version": "7.24.0", "dependencies": {"@babel/types": "^7.24.0"}},
        "node_modules/@babel/types": {"version": "7.24.0"},
    }
    declared = [DeclaredDependency(name="@babel/core", version_range="^7.24.0", category=DependencyCategory.RUNTIME)]
    graph, unresolved = resolve_dependency_graph("app", "1.0.0", declared, packages)

    assert unresolved == []
    ids = {n.id for n in graph.nodes}
    assert "@babel/core@7.24.0" in ids
    assert "@babel/types@7.24.0" in ids


def test_simple_fixture_direct_and_transitive_classification():
    manifest_deps = [
        DeclaredDependency(name="axios", version_range="^1.6.0", category=DependencyCategory.RUNTIME),
        DeclaredDependency(name="express", version_range="^4.18.2", category=DependencyCategory.RUNTIME),
        DeclaredDependency(name="jest", version_range="^29.7.0", category=DependencyCategory.DEVELOPMENT),
    ]
    parsed = parse_lockfile(read_fixture("simple", "package-lock.json"))
    graph, unresolved = resolve_dependency_graph("my-app", "1.0.0", manifest_deps, parsed.packages)

    assert unresolved == []
    by_id = {n.id: n for n in graph.nodes}

    assert by_id["my-app"].relation == DependencyRelation.ROOT
    assert by_id["my-app"].depth == 0

    assert by_id["express@4.18.2"].relation == DependencyRelation.DIRECT
    assert by_id["express@4.18.2"].depth == 1
    assert by_id["express@4.18.2"].category == DependencyCategory.RUNTIME

    assert by_id["body-parser@1.20.2"].relation == DependencyRelation.TRANSITIVE
    assert by_id["body-parser@1.20.2"].depth == 2
    assert by_id["body-parser@1.20.2"].category == DependencyCategory.RUNTIME  # inherited from express

    assert by_id["bytes@3.1.2"].relation == DependencyRelation.TRANSITIVE
    assert by_id["bytes@3.1.2"].depth == 3

    assert by_id["jest-cli@29.7.0"].category == DependencyCategory.DEVELOPMENT  # inherited from jest

    edges = {(e.source, e.target) for e in graph.edges}
    assert ("my-app", "express@4.18.2") in edges
    assert ("express@4.18.2", "body-parser@1.20.2") in edges
    assert ("body-parser@1.20.2", "bytes@3.1.2") in edges
    assert ("my-app", "axios@1.6.7") in edges
    assert ("axios@1.6.7", "follow-redirects@1.15.5") in edges


def test_duplicate_versions_remain_distinct_nodes():
    manifest_deps = [
        DeclaredDependency(name="package-a", version_range="^1.0.0", category=DependencyCategory.RUNTIME),
        DeclaredDependency(name="package-b", version_range="^1.0.0", category=DependencyCategory.RUNTIME),
    ]
    parsed = parse_lockfile(read_fixture("duplicate_versions", "package-lock.json"))
    graph, unresolved = resolve_dependency_graph("dup-version-app", "1.0.0", manifest_deps, parsed.packages)

    assert unresolved == []
    lodash_nodes = [n for n in graph.nodes if n.name == "lodash"]
    assert len(lodash_nodes) == 2

    versions = {n.version for n in lodash_nodes}
    assert versions == {"4.17.21", "4.17.20"}

    ids = {n.id for n in lodash_nodes}
    assert ids == {"lodash@4.17.21", "lodash@4.17.20"}


def test_unresolved_declared_dependency_reported_not_fatal():
    manifest_deps = [
        DeclaredDependency(name="ghost-package", version_range="^1.0.0", category=DependencyCategory.RUNTIME),
    ]
    parsed = parse_lockfile(read_fixture("simple", "package-lock.json"))
    graph, unresolved = resolve_dependency_graph("my-app", "1.0.0", manifest_deps, parsed.packages)

    assert unresolved == ["ghost-package"]
    assert len(graph) == 1  # only the root node
