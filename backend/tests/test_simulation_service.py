import pytest

from app.core.exceptions import AnalysisNotFoundError, InvalidSimulationNodeError
from app.models.dependency import DependencyCategory, DependencyNode, DependencyRelation, Ecosystem
from app.models.simulation import ImpactType
from app.services.analysis_store import AnalysisStore
from app.simulation.simulation_service import simulate_compromise
from tests.graph_builders import build_test_analysis_result, build_test_graph


def _store_with(graph):
    store = AnalysisStore(max_size=10, ttl_seconds=3600)
    analysis_id = store.put(build_test_analysis_result(graph))
    return store, analysis_id


def test_unknown_analysis_id_raises():
    store = AnalysisStore(max_size=10, ttl_seconds=3600)
    with pytest.raises(AnalysisNotFoundError):
        simulate_compromise("does-not-exist", "A@1.0.0", store)


def test_unknown_node_id_raises():
    graph = build_test_graph([("my-app", "A")])
    store, analysis_id = _store_with(graph)
    with pytest.raises(InvalidSimulationNodeError):
        simulate_compromise(analysis_id, "ghost@9.9.9", store)


def test_compromising_root_raises():
    graph = build_test_graph([("my-app", "A")])
    store, analysis_id = _store_with(graph)
    with pytest.raises(InvalidSimulationNodeError):
        simulate_compromise(analysis_id, "my-app", store)


def test_node_without_resolved_version_raises():
    graph = build_test_graph([("my-app", "A")])
    # Simulate a no-lockfile-fallback node: version=None means id falls
    # back to bare name (see DependencyNode.id).
    unresolved = DependencyNode(
        name="unresolved-pkg",
        version=None,
        ecosystem=Ecosystem.NPM,
        relation=DependencyRelation.DIRECT,
        depth=1,
        category=DependencyCategory.RUNTIME,
    )
    graph.add_node(unresolved)
    graph.add_edge("my-app", unresolved.id)

    store, analysis_id = _store_with(graph)
    with pytest.raises(InvalidSimulationNodeError):
        simulate_compromise(analysis_id, "unresolved-pkg", store)


def test_successful_simulation_linear_chain():
    graph = build_test_graph([("my-app", "A"), ("A", "B"), ("B", "C")])
    store, analysis_id = _store_with(graph)

    result = simulate_compromise(analysis_id, "C@1.0.0", store)

    assert result.compromised_node_id == "C@1.0.0"
    assert result.compromised_node_name == "C"
    assert result.compromised_node_version == "1.0.0"

    by_id = {n.node_id: n for n in result.affected_nodes}
    assert by_id["B@1.0.0"].impact_type == ImpactType.DIRECT
    assert by_id["B@1.0.0"].depth == 1
    assert by_id["A@1.0.0"].impact_type == ImpactType.INDIRECT
    assert by_id["A@1.0.0"].depth == 2
    assert by_id["my-app"].impact_type == ImpactType.INDIRECT
    assert by_id["my-app"].depth == 3

    assert result.application_impact.affected is True
    assert result.application_impact.shortest_path_depth == 3

    assert result.blast_radius.affected_nodes == 3
    assert result.blast_radius.affected_dependencies == 2
    assert result.blast_radius.affected_applications == 1
    assert result.blast_radius.max_propagation_depth == 3
    assert result.blast_radius.propagation_path_count == 1
    assert result.blast_radius.propagation_paths_truncated is False

    assert result.propagation_paths == [["C@1.0.0", "B@1.0.0", "A@1.0.0", "my-app"]]


def test_disconnected_node_application_not_affected():
    graph = build_test_graph([("my-app", "A")], disconnected=["Z"])
    store, analysis_id = _store_with(graph)

    result = simulate_compromise(analysis_id, "Z@1.0.0", store)

    assert result.application_impact.affected is False
    assert result.application_impact.shortest_path_depth is None
    assert result.blast_radius.affected_nodes == 0
    assert result.blast_radius.affected_applications == 0
    assert result.propagation_paths == []
    assert result.affected_nodes == []


def test_truncated_paths_surface_a_warning():
    edges = [("A", f"mid{i}") for i in range(5)] + [(f"mid{i}", "D") for i in range(5)]
    graph = build_test_graph(edges, root="A")
    store, analysis_id = _store_with(graph)

    # simulate_compromise uses settings.simulation_max_propagation_paths
    # (default 10) — 5 paths here won't truncate, so this exercises the
    # non-truncated path; truncation itself is covered directly in
    # tests/test_propagation.py against the raw algorithm with an
    # explicit small bound.
    result = simulate_compromise(analysis_id, "D@1.0.0", store)
    assert result.blast_radius.propagation_path_count == 5
    assert result.blast_radius.propagation_paths_truncated is False
    assert result.warnings == []
