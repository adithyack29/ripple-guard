from app.simulation.propagation import compute_affected_depths, find_propagation_paths
from tests.graph_builders import build_test_graph


def test_linear_chain_propagation_depths():
    # App -> A -> B -> C
    graph = build_test_graph([("my-app", "A"), ("A", "B"), ("B", "C")])
    depths = compute_affected_depths(graph, "C@1.0.0")

    assert depths == {"B@1.0.0": 1, "A@1.0.0": 2, "my-app": 3}


def test_branching_graph_only_the_dependent_branch_is_affected():
    # my-app -> A, my-app -> B (two independent direct deps), A -> C.
    # Compromising C must affect A (direct dependent) and my-app
    # (indirect, via A) — but NOT B, which never depends on C at all.
    graph = build_test_graph([("my-app", "A"), ("my-app", "B"), ("A", "C")])
    depths = compute_affected_depths(graph, "C@1.0.0")

    assert depths == {"A@1.0.0": 1, "my-app": 2}
    assert "B@1.0.0" not in depths


def test_diamond_multiple_paths():
    #        A (root)
    #       / \
    #      B   C
    #       \ /
    #        D  <- compromised
    graph = build_test_graph([("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")], root="A")

    depths = compute_affected_depths(graph, "D@1.0.0")
    assert depths == {"B@1.0.0": 1, "C@1.0.0": 1, "A": 2}

    paths, truncated = find_propagation_paths(
        graph, "D@1.0.0", "A", max_paths=10, max_path_length=200
    )
    assert truncated is False
    assert sorted(paths) == sorted(
        [
            ["D@1.0.0", "B@1.0.0", "A"],
            ["D@1.0.0", "C@1.0.0", "A"],
        ]
    )


def test_disconnected_node_not_reachable_to_root():
    graph = build_test_graph([("my-app", "A")], disconnected=["Z"])
    depths = compute_affected_depths(graph, "Z@1.0.0")

    assert depths == {}  # Z has no dependents at all
    assert "my-app" not in depths


def test_direct_vs_indirect_dependent_depth():
    # App -> A -> B -> C. Compromise C: B is direct (depth 1), A and App indirect.
    graph = build_test_graph([("my-app", "A"), ("A", "B"), ("B", "C")])
    depths = compute_affected_depths(graph, "C@1.0.0")

    assert depths["B@1.0.0"] == 1  # direct dependent
    assert depths["A@1.0.0"] == 2  # indirect
    assert depths["my-app"] == 3  # indirect


def test_cycle_safety_terminates_and_is_correct():
    # my-app -> A -> B -> C -> A (cycle back to A)
    graph = build_test_graph([("my-app", "A"), ("A", "B"), ("B", "C"), ("C", "A")])

    depths = compute_affected_depths(graph, "C@1.0.0")
    # B is C's only direct dependent; A is reached via B; my-app via A.
    # The cycle edge C->A must not cause infinite recursion or re-visit C.
    assert depths == {"B@1.0.0": 1, "A@1.0.0": 2, "my-app": 3}

    paths, truncated = find_propagation_paths(
        graph, "C@1.0.0", "my-app", max_paths=10, max_path_length=200
    )
    assert truncated is False
    assert paths == [["C@1.0.0", "B@1.0.0", "A@1.0.0", "my-app"]]


def test_root_cannot_be_reached_from_isolated_branch():
    # my-app -> A -> B (a normal chain) plus a fully separate compromised
    # node Z that nothing in the app depends on and that depends on nothing.
    graph = build_test_graph([("my-app", "A"), ("A", "B")], disconnected=["Z"])
    depths = compute_affected_depths(graph, "Z@1.0.0")
    assert "my-app" not in depths
    assert depths == {}


def test_large_linear_graph_does_not_recurse_or_hang():
    n = 1000
    edges = [("my-app", "pkg0")] + [(f"pkg{i}", f"pkg{i + 1}") for i in range(n - 1)]
    graph = build_test_graph(edges)

    depths = compute_affected_depths(graph, f"pkg{n - 1}@1.0.0")
    assert len(depths) == n  # pkg0..pkg{n-2} plus my-app
    assert depths["my-app"] == n
    assert max(depths.values()) == n


def test_propagation_direction_regression_dependency_not_dependent():
    """Regression test: propagation MUST follow dependency -> dependent
    (impact direction), never dependent -> dependency (the stored edge
    direction). my-app -> A -> B: compromising B must affect {A, my-app},
    never "nothing" and never B's own dependencies.
    """
    graph = build_test_graph([("my-app", "A"), ("A", "B"), ("B", "Z")])
    # B depends on Z (B -> Z is a dependency edge). Compromising B must
    # affect A and my-app (who depend ON B), NOT Z (what B depends on).
    depths = compute_affected_depths(graph, "B@1.0.0")

    assert set(depths.keys()) == {"A@1.0.0", "my-app"}
    assert "Z@1.0.0" not in depths  # would only appear under the WRONG (reversed) direction
    assert depths["A@1.0.0"] == 1
    assert depths["my-app"] == 2


def test_bounded_path_enumeration_truncates_and_reports_it():
    # Build a wide diamond with more paths than the bound allows.
    edges = [("A", f"mid{i}") for i in range(5)] + [(f"mid{i}", "D") for i in range(5)]
    graph = build_test_graph(edges, root="A")

    paths, truncated = find_propagation_paths(graph, "D@1.0.0", "A", max_paths=3, max_path_length=200)
    assert len(paths) == 3
    assert truncated is True


def test_max_path_length_safety_cap():
    n = 50
    edges = [("my-app", "pkg0")] + [(f"pkg{i}", f"pkg{i + 1}") for i in range(n - 1)]
    graph = build_test_graph(edges)

    paths, truncated = find_propagation_paths(
        graph, f"pkg{n - 1}@1.0.0", "my-app", max_paths=10, max_path_length=10
    )
    assert paths == []  # the only path is longer than max_path_length
    assert truncated is True


def test_compromised_node_never_included_in_its_own_affected_set():
    graph = build_test_graph([("my-app", "A"), ("A", "B")])
    depths = compute_affected_depths(graph, "B@1.0.0")
    assert "B@1.0.0" not in depths
