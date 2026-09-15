"""Compromise simulation and downstream propagation analysis (Phase 3).

Implemented:
    propagation.py          -> pure graph-traversal algorithms (BFS
                                reachability + bounded path enumeration),
                                independent of vulnerabilities/risk/API
    simulation_service.py     -> validates a simulation request against a
                                 stored analysis and orchestrates
                                 propagation.py into a SimulationResult

Deliberately vulnerability-agnostic: any dependency node with a resolved
version can be "compromised" here, regardless of whether OSV (Phase 2)
found anything for it. Vulnerability status and compromise impact are
kept as independent signals — see app.models.simulation's module
docstring and docs/ARCHITECTURE.md, "Phase 3".

Not this package's responsibility: contextual risk scoring, mitigation
priority (a later phase combines this module's impact output with
Phase 2's vulnerability data to produce those).
"""
