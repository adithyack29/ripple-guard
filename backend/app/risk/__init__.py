"""Contextual risk scoring: combines Phase 2 vulnerability data and
Phase 3 impact data into a single explainable score (Phase 4).

Implemented:
    scoring.py       -> pure, documented component-score functions
                        (severity/reachability/blast_radius/propagation/
                        structural_importance) and the weighted composite
                        formula + risk-level thresholds
    explanation.py     -> generates the human-readable explanation string
                          from the actual computed signals
    risk_service.py      -> compute_risk_assessment(): the single entry
                            point callers use; takes plain values, no
                            graph traversal, no network requests

This package deliberately does NOT make network requests and does NOT
traverse the graph itself — callers (`app.services.analysis_service` for
baseline risk, `app.simulation.simulation_service` for post-simulation
risk) extract plain values from the vulnerability/impact data they
already have and pass them in. See docs/ARCHITECTURE.md, "Phase 4", for
the full model, including why it is an explainable prototype heuristic,
not a validated industry-standard risk score.
"""
