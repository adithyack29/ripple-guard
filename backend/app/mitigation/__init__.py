"""Mitigation prioritization (Phase 5): ranks Phase 4's RiskAssessment
objects deterministically and attaches a recommended action + reason.

Implemented:
    prioritization.py  -> sort_mitigation_candidates() (deterministic
                          ranking), recommended_action_for_level(),
                          build_mitigation_reason(), and
                          build_mitigation_priorities() (top-N projection)

This package computes no new risk/impact signals — it only ranks and
explains data Phase 2 (vulnerabilities), Phase 3 (impact), and Phase 4
(risk) already produced. It does not automatically patch, remediate, or
open pull requests; every "action" is a category for a human to act on.
See docs/ARCHITECTURE.md, "Phase 5".
"""
