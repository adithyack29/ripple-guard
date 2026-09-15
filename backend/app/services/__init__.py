"""Orchestration layer that routes call into use-case pipelines.

Services coordinate the `graph`, `vulnerability`, `risk`, and `simulation`
packages to fulfill a request (e.g. "analyze this manifest"). Routes call
services; services should not import from `app.api`.
"""
