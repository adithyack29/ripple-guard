"""Pydantic request/response schemas for the public API.

These define the wire contract described in docs/API_CONTRACT.md.
Keep schemas separate from `app.models` (internal domain models) so the
API shape can evolve independently of internal representations.
"""
