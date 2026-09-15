"""API layer: FastAPI routers and route wiring live here.

This package contains no business logic. Routes should stay thin —
they parse/validate input via `app.schemas`, delegate to `app.services`,
and return response schemas.
"""
