"""FastAPI application entrypoint.

Run locally with:
    uvicorn app.main:app --reload

Only implemented routes are wired in here. See docs/API_CONTRACT.md for
what is implemented vs. planned.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.routes import analyze, health, simulate
from app.core.config import get_settings
from app.core.exceptions import AnalysisNotFoundError, RippleGuardError

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description=(
        "RippleGuard backend API. Maps open-source dependency ecosystems, "
        "simulates compromise propagation, and produces explainable, "
        "contextual risk assessments."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api")
app.include_router(analyze.router, prefix="/api")
app.include_router(simulate.router, prefix="/api")


@app.exception_handler(AnalysisNotFoundError)
async def analysis_not_found_handler(request: Request, exc: AnalysisNotFoundError) -> JSONResponse:
    """A missing/expired analysis_id is a 404 (resource not found), not a
    422 — distinct from the generic domain-error handler below, which
    this more specific handler takes precedence over.
    """
    return JSONResponse(
        status_code=404,
        content={"detail": {"error_type": type(exc).__name__, "message": str(exc)}},
    )


@app.exception_handler(RippleGuardError)
async def ripple_guard_error_handler(request: Request, exc: RippleGuardError) -> JSONResponse:
    """Turns a domain parsing/validation error into a structured 422
    response instead of a bare 500, so a developer integrating against
    this API can see exactly what was wrong with the input they sent.
    """
    return JSONResponse(
        status_code=422,
        content={"detail": {"error_type": type(exc).__name__, "message": str(exc)}},
    )
