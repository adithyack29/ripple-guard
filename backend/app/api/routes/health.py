"""Health check route.

Simple liveness/readiness signal for local development and for the
frontend team to confirm the backend is reachable. No dependency on
graph/vulnerability/risk/simulation layers.
"""

from fastapi import APIRouter

from app import __version__
from app.core.config import get_settings
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        app_name=settings.app_name,
        version=__version__,
        environment=settings.app_env,
    )
