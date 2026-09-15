"""Application settings, loaded from environment variables / .env."""

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application configuration.

    Values are read from environment variables first, falling back to a
    local `.env` file (see `.env.example`), then to the defaults below.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "RippleGuard Backend"
    app_env: str = "development"
    log_level: str = "INFO"

    # CORS origins allowed to call this API during local development.
    # The frontend (owned separately) will run on its own dev server port.
    cors_allow_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Consumed by app.vulnerability.osv_client (Phase 2).
    osv_api_base_url: str = "https://api.osv.dev"
    osv_request_timeout_seconds: float = 10.0
    osv_max_concurrency: int = 8

    # Consumed by app.services.analysis_store (Phase 3). Ephemeral,
    # in-process only — see docs/ARCHITECTURE.md.
    analysis_store_max_size: int = 100
    analysis_store_ttl_seconds: int = 3600

    # Optional: Upstash Redis REST credentials (Vercel Marketplace "Upstash
    # for Redis" integration injects these automatically once connected to
    # the project). When present, app.services.analysis_store uses a
    # Redis-backed store instead of the in-process dict, since a stateless
    # serverless deployment has no single long-lived process to hold it in
    # memory. Left unset, local development is unchanged.
    #
    # Two naming schemes exist for the exact same REST credentials,
    # depending on when/how the resource was provisioned: newer
    # connections inject UPSTASH_REDIS_REST_URL/TOKEN; resources connected
    # under Vercel's older KV-branded integration path inject
    # KV_REST_API_URL/TOKEN instead (see app.services.analysis_store's
    # _build_analysis_store, which prefers the former, falls back to the
    # latter). Both are genuine Upstash for Redis credentials — this is
    # not the deprecated @vercel/kv product, just an older env var prefix.
    upstash_redis_rest_url: Optional[str] = None
    upstash_redis_rest_token: Optional[str] = None
    kv_rest_api_url: Optional[str] = None
    kv_rest_api_token: Optional[str] = None

    # Consumed by app.simulation.propagation (Phase 3) — bounds on
    # propagation-path enumeration to avoid combinatorial blowup on
    # diamond-shaped dependency graphs.
    simulation_max_propagation_paths: int = 10
    simulation_max_path_length: int = 200

    # Consumed by app.services.analysis_service (Phase 4) — caps the
    # size of the analysis-level `ranked_risks` list in /api/analyze's
    # response. Does not affect per-node risk_assessment, which is
    # always computed for every qualifying node regardless of this cap.
    risk_ranked_list_max_size: int = 25


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (avoids re-parsing env on every call)."""
    return Settings()
