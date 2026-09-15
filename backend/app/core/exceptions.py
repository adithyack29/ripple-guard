"""Domain-level exceptions for dependency ingestion.

Routes should not need to know parsing internals — they let these
propagate and a global FastAPI exception handler (see `app.main`)
translates them into structured HTTP error responses.
"""


class RippleGuardError(Exception):
    """Base class for all RippleGuard domain errors."""


class ManifestParseError(RippleGuardError):
    """package.json is missing, malformed, or missing required fields."""


class LockfileParseError(RippleGuardError):
    """package-lock.json is malformed or internally inconsistent."""


class UnsupportedLockfileVersionError(LockfileParseError):
    """package-lock.json uses a lockfileVersion RippleGuard does not support."""


class SimulationError(RippleGuardError):
    """Base class for Phase 3 compromise-simulation domain errors."""


class AnalysisNotFoundError(SimulationError):
    """The given analysis_id does not exist or has expired from the in-memory store."""


class InvalidSimulationNodeError(SimulationError):
    """The given node_id cannot be used as a compromise-simulation target."""
