"""Ephemeral in-memory storage for analysis results, keyed by a generated
`analysis_id`, so `POST /api/simulate` can operate on the same dependency
graph a prior `POST /api/analyze` call produced.

This is deliberately NOT a database: no persistence across process
restarts, no external infrastructure (Redis/Postgres/Neo4j) — just a
bounded, in-process dict. Appropriate for a hackathon MVP with a single
backend process and no multi-user/durability requirements. See
docs/ARCHITECTURE.md, "temporary in-memory analysis storage".
"""

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional
from uuid import uuid4

from app.core.config import get_settings
from app.services.analysis_service import AnalysisResult


@dataclass
class _StoredAnalysis:
    result: AnalysisResult
    stored_at: float


class AnalysisStore:
    """Bounded, TTL-expiring, in-process store of `AnalysisResult` objects.

    - **Bounded size**: when full, the oldest entry is evicted (FIFO) to
      make room for a new one. This is a hackathon safety valve against
      unbounded memory growth, not an LRU cache tuned for hit rate — a
      heavily-reused old analysis can be evicted before a rarely-touched
      new one. That tradeoff is fine for a demo flow of analyze-then-
      simulate shortly after.
    - **TTL**: entries are lazily expired (checked on access, no
      background thread/sweep) — an analysis older than `ttl_seconds` is
      treated as though it never existed.
    - **Not thread-safe by design**: this process serves requests on a
      single asyncio event loop, so plain dict operations are safe here;
      add locking if this were ever run under a multi-threaded/
      multi-process server.
    - **All data is lost on process restart.** This is intentional, not
      a limitation to fix — see module docstring.
    """

    def __init__(self, max_size: int, ttl_seconds: int) -> None:
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._store: "OrderedDict[str, _StoredAnalysis]" = OrderedDict()

    def put(self, result: AnalysisResult) -> str:
        self._evict_expired()
        while len(self._store) >= self._max_size:
            self._store.popitem(last=False)  # evict oldest (FIFO)
        analysis_id = str(uuid4())
        self._store[analysis_id] = _StoredAnalysis(result=result, stored_at=time.monotonic())
        return analysis_id

    def get(self, analysis_id: str) -> Optional[AnalysisResult]:
        self._evict_expired()
        entry = self._store.get(analysis_id)
        return entry.result if entry is not None else None

    def clear(self) -> None:
        """Drop all stored analyses. Test/debug helper only."""
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [
            analysis_id
            for analysis_id, entry in self._store.items()
            if now - entry.stored_at > self._ttl_seconds
        ]
        for analysis_id in expired:
            del self._store[analysis_id]


_settings = get_settings()
_analysis_store = AnalysisStore(
    max_size=_settings.analysis_store_max_size,
    ttl_seconds=_settings.analysis_store_ttl_seconds,
)


def get_analysis_store() -> AnalysisStore:
    """Return the process-wide analysis store singleton."""
    return _analysis_store
