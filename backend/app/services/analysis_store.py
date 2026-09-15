"""Storage for analysis results, keyed by a generated `analysis_id`, so
`POST /api/simulate` can operate on the same dependency graph a prior
`POST /api/analyze` call produced.

Two interchangeable backends, chosen by `get_analysis_store()`:

- `AnalysisStore` — the original bounded, in-process dict. No persistence
  across process restarts, no external infrastructure. Correct for a
  single, long-lived local process (e.g. `uvicorn app.main:app --reload`),
  which is what local development and the test suite use. See
  docs/ARCHITECTURE.md, "temporary in-memory analysis storage".
- `RedisAnalysisStore` — same interface, backed by Upstash Redis (REST).
  A stateless serverless deployment (e.g. Vercel) has no single process
  that both an `/api/analyze` and a later `/api/simulate` request are
  guaranteed to hit, so an in-process dict silently loses data between
  requests in that environment. Selected automatically when Upstash REST
  credentials are configured (see `app.core.config.Settings`); otherwise
  behavior is identical to before.
"""

import base64
import pickle
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


def _serialize(result: AnalysisResult) -> str:
    return base64.b64encode(pickle.dumps(result)).decode("ascii")


def _deserialize(data: str) -> AnalysisResult:
    return pickle.loads(base64.b64decode(data))


class RedisAnalysisStore:
    """`AnalysisStore`-equivalent backed by Upstash Redis (REST API), for
    stateless/serverless deployment where an in-process dict cannot bridge
    `POST /api/analyze` -> `POST /api/simulate` (see module docstring).

    Same public interface as `AnalysisStore` (`put`/`get`/`clear`/`len`),
    approximating the same bounded-size + TTL behavior:

    - **TTL**: enforced natively by Redis (`SET ... EX ttl_seconds`)
      instead of lazily checked on access — strictly more precise than the
      original, since expiry no longer depends on some later `get()` call
      happening to notice.
    - **Bounded size**: an insertion-order index list gives FIFO eviction
      on the next `put()` once over `max_size`, mirroring the original's
      FIFO eviction. Approximate, not exact: an entry that already expired
      via Redis TTL is not proactively removed from the index, so the
      index can transiently hold more ids than live entries. Acceptable
      here the same way the original's "not a tuned LRU cache" tradeoff
      was — see `AnalysisStore` above.
    - **Serialization**: `AnalysisResult` (a plain dataclass tree wrapping
      `DependencyGraph`, itself a thin, picklable wrapper around a
      NetworkX `DiGraph` — see `app.graph.dependency_graph`) is pickled
      and base64-encoded, since Upstash's REST API is string-based. This
      data never crosses a trust boundary (it's produced and consumed only
      by this backend, under credentials only this backend holds), so
      `pickle` is appropriate here unlike for untrusted input.
    """

    _INDEX_KEY = "rippleguard:analysis:index"
    _DATA_PREFIX = "rippleguard:analysis:"

    def __init__(self, url: str, token: str, max_size: int, ttl_seconds: int) -> None:
        from upstash_redis import Redis

        self._client = Redis(url=url, token=token)
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds

    def put(self, result: AnalysisResult) -> str:
        analysis_id = str(uuid4())
        self._client.set(self._DATA_PREFIX + analysis_id, _serialize(result), ex=self._ttl_seconds)
        self._client.rpush(self._INDEX_KEY, analysis_id)
        self._evict_over_capacity()
        return analysis_id

    def get(self, analysis_id: str) -> Optional[AnalysisResult]:
        raw = self._client.get(self._DATA_PREFIX + analysis_id)
        return _deserialize(raw) if raw is not None else None

    def clear(self) -> None:
        """Drop all stored analyses. Test/debug helper only."""
        oldest = self._client.lpop(self._INDEX_KEY)
        while oldest is not None:
            self._client.delete(self._DATA_PREFIX + oldest)
            oldest = self._client.lpop(self._INDEX_KEY)

    def __len__(self) -> int:
        return self._client.llen(self._INDEX_KEY)

    def _evict_over_capacity(self) -> None:
        while self._client.llen(self._INDEX_KEY) > self._max_size:
            oldest = self._client.lpop(self._INDEX_KEY)
            if oldest is None:
                break
            self._client.delete(self._DATA_PREFIX + oldest)


def _build_analysis_store():
    settings = get_settings()
    # Prefer the newer UPSTASH_REDIS_REST_* naming; fall back to the older
    # KV_REST_API_* naming some Upstash-for-Redis resources still inject
    # (see app.core.config.Settings for why both exist).
    url = settings.upstash_redis_rest_url or settings.kv_rest_api_url
    token = settings.upstash_redis_rest_token or settings.kv_rest_api_token
    if url and token:
        return RedisAnalysisStore(
            url=url,
            token=token,
            max_size=settings.analysis_store_max_size,
            ttl_seconds=settings.analysis_store_ttl_seconds,
        )
    return AnalysisStore(
        max_size=settings.analysis_store_max_size,
        ttl_seconds=settings.analysis_store_ttl_seconds,
    )


_analysis_store = _build_analysis_store()


def get_analysis_store():
    """Return the process-wide analysis store singleton (`AnalysisStore`
    locally, `RedisAnalysisStore` in production — see module docstring).
    """
    return _analysis_store
