from app.services.analysis_store import AnalysisStore


def _fake_result(marker: str):
    # A minimal stand-in — AnalysisStore never inspects the stored value,
    # so any object works for these store-mechanics tests.
    return {"marker": marker}


def test_put_then_get_round_trips():
    store = AnalysisStore(max_size=10, ttl_seconds=3600)
    analysis_id = store.put(_fake_result("a"))
    assert store.get(analysis_id) == {"marker": "a"}


def test_unknown_id_returns_none():
    store = AnalysisStore(max_size=10, ttl_seconds=3600)
    assert store.get("does-not-exist") is None


def test_ids_are_unique():
    store = AnalysisStore(max_size=10, ttl_seconds=3600)
    id1 = store.put(_fake_result("a"))
    id2 = store.put(_fake_result("b"))
    assert id1 != id2
    assert store.get(id1) == {"marker": "a"}
    assert store.get(id2) == {"marker": "b"}


def test_bounded_size_evicts_oldest_fifo():
    store = AnalysisStore(max_size=2, ttl_seconds=3600)
    id1 = store.put(_fake_result("first"))
    id2 = store.put(_fake_result("second"))
    id3 = store.put(_fake_result("third"))  # should evict id1

    assert store.get(id1) is None
    assert store.get(id2) == {"marker": "second"}
    assert store.get(id3) == {"marker": "third"}
    assert len(store) == 2


def test_ttl_expiry():
    store = AnalysisStore(max_size=10, ttl_seconds=0)
    analysis_id = store.put(_fake_result("a"))
    # ttl_seconds=0 means any elapsed monotonic time (even a few
    # microseconds) is already "expired" on the next access.
    assert store.get(analysis_id) is None


def test_clear_removes_everything():
    store = AnalysisStore(max_size=10, ttl_seconds=3600)
    store.put(_fake_result("a"))
    store.put(_fake_result("b"))
    assert len(store) == 2
    store.clear()
    assert len(store) == 0
