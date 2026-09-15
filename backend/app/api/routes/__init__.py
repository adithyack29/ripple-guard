"""Individual FastAPI route modules (one per resource/feature area).

Implemented:
    health.py    -> GET /api/health
    analyze.py   -> POST /api/analyze  (dependency ingestion + OSV
                     vulnerability enrichment; returns an analysis_id)
    simulate.py  -> POST /api/simulate (compromise simulation + downstream
                     propagation + blast radius, given an analysis_id)

Planned, not yet created: contextual risk scoring / mitigation priority
have no dedicated route yet — see docs/API_CONTRACT.md.
"""
