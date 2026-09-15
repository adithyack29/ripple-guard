# RippleGuard Backend

Python/FastAPI backend for RippleGuard. See the root [README.md](../README.md) for
project context and [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) /
[../docs/API_CONTRACT.md](../docs/API_CONTRACT.md) for design details.

## Tech stack

- **FastAPI** — API layer
- **Pydantic v2** (+ pydantic-settings) — schemas & config
- **NetworkX** — in-memory dependency graph (implemented, Phase 1)
- **python-multipart** — required by FastAPI for `/api/analyze`'s file uploads
- **httpx** — async HTTP client for the OSV API (implemented, Phase 2)
- **pytest** (+ pytest-asyncio) — testing

Contextual risk scoring (Phase 4) and mitigation prioritization (Phase 5)
are both pure Python — no new dependencies.

## Setup

Requires Python 3.9+.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional, defaults work out of the box
```

## Run the API

```bash
uvicorn app.main:app --reload
```

- API base: http://127.0.0.1:8000
- Interactive docs: http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/api/health
- Dependency ingestion:
  `curl -X POST http://127.0.0.1:8000/api/analyze -F "package_json=@package.json" -F "package_lock_json=@package-lock.json"`
  (the lockfile is optional — see [../docs/API_CONTRACT.md](../docs/API_CONTRACT.md))
- Compromise simulation (use the `analysis_id` from the response above):
  `curl -X POST http://127.0.0.1:8000/api/simulate -H "Content-Type: application/json" -d '{"analysis_id": "...", "node_id": "some-package@1.2.3"}'`

## Run tests

```bash
pytest
```

## Project layout

```
backend/
├── app/
│   ├── main.py            # FastAPI app instance, middleware, router wiring, error handlers
│   ├── api/routes/         # Thin route handlers: health.py, analyze.py (implemented)
│   ├── core/               # Settings/config (incl. OSV timeout/concurrency), domain exceptions (implemented)
│   ├── models/              # Internal domain models: DependencyNode/Edge, ManifestData, Vulnerability (implemented)
│   ├── schemas/             # Pydantic request/response contracts, incl. vulnerability fields (implemented)
│   ├── services/            # manifest_parser.py, analysis_service.py (async orchestration incl.
│   │                          baseline risk), analysis_store.py (implemented)
│   ├── graph/                # DependencyGraph (incl. dependents_of/root), lockfile parsing/resolution,
│   │                            no-lockfile fallback (implemented)
│   ├── vulnerability/         # osv_client.py, osv_adapter.py, vulnerability_service.py (implemented)
│   ├── simulation/            # propagation.py, simulation_service.py (implemented)
│   ├── risk/                   # scoring.py, explanation.py, risk_service.py (implemented)
│   └── mitigation/              # prioritization.py (implemented)
└── tests/
    ├── fixtures/             # Small hand-written package.json/package-lock.json/OSV response fixtures
    ├── graph_builders.py      # Test helper: build DependencyGraph/AnalysisResult from edge lists
    └── test_*.py             # Unit tests per layer + API-level test suites
```

## Implementation status

**All 5 core backend phases are implemented** — this is the complete
backend MVP. `GET /api/health`, `POST /api/analyze` (dependency ingestion
+ OSV vulnerability enrichment + baseline contextual risk + mitigation
prioritization, returns an `analysis_id`), and `POST /api/simulate`
(compromise simulation + downstream propagation + blast radius +
contextual risk + a single-node mitigation recommendation) are
implemented and tested (198 pytest cases, all mocked against OSV — no
live network calls in the suite itself). See
[../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for the phased
implementation plan (section 5 ingestion, section 6 vulnerability
enrichment, section 7 compromise simulation, section 8 contextual risk
scoring, section 9 mitigation prioritization). NVD as a second
vulnerability provider remains planned/optional and unimplemented.
