# RippleGuard

**Open Source Supply Chains: The Ripple Effect** — SDG 9 (Industry,
Innovation and Infrastructure).

A traditional vulnerability scanner answers *"Is this dependency
vulnerable?"* RippleGuard answers *"What happens if this dependency is
compromised?"*

Modern software depends on deeply nested open-source packages, so a small
compromise in a low-level dependency can propagate through many downstream
applications. RippleGuard maps a project's real dependency graph (direct +
transitive), enriches it with public vulnerability data, simulates how a
compromise would propagate through that graph, and produces a **contextual,
explainable** risk rating — not just a raw severity score.

## What the MVP demonstrates

```
Project manifest -> Dependency Discovery -> Dependency Graph
    -> Vulnerability Enrichment -> Compromise Simulation
    -> Propagation Analysis -> Blast Radius
    -> Contextual Risk -> Mitigation Priority
```

Full design rationale: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
API contract for frontend integration: [docs/API_CONTRACT.md](docs/API_CONTRACT.md).

## Team split

- **Backend** (this repo's `backend/`): Python/FastAPI — dependency
  resolution, graph construction, OSV vulnerability integration, compromise
  simulation, blast-radius and contextual risk calculation, mitigation
  prioritization, API.
- **Frontend** (`frontend/`, owned separately): dashboard, graph
  visualization, risk cards, styling/interactions. Integrates purely
  through the HTTP API in `docs/API_CONTRACT.md`.

## Backend technology

FastAPI, Pydantic v2, NetworkX, httpx, pytest. In-memory graph for the MVP —
no database, no Docker/Kubernetes/Neo4j. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for why.

## Quick start

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then visit `http://127.0.0.1:8000/api/health` or the interactive docs at
`http://127.0.0.1:8000/docs`. Full instructions: [backend/README.md](backend/README.md).

### Run tests

```bash
cd backend
pytest
```

## Current implementation status

**This is the complete backend MVP — all 5 core phases are implemented.**
`GET /api/health`, `POST /api/analyze` (NPM dependency ingestion + OSV
vulnerability enrichment + baseline contextual risk scoring + mitigation
prioritization, returning an `analysis_id`), and `POST /api/simulate`
(compromise simulation, downstream propagation tracing, graph-based
blast radius, contextual risk, and a mitigation recommendation for the
simulated node) are all implemented. The accurate summary of what exists
today: *RippleGuard can ingest an NPM dependency graph, enrich
dependencies with OSV vulnerability information, simulate compromise,
calculate downstream blast radius, produce explainable contextual risk
assessments, and prioritize dependencies for mitigation based on their
contextual risk and observed impact.* This is a deterministic, documented
heuristic — not machine learning, not an AI prediction, not a validated
industry-standard score — and it does **not** automatically patch,
remediate, or open pull requests; every recommendation is a category for
a human security team to act on.

**Planned / optional, not implemented:** NVD as a second vulnerability
provider — see the phase table in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#12-implementation-status).
