# RippleGuard Frontend

Owned separately (dashboard, graph visualization, risk cards, styling,
animations). No frontend code lives in this repository yet.

The backend/frontend boundary is the HTTP API described in
[../docs/API_CONTRACT.md](../docs/API_CONTRACT.md). The backend
(`../backend/`) is built and owned independently — treat that contract as
the integration surface rather than reading backend source directly.

Run the backend locally (`../backend/README.md`) to get a live
`GET /api/health` endpoint to point a dev frontend at while the rest of
the API is built out.
