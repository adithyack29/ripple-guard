# RippleGuard — Architecture

## 1. System overview

Traditional dependency scanners answer: **"Is this package vulnerable?"**
RippleGuard answers: **"What happens if this package is compromised?"**

It does this by treating a project's dependencies not as an independent list
but as a graph, then reasoning over that graph: who depends on this package
(directly or transitively), what could that compromise reach, and how
important is this package structurally — regardless of what its raw CVSS
score says.

## 2. End-to-end data flow

```
Project manifest (e.g. package.json)
        |
        v
Dependency Discovery + Direct/Transitive Deps + Dependency Graph   (Phase 1 — IMPLEMENTED)
        |
        v
Vulnerability Enrichment (OSV, later NVD)                          (Phase 2 — IMPLEMENTED)
        |
        v
Compromise Simulation + Propagation Analysis + Blast Radius        (Phase 3 — IMPLEMENTED)
        |
        v
Contextual Risk (vulnerability + impact, explainable)               (Phase 4 — IMPLEMENTED)
        |
        v
Mitigation Priority                                                  (Phase 5 — PLANNED)
        |
        v
API response -> Frontend
```

This supersedes the original 9-stage sketch from the initial setup phase:
as implementation proceeded, graph construction turned out to belong
inside Phase 1 (a graph is required output of ingestion, not a separate
stage), and simulation/propagation/blast-radius were implemented together
as a single Phase 3 rather than three separate phases — see §11 for the
authoritative phase-by-phase status table. Each stage is still a separate
module (below) so any one of them can be built, tested, and explained in
isolation — important both for hackathon judging and for keeping the
system debuggable.

## 3. Backend module map

```
backend/app/
├── main.py            FastAPI app instance, middleware, router registration, error handlers
├── api/routes/         Thin HTTP handlers: parse request, call a service, return a schema
│   ├── health.py        IMPLEMENTED — GET /api/health
│   ├── analyze.py        IMPLEMENTED — POST /api/analyze (ingestion + OSV enrichment +
│   │                       baseline risk + mitigation priorities + analysis_id)
│   └── simulate.py        IMPLEMENTED — POST /api/simulate (compromise simulation + blast
│                            radius + risk + single-node mitigation recommendation)
├── core/                Settings (env config), shared exceptions
│   ├── config.py          IMPLEMENTED — incl. OSV, analysis-store, and simulation bounds
│   │                        (risk_ranked_list_max_size also bounds mitigation_priorities)
│   └── exceptions.py       IMPLEMENTED — RippleGuardError hierarchy
├── models/               Internal domain representations
│   ├── dependency.py       IMPLEMENTED — DependencyNode/Edge, enums, incl. risk_assessment
│   ├── manifest.py          IMPLEMENTED — parsed package.json representation
│   ├── vulnerability.py      IMPLEMENTED — Vulnerability, severity/status enums
│   ├── simulation.py          IMPLEMENTED — AffectedNode, BlastRadius, SimulationResult
│   │                            (incl. mitigation field)
│   ├── risk.py                  IMPLEMENTED — RiskLevel, RiskBasis, RiskBreakdown, RiskAssessment
│   └── mitigation.py              IMPLEMENTED — RecommendedAction, MitigationCandidate,
│                                    MitigationPriority, MitigationRecommendation
├── schemas/              Pydantic request/response contracts (the public API shape)
│   ├── health.py           IMPLEMENTED
│   ├── analyze.py           IMPLEMENTED — incl. vulnerability + risk + mitigation fields + analysis_id
│   ├── simulate.py            IMPLEMENTED — incl. risk_assessment + mitigation
│   ├── risk.py                  IMPLEMENTED — shared risk schemas (used by both above)
│   └── mitigation.py              IMPLEMENTED — shared mitigation schemas (used by both above)
├── services/             Orchestrates graph + vulnerability + risk + simulation per use case
│   ├── manifest_parser.py    IMPLEMENTED — package.json -> ManifestData
│   ├── analysis_service.py    IMPLEMENTED — async orchestration entry point (ingestion, OSV
│   │                            enrichment, baseline risk scoring, mitigation ranking, then
│   │                            response assembly)
│   └── analysis_store.py       IMPLEMENTED — ephemeral, bounded, TTL-expiring in-memory store
├── graph/                 Dependency graph construction & traversal (NetworkX-backed)
│   ├── dependency_graph.py    IMPLEMENTED — DependencyGraph domain type, incl.
│   │                            `dependents_of()` (impact-direction traversal) and `root`
│   ├── lockfile_parser.py      IMPLEMENTED — validates package-lock.json
│   ├── lockfile_resolver.py     IMPLEMENTED — node_modules-resolution graph builder
│   └── fallback_resolver.py      IMPLEMENTED — no-lockfile direct-only graph
├── vulnerability/          Vulnerability data providers (OSV implemented; NVD planned/optional)
│   ├── osv_client.py           IMPLEMENTED — OSV /v1/query HTTP client
│   ├── osv_adapter.py           IMPLEMENTED — raw OSV JSON -> Vulnerability
│   └── vulnerability_service.py  IMPLEMENTED — dedup + bounded-concurrency fetch
├── simulation/             Compromise simulation & downstream propagation (Phase 3)
│   ├── propagation.py           IMPLEMENTED — pure BFS reachability + bounded path enumeration,
│   │                              plus shared build_blast_radius()/build_application_impact()
│   └── simulation_service.py     IMPLEMENTED — validation + orchestration into SimulationResult
│                                   (incl. risk_assessment + a single-node mitigation recommendation)
├── risk/                   Contextual risk scoring (Phase 4)
│   ├── scoring.py                IMPLEMENTED — pure component-score functions + composite formula
│   ├── explanation.py             IMPLEMENTED — human-readable explanation generator
│   └── risk_service.py             IMPLEMENTED — compute_risk_assessment(): the single entry point
└── mitigation/             Mitigation prioritization (Phase 5)
    └── prioritization.py           IMPLEMENTED — sort_mitigation_candidates() (deterministic
                                      ranking), recommended_action_for_level(),
                                      build_mitigation_reason(), build_mitigation_priorities()
```

`models/` vs `schemas/`: `schemas` is the API's wire contract (what the
frontend sees); `models` is RippleGuard's internal understanding of the
graph and vulnerabilities. Keeping them separate lets the internal
representation evolve (e.g. switching graph libraries) without breaking the
API, and lets the API shape be tuned for the frontend without leaking
internal structure. `app.models.dependency.DependencyNode` is a plain
dataclass carrying (among other fields) `vulnerabilities: List[Vulnerability]`,
`vulnerability_lookup_status`, and `risk_assessment: Optional[RiskAssessment]`;
`app.schemas.analyze.DependencyNodeSchema` is the flat Pydantic shape the
API actually returns — the route (`app/api/routes/analyze.py`) is the only
place that converts one into the other, including nested `Vulnerability` ->
`VulnerabilitySchema`, `RiskAssessment` -> `RiskAssessmentSchema`, and
`MitigationPriority` -> `MitigationPrioritySchema` conversion.
`app/schemas/risk.py` and `app/schemas/mitigation.py` each exist
specifically so their respective identical shape is shared between
`analyze.py` and `simulate.py` without duplication.

`services/` exists so routes stay thin and the graph/vulnerability/risk/
simulation/mitigation modules stay independent of FastAPI and of each
other's internals — they're composed by a service, not by each other
directly. `app.services.analysis_service.analyze_project()` is the only
function `app/api/routes/analyze.py` calls; internally it now calls the
Phase 1 graph-building functions, Phase 2's
`app.vulnerability.vulnerability_service.fetch_vulnerabilities()` (hence
`analyze_project()` is `async def` — it performs real network I/O),
Phase 4's `app.risk.risk_service.compute_risk_assessment()` (reusing
Phase 3's `app.simulation.propagation` for impact — see §8), and Phase 5's
`app.mitigation.prioritization.sort_mitigation_candidates()` /
`build_mitigation_priorities()` (see §9) — all from the single
`_compute_baseline_risk()` pass, so risk scoring and mitigation ranking
share one graph traversal per assessed node, not two.

## 4. Dependency graph model

**Conceptual model:** nodes are packages/components, edges are "depends on"
relationships.

```
Application
    |
    v
Package A
    |
    v
Package B
    |
    v
Package C
```

Implemented node attributes (`app.models.dependency.DependencyNode`):

| Attribute       | Purpose                                                              |
|------------------|------------------------------------------------------------------------|
| name             | Package name (scoped names like `@babel/core` supported).              |
| version          | Exact resolved version, or `None` if unresolved (no lockfile).          |
| declared_range   | Raw semver range from package.json; only set when `version` is `None`. |
| ecosystem        | `npm` (only ecosystem in Phase 1; kept as an enum for future ecosystems). |
| relation         | `root` \| `direct` \| `transitive`.                                     |
| depth            | Shortest-path distance from the root (root = 0).                        |
| category         | `runtime` \| `development` \| `optional`, or `None` for the root.       |
| install_path     | The lockfile's `node_modules/...` key this node resolved to, if any.    |
| `id` (property)  | See "Node identity" below.                                              |

`downstream_dependents` and `vulnerabilities` are **not yet on the model** —
they belong to Phase 2 (graph traversal helpers) and Phase 3 (vulnerability
enrichment) respectively, and will be added to `DependencyNode` (or a
wrapping type) when those phases start, not retrofitted speculatively now.

**Node identity.** A node's `id` is `name@version` for ordinary packages —
deliberately including the version, so that `lodash@4.17.21` and
`lodash@4.17.20` are always two distinct nodes even though they share a
name. This matters because a later phase may find a vulnerability in one
version and not the other. The **root/application node is the one
exception**: its `id` is the bare project name (e.g. `"my-app"`, never
`"my-app@1.0.0"`), because it is not a package instance that needs
version-based identity for vulnerability matching — it's the context the
rest of the graph hangs off of. This matches the edge example in the
original design brief (`"source": "my-app"`, not `"source": "my-app@1.0.0"`).

If the lockfile places the *exact same* name+version at two different
`node_modules` paths (npm's hoisting/dedup can legitimately do this),
RippleGuard treats them as **one logical node with multiple incoming
edges** rather than duplicating the node — `install_path` then reflects
only the first path discovered during traversal. This is a deliberate
simplification: the alternative (path-qualified identity) would produce a
more "physically accurate" but harder-to-read graph for a hackathon demo,
at no benefit to vulnerability analysis (same name+version = same code).

**Why NetworkX, why in-memory:** the MVP needs correct graph algorithms
(reachability, shortest paths, centrality) more than it needs persistence
or concurrent multi-user access. NetworkX gives us these algorithms directly
and keeps the whole system running in a single process with no external
infrastructure — appropriate for a hackathon demo, and easy for a judge or
teammate to reason about. A database-backed graph (e.g. Neo4j) is
deliberately out of scope; it would add operational complexity without
improving the demo. `app.graph.dependency_graph.DependencyGraph` wraps a
`networkx.DiGraph` but never exposes it — the API route converts nodes/edges
to plain Pydantic schemas, so NetworkX objects never reach a JSON response.

## 5. Phase 1 — dependency ingestion (implemented)

Answers: "what does this NPM project actually depend on, directly and
transitively?" Entry point: `app.services.analysis_service.analyze_project()`.

```
package.json bytes, package-lock.json bytes (optional)
        |
        v
manifest_parser.parse_package_json()      -> ManifestData (project identity +
        |                                     declared deps by category)
        v
   lockfile provided? ----no----> fallback_resolver.resolve_direct_only_graph()
        |                                -> direct-only DependencyGraph
       yes                                  resolution_status = direct_dependencies_only
        v
lockfile_parser.parse_lockfile()          -> validates lockfileVersion (2/3 only),
        |                                     returns the raw `packages` map
        v
lockfile_resolver.resolve_dependency_graph()
        |     BFS from the root over package.json's *declared* dependencies,
        |     resolving each name to a `packages` key by walking node_modules
        |     the same way Node.js resolves a require() (nearest node_modules
        |     first, walking up to the project root) — not by guessing from
        |     package names.
        v
   any declared dependency unresolved? --yes--> resolution_status = lockfile_partial
        |no                                      (unresolved_dependencies populated)
        v
   resolution_status = lockfile_resolved
        v
analysis_service._compute_statistics()    -> totals, max depth, category breakdown
        v
api/routes/analyze.py converts DependencyGraph -> AnalyzeResponse (JSON)
```

**Why package-lock.json is preferred, and how the fallback is represented.**
`package.json` declares *ranges* (`"^4.18.2"`), not the exact versions or
transitive tree actually installed — two installs of the same
`package.json` can resolve differently over time. `package-lock.json`
records the exact resolved tree npm actually installed. RippleGuard treats
`package.json` as authoritative for *which* names are direct dependencies
and what category they're in, and the lockfile as authoritative for *exact
versions and transitive edges* — never the reverse. When no lockfile is
supplied, RippleGuard does not pretend to know the transitive tree: it
returns direct-dependency nodes only, each with `version: null` and a
`declared_range` field carrying the raw range, and sets
`resolution_status: "direct_dependencies_only"` so callers can render this
state honestly rather than mistaking a partial picture for a complete one.

**lockfileVersion support.** Only lockfileVersion 2 and 3 (npm 7+'s flat
`"packages"` map, keyed by install path such as
`"node_modules/express"`) are supported. lockfileVersion 1 (the older
nested `"dependencies"` tree format) is rejected with a structured 422
(`UnsupportedLockfileVersionError`) rather than silently falling back to
direct-only mode — an explicit error was chosen over a silent behavior
change, consistent with the general "never fabricate resolution
confidence" principle above.

**Dependency categories.** `dependencies` -> `runtime`, `devDependencies`
-> `development`, `optionalDependencies` -> `optional` — assigned to
*direct* dependencies from package.json. A transitive dependency inherits
the category of the nearest direct-dependency ancestor it descends from
(BFS processes `dependencies` before `optionalDependencies` before
`devDependencies`, so if a name is declared in more than one list —
unusual but not invalid — `runtime` wins). This is a deliberate MVP
simplification: precisely computing "is this transitive package *only*
reachable through dev dependencies" would require tracking category per
edge rather than per node, which Phase 1 does not need.

**Peer dependencies.** Not traversed. A `peerDependencies` entry describes
a compatibility constraint the *parent* package expects its consumer to
already satisfy — not a distinct package the parent pulls in — so treating
it as a graph edge would misrepresent the dependency relationship (and
risks cycles). This is documented here rather than silently omitted.

**Scoped packages** (e.g. `@babel/core`) are handled by
`app.graph.lockfile_resolver.path_segments`, which splits a lockfile path
like `"node_modules/@babel/core/node_modules/@babel/types"` into
`["@babel/core", "@babel/types"]` by splitting on the `"/node_modules/"`
delimiter rather than on every `"/"`, so a scoped name's internal slash is
never mistaken for a nesting boundary. **Duplicate package versions** are
covered under "Node identity" above.

**Error handling.** `app.core.exceptions.RippleGuardError` and its three
subclasses (`ManifestParseError`, `LockfileParseError`,
`UnsupportedLockfileVersionError`) are raised for unusable input and
caught by a single global FastAPI exception handler in `app.main`, which
returns a structured `422` rather than letting the process return a bare
`500` or crash. Recoverable issues (e.g. a missing `name` field, a
declared dependency the lockfile doesn't contain) are surfaced as
`warnings` / `unresolved_dependencies` in a normal `200` response instead
of failing the request — see [API_CONTRACT.md](./API_CONTRACT.md) for the
exact response shape and status codes.

## 6. Phase 2 — vulnerability enrichment (implemented)

Design goal: the rest of the system should not care which vulnerability
database a finding came from, and OSV's role is strictly to answer "is
this exact package/version affected?" — not to say how much that matters.
Entry point: `app.services.analysis_service._enrich_with_vulnerabilities()`,
called from `analyze_project()` after the dependency graph is built.

```
DependencyGraph (from Phase 1)
        |
        v
Collect queryable nodes: non-root, version != null
        |     (root -> NOT_APPLICABLE; no-version nodes -> NOT_CHECKED,
        |      neither is queried — see "version accuracy" below)
        v
vulnerability_service.fetch_vulnerabilities()
        |     dedupe queries by (name, version); bounded-concurrency
        |     asyncio.gather over osv_client.query_osv() calls
        v
osv_client.query_osv()            -- one HTTP call per unique (name, version)
        |     POST https://api.osv.dev/v1/query with an explicit `version`
        |     (OSV evaluates its own affected-ranges server-side)
        |     never raises: timeout/HTTP/connection/parse errors all
        |     become a failed OsvQueryOutcome instead
        v
osv_adapter.parse_osv_vulnerability() -- per raw vuln object returned
        |     normalizes id/summary/severity/aliases/references into
        |     app.models.vulnerability.Vulnerability (OSV-JSON never
        |     leaves this module)
        v
analysis_service writes results back onto each DependencyNode in place:
        |     node.vulnerabilities: List[Vulnerability]  (always a list)
        |     node.vulnerability_lookup_status: ok | unavailable |
        |                                        not_checked | not_applicable
        v
VulnerabilitySummary computed by one pass over the enriched graph
        v
api/routes/analyze.py converts nodes + summary -> AnalyzeResponse (JSON)
```

**Why OSV is an enrichment layer, not the risk engine.** This is the
core product principle (see root README): a traditional scanner stops at
"Package X, vulnerability score = HIGH." RippleGuard's future contextual
risk score needs more than that — reachability, downstream exposure,
graph importance, blast radius — none of which OSV can tell us, because
OSV only knows about one package in isolation, not this project's
specific dependency graph. Phase 2 therefore does exactly one thing:
answer "is this exact package/version affected, and by what?" for every
node. It deliberately does **not** rank, filter, or interpret that data —
that's Phase 5+ (contextual risk), a structurally separate module
(`app/risk/`) that will *consume* `Vulnerability` records as one input
among several, not replace them.

**Version accuracy.** OSV is queried with the exact resolved version
(`node.version`), never a semver range and never by name alone — this is
enforced structurally: `_enrich_with_vulnerabilities()` only builds a
query for nodes where `node.version is not None`. In
`direct_dependencies_only` mode (no lockfile), direct-dependency nodes
have `version = None` by design (see §5) and are therefore never queried
— `lodash@4.17.20` and `lodash@4.17.21` get independently correct
results because Phase 1's node identity already keeps them as separate
nodes (see §4, "Node identity"); Phase 2 simply queries each one by its
own exact version.

**Deduplication.** `vulnerability_service.fetch_vulnerabilities()`
deduplicates its input queries by `(name, version)` before issuing any
HTTP request — a package/version repeated in the input list only ever
triggers one OSV call. In practice, Phase 1's own node-identity rule
(same name+version collapses to one graph node — §4) already guarantees
every node's (name, version) pair is unique within a single graph, so
this dedup is effectively defense-in-depth: the vulnerability service is
correct on its own even if some future caller feeds it a non-deduplicated
list, rather than silently relying on a Phase 1 invariant it has no
visibility into (see "module boundary" below).

**Concurrency.** Deduplicated queries run concurrently via `asyncio.gather`
bounded by an `asyncio.Semaphore` (default concurrency: `settings.
osv_max_concurrency`, currently 8) — enough to keep a hackathon-sized
project (dozens of dependencies) fast without hammering OSV with hundreds
of simultaneous requests. This was a deliberate choice against a two-phase
batch-then-detail-fetch design (OSV's `/v1/querybatch` + per-id
`/v1/vulns/{id}` lookups): batching can reduce total request count when
many packages share a vulnerability, but adds a second round-trip and
more response-shape handling for a benefit that doesn't matter at
hackathon scale. Documented here as a known, intentional simplification —
not an oversight — should a future phase need to optimize for much larger
graphs.

**Severity normalization.** OSV vulnerability objects don't have one
consistent severity field — RippleGuard prefers a source-provided plain
label (`database_specific.severity`, the convention GHSA-derived OSV
entries use, checked at both the vulnerability level and the per-affected
level) over inventing one. If OSV only provides a raw CVSS vector string
(`severity[].score`), that string is preserved as `severity_vector` for
future use, but the normalized `severity` field is reported as `UNKNOWN`
rather than computed — RippleGuard does not implement its own CVSS
vector-to-score calculator, deliberately, to avoid silently fabricating a
severity the source didn't actually assert. GHSA's `"MODERATE"` label is
normalized to RippleGuard's `"MEDIUM"`.

**Network failure behavior.** OSV is an external dependency and can be
slow, rate-limited, or unreachable. `osv_client.query_osv()` catches
`httpx.TimeoutException`, `httpx.HTTPStatusError`, `httpx.RequestError`,
and JSON-decode failures, and never raises for any of them — it returns a
failed `OsvQueryOutcome` instead, so one flaky package can never crash
the whole analysis. Crucially, RippleGuard distinguishes **"checked,
found nothing"** from **"we don't actually know"**: a node whose lookup
failed gets `vulnerability_lookup_status: "unavailable"` and an empty
`vulnerabilities` list — never silently reported the same way as a
genuinely clean, successfully-checked package (`"ok"` with an empty
list). The aggregate `vulnerability_summary.status` mirrors this at the
whole-response level: `"ok"` only when every attempted lookup succeeded,
`"partial"` when some failed, `"unavailable"` when all attempted lookups
failed. This is treated as a hard product requirement, not a nice-to-have
— see docs/API_CONTRACT.md for the exact status values and their meaning.

**Module boundary.** `app/vulnerability/` (client + adapter + service)
never imports `app.graph` or `app.models.dependency` — it operates on
flat `PackageQuery` objects in, `PackageVulnerabilityResult` objects out,
keyed by `(name, version)`. Mapping those results onto `DependencyNode`
objects and computing the aggregate summary is
`app.services.analysis_service`'s job, not `app/vulnerability/`'s. This
keeps the vulnerability layer correct and testable in complete isolation
from the graph, and means adding NVD later is "write `nvd_client.py` +
`nvd_adapter.py` that also produce `app.models.vulnerability.Vulnerability`
objects," not a rewrite of the orchestration or API layers.

## 7. Phase 3 — compromise simulation & impact analysis (implemented)

Design goal: turn "this package has a vulnerability" into "here is what a
compromise of this package would actually reach" — the feature that
makes RippleGuard more than a conventional vulnerability scanner. Entry
point: `app.simulation.simulation_service.simulate_compromise()`, called
from `POST /api/simulate`.

### The critical direction rule

This is the single most important correctness requirement in this phase,
so it is stated plainly and enforced structurally, not just by
convention:

- **Dependency direction** (how the graph is stored, Phase 1): an edge
  `A -> B` means "A depends on B." Parent/dependent points at its
  dependency.
- **Impact direction** (how compromise propagates, Phase 3): if `B` is
  compromised, `A` — and anything that depends on `A` — may be affected.
  Impact travels the *opposite* way from the stored edge.

RippleGuard does **not** reverse or rebuild the stored graph to handle
this. Instead, `DependencyGraph.dependents_of(node_id)`
(`app/graph/dependency_graph.py`) returns the predecessors of a node in
the *stored* (dependency-direction) graph — which is exactly the set of
things that depend on it — and `app.simulation.propagation` is written to
call *only* this method, never `graph.edges` or any forward adjacency.
This is enforced by construction: the propagation module has no other
way to walk the graph. A regression test
(`tests/test_propagation.py::test_propagation_direction_regression_dependency_not_dependent`)
exists specifically to catch a future accidental reversal.

### Traversal strategy

```
Compromised node
        |
        v
compute_affected_depths()          -- BFS over dependents_of(), O(V+E)
        |     iterative (collections.deque), not recursive — safe on
        |     graphs with hundreds/thousands of nodes, no recursion-depth
        |     risk. A `visited` set means each node is enqueued at most
        |     once, which makes this both cycle-safe (a dependency cycle
        |     can never cause an infinite loop) and gives the true
        |     shortest hop-count depth to every reachable node.
        v
{node_id: depth}  -- every node reachable from the compromised node in
                      the impact direction, EXCLUDING the compromised
                      node itself
        |
        v
find_propagation_paths()           -- bounded DFS from compromised node
        |                             to the root, impact-direction order
        v
(paths, truncated)  -- up to `simulation_max_propagation_paths` (default
                        10) simple paths, each capped at
                        `simulation_max_path_length` (default 200) hops;
                        cycle-safe via per-path (not global) visited
                        tracking, so multiple genuine paths through a
                        shared ancestor are all still found
```

Two deliberately separate algorithms, for a reason: full node
*reachability* (`compute_affected_depths`) is always safe and linear —
there's exactly one BFS visit per node. Path *enumeration* is not: a
diamond-shaped dependency graph (a node reachable from the root through
several independent routes) can have combinatorially many simple paths
between two nodes, so it must be bounded (see "multiple paths" below).
Because these are separate, `affected_nodes`, `affected_dependencies`,
and `max_propagation_depth` in the API response are always exact — never
degraded by the path-count bound, which only ever limits
`propagation_paths` itself.

### Blast-radius metrics

| Field | Definition |
|---|---|
| `affected_nodes` | Total distinct nodes reachable from the compromised node in the impact direction (dependencies + the root, if reached). |
| `affected_dependencies` | `affected_nodes` excluding the root. |
| `affected_applications` | `1` if the root is reachable, else `0`. Single-project MVP, so always 0 or 1 — not a count of independent "applications" in a multi-project sense. |
| `max_propagation_depth` | Longest shortest-hop depth among all affected nodes. Exact, from `compute_affected_depths`, not path enumeration. |
| `propagation_path_count` | `len(paths)` from the bounded search — may undercount if `propagation_paths_truncated` is true. |
| `propagation_paths_truncated` | `True` if the bound was hit and more paths might exist. RippleGuard never silently reports a bounded count as if it were exhaustive — this mirrors the same honesty principle as Phase 1's `resolution_status` and Phase 2's `vulnerability_lookup_status`: a number is always paired with a flag saying whether it's complete. |

**Direct vs. indirect impact** (`AffectedNode.impact_type`): `direct` if
`depth == 1` (an immediate dependent of the compromised node — matches
the "who directly requires this package" definition), `indirect`
otherwise. This is a *different* concept from `DependencyRelation`
(root/direct/transitive), which describes a node's relationship to the
*project root*, not to the compromised node — a node can be an indirect
impact-type while being a direct dependency of the project, and vice
versa. Both fields are returned so the frontend can distinguish them
without confusion.

### Application reachability

`application_impact.affected` is `root_node_id in depths` — a genuine
graph-based reachability check via BFS, not a heuristic or a "count all
nodes" shortcut. In practice, because Phase 1 only ever adds nodes that
are themselves reachable *from* the root (see §4), every node produced by
real ingestion has at least one path back to root in the impact
direction — so `affected` will typically be `true` for any node from a
real `/api/analyze` result. The algorithm remains fully general on
purpose (tested against a synthetic disconnected-node fixture in
`tests/test_propagation.py`), so it stays correct if a future input
source (e.g. a manually constructed or partially-resolved graph) ever
produces genuinely disconnected components.

### Multiple paths

A diamond shape — `D` reachable from root `A` via both `B` and `C`,
`A -> B -> D` and `A -> C -> D` — means compromising `D` has two distinct
propagation routes back to `A`. `find_propagation_paths` discovers both
(bounded by `simulation_max_propagation_paths`), so `propagation_paths`
in the response can contain more than one path to root, and
`propagation_path_count` reflects that. This is intentionally *not* full
simple-path enumeration for arbitrary node pairs (which is combinatorial
in the worst case) — it is bounded, root-targeted, path-count-limited
search, which is what the MVP needs to demonstrate "there are multiple
routes this compromise could take" without risking exponential blowup on
a large or highly-connected graph.

### Cycle safety

Real npm dependency graphs are expected to be acyclic, but the simulation
code never assumes that. `compute_affected_depths` is cycle-safe via a
single global `visited` set (standard BFS). `find_propagation_paths` is
cycle-safe via a *per-path* check (a node already on the current
candidate path is skipped, not globally — otherwise a second, equally
valid path through an already-visited node would be missed). Both
algorithms are iterative (a `deque` and an explicit `stack`, respectively)
— no recursion, so there is no recursion-depth limit to hit on a large or
cyclic graph. `tests/test_propagation.py` includes a dedicated cyclic
fixture and a 1000-node linear-chain fixture proving both termination and
correctness at scale.

### Simulation precondition & vulnerability-agnosticism

Before traversal, `simulate_compromise()` validates: the node exists in
that analysis's own graph (which also guarantees it *belongs* to that
analysis — there's no way to reference a node from a different one), it
is not the root, and it has a resolved exact version (no-lockfile-
fallback nodes have `version = None` and cannot be simulated — see §5).
Deliberately **not** validated: whether OSV found a vulnerability for the
node. The simulation engine is vulnerability-agnostic by design — the
problem statement explicitly allows simulated compromise scenarios, so
"what if this package were compromised?" must work even for a package
OSV has never flagged. Vulnerability status (Phase 2) and compromise
impact (Phase 3) remain independent signals; a future risk phase
combines them, this phase does not conflate them (see
`app.models.simulation`'s module docstring).

### Temporary in-memory analysis storage

`POST /api/simulate` needs the same graph a prior `POST /api/analyze`
call produced. Rather than requiring the client to re-upload/reconstruct
the graph, `POST /api/analyze` now stores its full `AnalysisResult` in
`app.services.analysis_store.AnalysisStore` and returns the generated key
as `analysis_id` in its response; `POST /api/simulate` takes that
`analysis_id` plus a `node_id` and looks the graph up.

`AnalysisStore` is a deliberately simple, **ephemeral, in-process, bounded
dict** — not a database:
- **Bounded size** (`analysis_store_max_size`, default 100): FIFO
  eviction (oldest inserted, not least-recently-used) once full — a
  simple safety valve against unbounded memory growth, not a tuned cache.
- **TTL** (`analysis_store_ttl_seconds`, default 3600s / 1 hour): checked
  lazily on access, no background sweep thread.
- **Not thread-safe by design**: a single asyncio event loop serves all
  requests, so plain dict operations are safe as-is; this would need a
  lock under a multi-threaded/multi-process server.
- **All data is lost on process restart.** This is intentional, not a
  gap — a hackathon MVP with a single backend process has no
  multi-user/durability requirement, and adding Redis/Postgres/Neo4j
  purely to persist an ephemeral graph would be exactly the kind of
  infrastructure this project deliberately avoids (see §12).

A missing or expired `analysis_id` is a `404` (`AnalysisNotFoundError`),
distinguished from a structurally-present-but-invalid `node_id`, which is
a `422` (`InvalidSimulationNodeError`) — see docs/API_CONTRACT.md.

## 8. Phase 4 — explainable contextual risk scoring (implemented)

RippleGuard deliberately does **not** just report CVSS/severity. The
product principle: a traditional tool says "Package X has a HIGH
severity vulnerability." RippleGuard says "Package X has a HIGH severity
vulnerability AND its compromise can reach the analyzed application
through N propagation paths, therefore its contextual risk is higher."
**Vulnerability severity does not equal contextual risk** — risk
combines vulnerability severity (Phase 2) with graph-based impact
(Phase 3). Entry point: `app.risk.risk_service.compute_risk_assessment()`.

**This is an explainable prototype heuristic — a deterministic, hand-
documented formula with a handful of defensible factors — not a
validated industry-standard risk score, not machine-learned, and not an
AI risk prediction.** Every constant in `app.risk.scoring` is a
documented judgment call, not a value derived from external calibration
data. Use "Contextual Risk Score" / "Explainable Risk Assessment" /
"Graph-based Impact Analysis" to describe it — never "AI risk
prediction," "machine learning," "industry-certified," or "guaranteed
exploit prediction."

### Architectural separation

```
Vulnerability (Phase 2, app.vulnerability)      Impact (Phase 3, app.simulation.propagation)
        |                                                |
        +-------------------- combined by ---------------+
                                |
                                v
                    app.risk.risk_service
                    (compute_risk_assessment)
                                |
                                v
                          RiskAssessment
```

`app.risk` never makes a network request and never traverses the graph
itself — `compute_risk_assessment()` takes plain scalar/list values
(a node's `vulnerabilities`, its `vulnerability_lookup_status`, and
impact numbers already computed by `app.simulation.propagation`). The
caller (`app.services.analysis_service` for baseline risk,
`app.simulation.simulation_service` for post-simulation risk) extracts
those values from data it already has. Risk calculation does not live in
`osv_client.py`, `osv_adapter.py`, or `propagation.py` — those modules
have no idea `app.risk` exists.

### Factors and normalization (0-100 each)

| Factor | Weight | What it measures | Formula (see `app.risk.scoring` for exact constants) |
|---|---|---|---|
| Severity | 40% | How bad the worst known vulnerability is | `SEVERITY_SCORE_MAP`: CRITICAL=100, HIGH=80, MEDIUM=60, LOW=30, **UNKNOWN=50**. The single MOST severe vulnerability drives this (not an average — averaging would let several LOW findings dilute one CRITICAL one, which would be actively misleading). |
| Reachability | 25% | Whether — and how broadly — the compromise reaches real consumers | Base score 70 if the analyzed application is reachable, else 15, **plus** up to +30 for affected dependency breadth (+3 per affected dependency, capped at 10). Deliberately NOT `affected_nodes / total_nodes` — see below. |
| Blast radius | 20% | Raw scale of the affected set + route redundancy | `min(affected_nodes,15)*5 + min(propagation_path_count,5)*5`, capped at 100. |
| Propagation depth | 15% | How deep the propagation chain runs | `min(max_propagation_depth * 20, 100)` — depth 5+ maxes out. One component among four, not a "deep = critical" rule on its own. |
| Structural importance | *(not weighted)* | Direct dependent count — a lightweight, non-centrality graph signal | `min(direct_dependents * 25, 100)`. Surfaced in the breakdown and used in the explanation, but deliberately excluded from the weighted composite score — see "why structural importance isn't weighted" below. |

**Why not a raw reachability ratio.** `affected_nodes / total_nodes`
would let a huge dependency graph automatically dilute every package's
risk regardless of what it can actually reach — a package that
compromises one critical application shouldn't be scored as "low risk"
just because the graph has 500 other unrelated packages. Reachability
instead uses a fixed base score for reaching the application (the
dominant signal, independent of graph size) plus a capped breadth bonus.

**Why structural importance isn't weighted.** The spec's own recommended
model (and the one implemented here) has four weighted factors summing
to 100%. Structural importance (direct dependent count) is a genuinely
useful signal — it's why the human-readable explanation calls out
"Structurally significant: N packages directly depend on this
dependency" — but folding it into the score as an unrequested fifth
weight would mean either inventing a new percentage split not grounded
in anything, or diluting the four documented weights without
justification. It's computed, exposed in `breakdown.structural_importance`,
and used for explanation — just not scored into the composite number.

### Composite score and risk level

```python
score = round(0.40*severity + 0.25*reachability + 0.20*blast_radius + 0.15*propagation)
```

| Score | Level |
|---|---|
| >= 85 | CRITICAL |
| >= 65 | HIGH |
| >= 40 | MEDIUM |
| < 40 | LOW |

Thresholds are round, documented numbers — not derived from any external
calibration. `UNDETERMINED` is not a fifth tier below LOW; see below.

**Emergent property, not a special case:** because severity is 40% of
the formula, a node with **no known vulnerability** (severity
contributes 0) is mathematically capped at `0.25*100 + 0.20*100 +
0.15*100 = 60` — it can never reach HIGH or CRITICAL from graph
structure alone. This isn't a threshold hack; it falls directly out of
the weighting, and it's exactly what §13 of the spec requires: RippleGuard
must never label a clean dependency as critical purely because of where
it sits in the graph.

### Known vs. simulated vs. undetermined (`RiskBasis`)

Every `RiskAssessment` carries a `basis`, so a consumer never has to
infer *why* a score looks the way it does:

- **`known_vulnerability`** — at least one real OSV vulnerability exists
  for this package/version. The normal weighted formula applies.
- **`simulated_no_vulnerability`** — no known OSV vulnerability, but the
  caller explicitly asked "what if this were compromised?" (Phase 3's
  vulnerability-agnostic simulation). Severity contributes 0, so the
  score is capped at 60 (see above). This keeps "known vulnerability
  risk" and "simulated structural exposure" as related but explicitly
  distinct concepts, per §13 of the spec.
- **`undetermined`** — whether a vulnerability exists AT ALL is unknown
  (`vulnerability_lookup_status` is `unavailable` — OSV failed — or
  `not_checked` — no lockfile). `score` is `None` and `level` is
  `UNDETERMINED`, never a fabricated number. This is a hard requirement,
  not a nice-to-have: an OSV lookup failure must never silently become
  "no vulnerability," and severity `UNKNOWN` (a real, confirmed
  vulnerability OSV just didn't label — mapped to 50 in the normal
  formula) must never be conflated with `undetermined` (we don't even
  know if a vulnerability exists). These are two different kinds of
  uncertainty, handled by two different mechanisms.

Impact-derived breakdown fields (`reachability`, `blast_radius`,
`propagation`, `structural_importance`) are still computed and returned
for an `UNDETERMINED` node — only `severity` (and therefore `score`) is
`None`, since impact is knowable from the graph regardless of
vulnerability status.

### No-vulnerability case

A node with `vulnerabilities == []` and `vulnerability_lookup_status ==
ok` (genuinely checked, confirmed clean) gets **no risk assessment at
all** in `/api/analyze`'s baseline pass — not a low score, not an
`UNDETERMINED` entry, nothing. There is no risk to assess for a package
with no known issue and no explicit simulation request; inventing one
from graph structure alone would violate §13's warning directly. A clean
node *can* still get a `SIMULATED_NO_VULNERABILITY` assessment, but only
on request — via `POST /api/simulate`, where the user explicitly chose
to simulate that specific node's compromise.

### Explanation generation

`app.risk.explanation.build_explanation()` composes a sentence from the
actual computed signals — never a hard-coded generic string. It branches
on `basis` (undetermined / simulated-no-vulnerability / known-
vulnerability, with a different opening clause for each), always
includes a data-driven impact clause (mentions the actual propagation
path count, affected dependency count, and max depth, or explicitly says
"does not reach the analyzed application" when that's true), and appends
a structural-significance clause when `direct_dependents >= 2`. Example,
captured from a live run: *"High severity vulnerability (highest of 6
known vulnerabilities); compromise shows downstream reachability to the
analyzed application through 1 propagation path(s), affecting 0
dependencies at depth up to 1."*

### Where risk is computed: baseline vs. post-simulation

```
POST /api/analyze                          POST /api/simulate
        |                                          |
   ... ingestion, OSV enrichment ...          look up stored analysis
        |                                          |
_compute_baseline_risk(graph)              compute_affected_depths() +
        |  for every node with a               find_propagation_paths()
        |  known vulnerability OR                  |
        |  an inconclusive lookup:            build_blast_radius() +
        |    compute_affected_depths()        build_application_impact()
        |    find_propagation_paths()              |
        |    build_blast_radius()             compute_risk_assessment()
        |    build_application_impact()            |
        |    compute_risk_assessment()        SimulationResult.risk_assessment
        |         |
        |    node.risk_assessment
        v
  AnalysisResult.risk_summary
```

Both paths call the exact same `app.simulation.propagation` functions
(`build_blast_radius`/`build_application_impact` were promoted to public,
shared functions specifically so baseline and post-simulation risk are
never computed by two different formulas) and the exact same
`compute_risk_assessment()`. The only difference is *which* nodes get
assessed: baseline risk runs for every node with a known vulnerability or
an inconclusive lookup (one bounded graph traversal per such node —
acceptable at hackathon scale; a graph with dozens of simultaneously-
vulnerable packages could make this the dominant cost of `/api/analyze`,
flagged here as a known scaling consideration, not an unknown one), while
`/api/simulate` computes it once, for the single node the user chose to
simulate — which may or may not have a known vulnerability at all.

### Analysis-level risk summary and ranking

The primary unit of contextual risk is the dependency **node**
(`DependencyNode.risk_assessment`), not the whole application — per §16
of the spec. `AnalysisResult.risk_summary` is a convenience rollup only:
counts per level, the highest score/level seen, and a `ranked_risks` list
(capped at `settings.risk_ranked_list_max_size`, default 25) that the
frontend can render directly as a prioritized list. **`UNDETERMINED`
entries are always listed first**, ahead of every scored entry — unresolved
uncertainty demands attention and must never be sorted to the bottom as
if it were low risk. Scored entries follow in descending score order.
This is exposed as sortable data only; Phase 4 itself guarantees the
numbers are deterministic and therefore safely sortable — Phase 5 (next)
is what actually does that ranking and attaches a recommendation.

## 9. Phase 5 — mitigation prioritization (implemented)

Phase 4 answers "how risky is this dependency?" Phase 5 answers "which
dependency should we address first?" It computes **no new signals**: it
deterministically ranks the `RiskAssessment` objects Phase 4 already
produced, and attaches a short, data-driven reason and a recommended
action category. Entry point:
`app.mitigation.prioritization.build_mitigation_priorities()`, called
from `app.services.analysis_service._compute_baseline_risk()` (project-
wide, in `/api/analyze`) and, for a single node, from
`app.simulation.simulation_service.simulate_compromise()` (in
`/api/simulate`).

```
Risk Assessments (Phase 4, already computed)
        |
        v
Filter to actionable dependencies      -- structural, not a separate
        |                                  filter step: only nodes Phase 4
        |                                  ever assessed (known vulnerability
        |                                  or inconclusive lookup) are
        |                                  candidates at all — see below
        v
Deterministic ranking                  -- sort_mitigation_candidates()
        |
        v
Top-N mitigation priorities            -- build_mitigation_priorities()
        |                                  (numbered, capped)
        v
Recommended action + reason per entry
```

**Does not automatically patch, remediate, or open a pull request.**
Every "recommended action" is a category for a human security team to
decide on — see "recommended action" below.

### Ranking order (`app.mitigation.prioritization.sort_mitigation_candidates`)

A single deterministic sort key, most to least significant:

1. **UNDETERMINED first.** Unresolved uncertainty is not risk-free and
   must never be sorted as if it were low risk — see "UNDETERMINED
   handling" below. This is the same principle Phase 4 already applies to
   `risk_summary.ranked_risks`; Phase 5 uses the identical rule so the
   two lists never disagree about what "first" means.
2. **Contextual risk score, descending** (only meaningful within the
   determined group; UNDETERMINED entries have no score and are already
   separated by rule 1).
3. **Risk level, descending** (CRITICAL > HIGH > MEDIUM > LOW) — a
   tie-breaker for equal scores, since the level is derived from the
   score via thresholds and two different scores can round to the same
   level boundary.
4. **Highest known vulnerability severity, descending.**
5. **`affected_applications`, descending** — reaching the analyzed
   application outranks only affecting peer dependencies.
6. **`affected_dependencies`, descending.**
7. **`node_id`, ascending** — final, stable tie-breaker. Two otherwise
   identical candidates always sort the same way on every run; ranking
   never depends on dict/set iteration order (verified directly by
   `tests/test_mitigation_prioritization.py`, which constructs candidates
   with deliberately equal scores/levels/severity to exercise every tier).

`RiskSummary.ranked_risks` (Phase 4's simpler `{node_id, name, version,
score, level}` shape) and `mitigation_priorities` (Phase 5's richer shape,
below) are two *projections of the same sorted candidate list* — one sort
operation in `_compute_baseline_risk`, not two different orderings for
what is conceptually the same ranking.

### UNDETERMINED handling

Identical principle to Phase 4, restated because it's just as easy to get
wrong here: a node whose vulnerability lookup was `unavailable` or
`not_checked` is not "probably fine" — RippleGuard has no idea. Such
nodes are ranked **ahead of every scored entry**, not appended at the
bottom (which would visually read as "least important"), and their
`risk_level` is the literal string `"UNDETERMINED"` — never `"LOW"`,
never a fabricated numeric score. Their recommended action is
`investigate_vulnerability_data`, not `monitor`.

### Clean dependency handling

A node only ever becomes a `MitigationCandidate` if Phase 4 assessed it
in the first place — and Phase 4's `needs_assessment` check
(`_compute_baseline_risk` in `app.services.analysis_service`) already
excludes any node that was genuinely checked and found clean (`OK` lookup
status, zero vulnerabilities). There is no separate "hide clean
dependencies" filter in Phase 5 — it's structurally impossible for a
clean, unsimulated dependency to reach the ranking step at all, so the
project-wide `mitigation_priorities` list is a small, actionable subset
by construction, not a filtered-down version of "everything."

`POST /api/simulate` is the one place a clean dependency's compromise
*can* still produce a risk assessment and a recommendation
(`basis: "simulated_no_vulnerability"`) — because the caller explicitly
asked "what if this were compromised?" The reason text always says "No
known vulnerability, but simulated compromise…" so it can never be
mistaken for a real finding (see "no fake business logic" below).

### Priority entry model (`app.models.mitigation.MitigationPriority`)

`{priority, node_id, name, version, risk_level, risk_score,
vulnerability_count, affected_dependencies, affected_applications,
recommended_action, reason}`. Deliberately concise — it does not
duplicate `RiskAssessment.breakdown` or `explanation` (those are still
available via `nodes[].risk_assessment`); `reason` is a distinct, shorter
string purpose-built for a priority-list UI (see next).

### Reason generation (`app.mitigation.prioritization.build_mitigation_reason`)

Built from the actual severity label, vulnerability count, and impact
data passed in — never one generic sentence for every package (verified
by `tests/test_mitigation_prioritization.py::test_reason_not_generic_across_different_inputs`).
Distinct from Phase 4's `RiskAssessment.explanation`: the explanation is
a full narrative (exact propagation depth, path count, etc.); the
mitigation reason is a shorter, ranking-oriented sentence — e.g. *"High
severity vulnerability (highest of 6 known); reaches the analyzed
application. Overall contextual risk: Medium."* (captured from a live
run). Branches by basis exactly like the Phase 4 explanation does:
UNDETERMINED gets an "investigate" framing, `SIMULATED_NO_VULNERABILITY`
explicitly says "No known vulnerability, but simulated compromise" so it
is never confused with a real finding, and `KNOWN_VULNERABILITY` states
the actual severity and count.

### Recommended action

A deterministic, level-driven category — a prototype recommendation for
a human to act on, **not automated remediation**:

| Risk level | Recommended action |
|---|---|
| CRITICAL | `investigate_immediately` |
| HIGH | `prioritize_remediation` |
| MEDIUM | `plan_remediation` |
| LOW | `monitor` |
| UNDETERMINED | `investigate_vulnerability_data` |

### Top-N limit

`mitigation_priorities` reuses `settings.risk_ranked_list_max_size`
(default 25 — the same bound `risk_summary.ranked_risks` already used)
rather than introducing a second, potentially-inconsistent limit. The
full dependency graph and every node's own `risk_assessment` are still in
the response (`nodes[]`) regardless of this cap — only the *priority
list* is intentionally summarized to the top N actionable dependencies.

### No fake business logic

RippleGuard never claims exploit likelihood, patch availability, exploit
maturity, business criticality, production usage, or real customer
impact — none of that data exists in this pipeline. Every field in a
`MitigationPriority` traces back to a signal RippleGuard actually
computed: Phase 2 vulnerability data, Phase 3 impact, or Phase 4's
deterministic score. `recommended_action` is a category derived purely
from `risk_level`, not a claim about what will actually happen if the
dependency is ignored.

### Simulation vs. analysis scope

`POST /api/simulate` returns a single `mitigation` recommendation
(`{recommended_action, reason}`, no `priority` field) for the one node
being simulated — never a project-wide ranking. `POST /api/analyze`
returns the full `mitigation_priorities` list. This mirrors the same
split as `risk_assessment` (per-node) vs. `risk_summary` (project-wide)
in Phase 4, and keeps `/api/simulate`'s job scoped to "what if THIS
package were compromised?" — never "here is the whole project's priority
list," which requires no simulation input at all and belongs entirely to
the baseline `/api/analyze` pass.

## 10. API layer

API-first, versioned under a single `/api` prefix, thin routes that
delegate to services. See [API_CONTRACT.md](./API_CONTRACT.md) for the
concrete contract. `GET /api/health`, `POST /api/analyze` (ingestion +
OSV vulnerability enrichment + baseline contextual risk scoring +
mitigation prioritization, returning an `analysis_id`), and
`POST /api/simulate` (compromise simulation + blast radius + contextual
risk + a mitigation recommendation for the simulated node, given an
`analysis_id` + `node_id`) are all implemented.

## 11. Frontend/backend boundary

This repository's `backend/` is owned by the backend engineer (Claude
Code / this setup). `frontend/` is owned separately (Gemini/Antigravity) and
contains no application code yet — see `frontend/README.md`. The only
integration surface between the two is the HTTP API documented in
[API_CONTRACT.md](./API_CONTRACT.md). The backend does not assume anything
about how the frontend renders results; the frontend should not assume
anything about backend internals beyond the documented response shapes.

## 12. Implementation status

| Phase | Area                          | Status        |
|-------|--------------------------------|---------------|
| —     | Project scaffolding, FastAPI app, health check | **Implemented** |
| 1     | Dependency ingestion (NPM: package.json + package-lock.json v2/v3) | **Implemented** |
| 2     | Vulnerability enrichment (OSV) — normalized `Vulnerability` records attached to graph nodes | **Implemented** |
| 3     | Compromise simulation, downstream propagation analysis, graph-based blast radius | **Implemented** |
| 4     | Explainable contextual risk scoring (combining Phase 2 vulnerability + Phase 3 impact) | **Implemented** |
| 5     | Mitigation prioritization (deterministic ranking + recommended action) | **Implemented** |
| —     | NVD as a second vulnerability provider | Planned / optional — module boundary exists (see §6); explicitly not implemented in the MVP |
| —     | Graph centrality metrics beyond direct-dependent count | Planned — not needed yet; current structural-importance signal is deliberately lightweight (see §8) |
| —     | Automated remediation / patch generation / PRs | Explicitly out of scope — see §9, "no fake business logic" |
| —     | Full API integration for frontend | Implemented — `/api/health`, `/api/analyze` (ingestion + enrichment + baseline risk + mitigation priorities), `/api/simulate` (impact + risk + single-node mitigation recommendation) |

**Accurate one-line summary of current capability — this is the final
core backend feature set:** RippleGuard can ingest an NPM dependency
graph, enrich dependencies with OSV vulnerability information, simulate
compromise, calculate downstream blast radius, produce explainable
contextual risk assessments, and prioritize dependencies for mitigation
based on their contextual risk and observed impact. It does **not**
automatically patch, remediate, or open pull requests — every
recommendation is a category for a human security team to act on, and
every field traces back to a signal RippleGuard actually computed, never
an assumed exploit likelihood, patch availability, or business
criticality.

## 13. Deliberately out of scope for the MVP

Docker, Kubernetes, Neo4j, Redis, Celery, PostgreSQL, authentication/user
accounts, billing, CI/CD pipelines, and any trained ML model. These would
add operational and cognitive overhead without strengthening the core demo:
mapping a real dependency ecosystem and showing, with a clear rationale,
what a compromise would actually reach.
