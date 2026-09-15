# RippleGuard — API Contract

Base URL (local dev): `http://127.0.0.1:8000`
All routes are namespaced under `/api`.
Interactive OpenAPI docs (auto-generated, always up to date): `/docs`.

Status legend: **IMPLEMENTED** = live today and safe to integrate against.
**PLANNED / NOT IMPLEMENTED** = shape below is an illustrative draft for
planning purposes only, subject to change, and returns nothing today.

---

## `GET /api/health` — **IMPLEMENTED**

Liveness check. No input.

### Response `200`

```json
{
  "status": "ok",
  "app_name": "RippleGuard Backend",
  "version": "0.1.0",
  "environment": "development"
}
```

| Field       | Type   | Meaning                                      |
|-------------|--------|-----------------------------------------------|
| status      | string | Always `"ok"` if the process is responding    |
| app_name    | string | Human-readable service name                   |
| version     | string | Backend package version (`app.__version__`)   |
| environment | string | `APP_ENV` the server is running under         |

---

## `POST /api/analyze` — **IMPLEMENTED (Phases 1–2–4–5: dependency ingestion + OSV vulnerability enrichment + baseline contextual risk + mitigation prioritization)**

Ingests an NPM project's `package.json` (required) and `package-lock.json`
(optional), builds a structured direct/transitive dependency graph,
enriches each dependency node with normalized vulnerability data from OSV
(https://osv.dev), computes a baseline **contextual risk assessment** for
every node with a known vulnerability or an inconclusive vulnerability
lookup, and deterministically ranks those into a **mitigation-priority
list** with a recommended action per entry. The response also carries an
`analysis_id` — pass it to `POST /api/simulate` (below) to simulate a
compromise against this same graph and get an updated, impact-specific
risk assessment (and a single-node mitigation recommendation) for the
chosen node.

A node's `risk_assessment` is an **explainable heuristic score** — a
deterministic combination of OSV severity and graph-based impact — not a
validated industry-standard risk rating, not machine-learned, and not an
AI prediction. `mitigation_priorities` ranks and explains that same data;
it does not compute anything new, and it does **not** automatically
patch, remediate, or open a pull request — every `recommended_action` is
a category for a human security team to decide on. See ARCHITECTURE.md
§8 (risk) and §9 (mitigation) for the full model.

### Request

`Content-Type: multipart/form-data`

| Field               | Required | Type | Description                                             |
|----------------------|----------|------|-----------------------------------------------------------|
| `package_json`        | Yes      | file | The project's `package.json`.                              |
| `package_lock_json`    | No       | file | The project's `package-lock.json`. Must be lockfileVersion 2 or 3 (the modern "packages"-keyed format written by npm 7+). lockfileVersion 1 is rejected with a 422. |

If `package_lock_json` is omitted, the response falls back to
direct-dependencies-only mode (see `resolution_status` below) — it is
never required.

### Response `200` — `AnalyzeResponse`

```json
{
  "analysis_id": "3b593c95-f508-45e9-b64f-9fce764067c1",
  "project": { "name": "live-check-app", "version": "1.0.0" },
  "ecosystem": "npm",
  "resolution_status": "lockfile_resolved",
  "statistics": {
    "total_dependencies": 1,
    "direct_dependencies": 1,
    "transitive_dependencies": 0,
    "max_depth": 1,
    "category_breakdown": { "runtime": 1 }
  },
  "vulnerability_summary": {
    "status": "ok",
    "vulnerable_dependencies": 1,
    "total_vulnerabilities": 6,
    "direct_vulnerable_dependencies": 1,
    "transitive_vulnerable_dependencies": 0,
    "severity_breakdown": { "MEDIUM": 3, "HIGH": 3 },
    "nodes_checked": 1,
    "nodes_skipped_no_version": 0,
    "nodes_failed": 0
  },
  "risk_summary": {
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 1,
    "low_count": 0,
    "undetermined_count": 0,
    "highest_risk_score": 54,
    "highest_risk_level": "MEDIUM",
    "ranked_risks": [
      { "node_id": "lodash@4.17.15", "name": "lodash", "version": "4.17.15", "score": 54, "level": "MEDIUM" }
    ]
  },
  "mitigation_priorities": [
    {
      "priority": 1,
      "node_id": "lodash@4.17.15",
      "name": "lodash",
      "version": "4.17.15",
      "risk_level": "MEDIUM",
      "risk_score": 54,
      "vulnerability_count": 6,
      "affected_dependencies": 0,
      "affected_applications": 1,
      "recommended_action": "plan_remediation",
      "reason": "High severity vulnerability (highest of 6 known); reaches the analyzed application. Overall contextual risk: Medium."
    }
  ],
  "nodes": [
    {
      "id": "live-check-app",
      "name": "live-check-app",
      "version": "1.0.0",
      "declared_range": null,
      "ecosystem": "npm",
      "relation": "root",
      "category": null,
      "depth": 0,
      "install_path": "",
      "vulnerabilities": [],
      "vulnerability_lookup_status": "not_applicable",
      "risk_assessment": null
    },
    {
      "id": "lodash@4.17.15",
      "name": "lodash",
      "version": "4.17.15",
      "declared_range": null,
      "ecosystem": "npm",
      "relation": "direct",
      "category": "runtime",
      "depth": 1,
      "install_path": "node_modules/lodash",
      "vulnerabilities": [
        {
          "id": "GHSA-29mw-wpgm-hmr9",
          "source": "OSV",
          "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
          "severity": "MEDIUM",
          "severity_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
          "aliases": ["CVE-2020-28500"],
          "references": [
            { "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-28500", "type": "ADVISORY" },
            { "url": "https://github.com/github/advisory-database/pull/6139", "type": "WEB" }
          ],
          "published": "2021-02-15T06:23:00Z",
          "modified": "2023-11-08T04:12:30Z"
        }
      ],
      "vulnerability_lookup_status": "ok",
      "risk_assessment": {
        "score": 54,
        "level": "MEDIUM",
        "basis": "known_vulnerability",
        "breakdown": {
          "severity": 80,
          "reachability": 70,
          "blast_radius": 10,
          "propagation": 20,
          "structural_importance": 25
        },
        "explanation": "High severity vulnerability (highest of 6 known vulnerabilities); compromise shows downstream reachability to the analyzed application through 1 propagation path(s), affecting 0 dependencies at depth up to 1.",
        "vulnerability_count": 6,
        "highest_severity": "HIGH"
      }
    }
  ],
  "edges": [
    { "source": "live-check-app", "target": "lodash@4.17.15" }
  ],
  "unresolved_dependencies": [],
  "warnings": []
}
```

This is real, captured output (trimmed to one vulnerability in `nodes[]`
for readability — the live response actually contains 6, which is why
`vulnerability_count` in the risk assessment is 6) from a live, unmocked
call to `POST /api/analyze` against a lockfile declaring `lodash@4.17.15`,
a version with genuine public OSV advisories — not an illustrative draft.
Note `breakdown.severity` (80) reflects `HIGH`, the single most severe of
the 6 known vulnerabilities — not an average. The `mitigation_priorities`
entry is also live-captured, from the same analysis: this project also
declared a clean dependency (`is-odd@3.0.1`, no known OSV vulnerability)
which is correctly **absent** from `mitigation_priorities` — see the
field reference below for exactly which nodes qualify.

### Field reference

**`analysis_id`** — ephemeral, in-memory identifier for this analysis (a fresh UUID every call). Pass it, with a `node_id` from `nodes[]`, to `POST /api/simulate`. Not durable — see that endpoint's docs below for expiry/eviction behavior.

**`project`** — `{ name, version }` of the analyzed project, read from `package.json`.

**`ecosystem`** — always `"npm"` in Phase 1.

**`resolution_status`** — one of:
| Value | Meaning |
|---|---|
| `lockfile_resolved` | A lockfile was supplied and every declared dependency was found in it. The graph includes real resolved versions and full transitive depth. |
| `lockfile_partial` | A lockfile was supplied, but one or more dependencies declared in `package.json` could not be found in it (see `unresolved_dependencies`) — e.g. a stale lockfile, or a platform-skipped optional dependency. The rest of the graph is still lockfile-resolved. |
| `direct_dependencies_only` | No lockfile was supplied. Only direct dependencies are represented; transitive dependencies are unknown and are **not** fabricated. |

**`statistics`**
| Field | Meaning |
|---|---|
| `total_dependencies` | direct + transitive node count (excludes the root). |
| `direct_dependencies` | Nodes with `relation: "direct"`. |
| `transitive_dependencies` | Nodes with `relation: "transitive"`. |
| `max_depth` | Longest shortest-path depth from the root among all nodes. |
| `category_breakdown` | Count of non-root nodes per `category` value. |

**`nodes[]`** — one entry per package plus one root entry for the project itself.
| Field | Meaning |
|---|---|
| `id` | Node identity. `name@version` for packages; bare project `name` for the root (never versioned — see ARCHITECTURE.md). In `direct_dependencies_only` mode, package nodes also fall back to bare `name` since no exact version was resolved. **Two different versions of the same package name are always two different node ids** — never collapsed. |
| `name` | Package name (may be scoped, e.g. `@babel/core`). |
| `version` | Exact resolved version, or `null` if not resolved (no lockfile). |
| `declared_range` | The raw semver range from `package.json` (e.g. `"^4.18.2"`); only populated when `version` is `null`. Never treat this as a resolved version. |
| `ecosystem` | Always `"npm"`. |
| `relation` | `"root"` \| `"direct"` \| `"transitive"`. |
| `category` | `"runtime"` \| `"development"` \| `"optional"`, or `null` for the root. A transitive dependency inherits the category of the nearest direct-dependency ancestor it descends from. |
| `depth` | Shortest-path distance from the root (root = 0). |
| `install_path` | The `node_modules/...` path this node resolved to in the lockfile, or `null` if not lockfile-resolved. |
| `vulnerabilities` | **Always a list, never `null`.** Zero or more `Vulnerability` objects (below) found by OSV for this exact package/version. An empty list is ambiguous on its own — always read it together with `vulnerability_lookup_status`. |
| `vulnerability_lookup_status` | `"ok"` (checked; `vulnerabilities` is a trustworthy result, possibly empty) \| `"unavailable"` (an OSV lookup was attempted for this package and failed — network/timeout/HTTP/parse error; `vulnerabilities` is empty because we don't know, **not** because it's clean) \| `"not_checked"` (no resolved version was available to look up — only occurs when `resolution_status` is `direct_dependencies_only`) \| `"not_applicable"` (the root node; it is the analyzed application, not a dependency package, and is never queried). |
| `risk_assessment` | `null`, or a `RiskAssessment` object (below). **Present only** for nodes with a known vulnerability, or an inconclusive lookup (`unavailable`/`not_checked`). `null` for the root, and for nodes genuinely checked and found clean — RippleGuard does not invent a risk score for a package with no known issue. |

**`RiskAssessment` object** (a node's `risk_assessment`, or `/api/simulate`'s top-level `risk_assessment`):
| Field | Meaning |
|---|---|
| `score` | `0`-`100` composite contextual risk score, or `null` when `level` is `"UNDETERMINED"`. **Never treat a `null` score as `0`/low** — it means "unknown," not "safe." |
| `level` | `"CRITICAL"` \| `"HIGH"` \| `"MEDIUM"` \| `"LOW"` \| `"UNDETERMINED"`. `UNDETERMINED` is not a tier below `LOW` — see `basis`. |
| `basis` | `"known_vulnerability"` (score driven by a real OSV finding) \| `"simulated_no_vulnerability"` (no known vulnerability; the score reflects hypothetical/structural exposure only if this package were compromised, and is mathematically capped at 60/`MEDIUM` — see ARCHITECTURE.md) \| `"undetermined"` (vulnerability presence itself is unknown — OSV lookup failed, or no lockfile was supplied). |
| `breakdown` | `{ severity, reachability, blast_radius, propagation, structural_importance }`, each `0`-`100`. `severity` is `null` only when `basis` is `"undetermined"`. `structural_importance` is informational only — **not** included in `score`'s weighted formula. See ARCHITECTURE.md §8 for the exact formula and weights (40/25/20/15%). |
| `explanation` | Human-readable, generated from the actual computed signals (e.g. real severity label, real affected-dependency count) — never a generic hard-coded string. |
| `vulnerability_count` | Number of known OSV vulnerabilities for this package/version (`0` when `basis` is not `"known_vulnerability"`). |
| `highest_severity` | `"CRITICAL"` \| `"HIGH"` \| `"MEDIUM"` \| `"LOW"` \| `"UNKNOWN"`, or `null`. The vulnerability driving `breakdown.severity` — the single most severe among `vulnerability_count` known vulnerabilities, never an average. |

**`Vulnerability` object** (inside a node's `vulnerabilities[]`):
| Field | Meaning |
|---|---|
| `id` | Canonical vulnerability id — OSV's own `id` (typically a GHSA id for the npm ecosystem). |
| `source` | Always `"OSV"` in Phase 2. Present so a future second provider (e.g. NVD) is distinguishable without a breaking change. |
| `summary` | Short human-readable description, when OSV provided one (falls back to a truncated `details` field; `null` if neither exists). |
| `severity` | `"CRITICAL"` \| `"HIGH"` \| `"MEDIUM"` \| `"LOW"` \| `"UNKNOWN"`. Taken directly from OSV/GHSA's own severity label when present (GHSA's `"MODERATE"` is normalized to `"MEDIUM"`). **Never computed or guessed by RippleGuard** — `"UNKNOWN"` means the source genuinely didn't provide one. This is vulnerability *metadata*, not RippleGuard's future contextual risk rating — see ARCHITECTURE.md. |
| `severity_vector` | Raw CVSS vector string (e.g. `"CVSS:3.1/AV:N/..."`) when OSV supplied one and no plain label was available. Preserved as-is, not interpreted into a score. Usually `null` when `severity` is already a known label. |
| `aliases` | Other identifiers for the same vulnerability, e.g. CVE ids. Never assume a CVE exists — this can be empty. |
| `references` | Up to 5 `{ url, type }` objects for further reading (`type` is OSV's own reference type, e.g. `"ADVISORY"`, `"WEB"`, `"FIX"`, or `null`). |
| `published` / `modified` | ISO-8601 timestamps from OSV, when provided, else `null`. |

**`edges[]`** — `{ source, target }` pairs, both referencing node `id`s; `source` depends on `target`.

**`vulnerability_summary`** — aggregate, descriptive-only statistics; computes nothing about risk or priority.
| Field | Meaning |
|---|---|
| `status` | `"ok"` (every attempted OSV lookup succeeded — a `vulnerable_dependencies: 0` result can be trusted) \| `"partial"` (some lookups succeeded, some failed — see `nodes_failed`) \| `"unavailable"` (every attempted lookup failed; treat vulnerability data in this response as unknown, not "clean"). Nodes skipped for having no resolved version do **not** by themselves cause `"partial"`/`"unavailable"` — see `nodes_skipped_no_version`. |
| `vulnerable_dependencies` | Count of non-root nodes with at least one vulnerability. |
| `total_vulnerabilities` | Sum of vulnerability counts across all nodes (a node with 3 vulnerabilities contributes 3). |
| `direct_vulnerable_dependencies` / `transitive_vulnerable_dependencies` | Same count, split by `relation`. |
| `severity_breakdown` | Count of individual vulnerabilities (not nodes) per `severity` value across the whole graph. |
| `nodes_checked` | Non-root, versioned nodes OSV was successfully queried for. |
| `nodes_skipped_no_version` | Non-root nodes with no resolved version, so never queried (only in `direct_dependencies_only` mode). |
| `nodes_failed` | Non-root, versioned nodes whose OSV query failed. |

Note the two similarly-named but distinct statuses: `resolution_status` (Phase 1 — how completely the *dependency graph itself* was resolved) and `vulnerability_summary.status` (Phase 2 — how completely *OSV lookups* succeeded). They vary independently; a fully lockfile-resolved graph can still have a `"partial"` or `"unavailable"` vulnerability status if OSV had problems, and vice versa.

**`risk_summary`** — analysis-level rollup of the per-node `risk_assessment`s. The primary unit of contextual risk is the dependency *node*, not the whole application — this is a convenience rollup for a dashboard, not a separate scoring model.
| Field | Meaning |
|---|---|
| `critical_count` / `high_count` / `medium_count` / `low_count` / `undetermined_count` | Count of nodes at each risk level. |
| `highest_risk_score` / `highest_risk_level` | The single highest score/level among nodes with a real `score` (i.e. excluding `UNDETERMINED` entries, which have no score). `null` if no node has a scored risk assessment. |
| `ranked_risks` | `[{ node_id, name, version, score, level }]`, bounded (25 entries by default). **`UNDETERMINED` entries are always listed first** — unresolved uncertainty demands attention and must never be sorted to the bottom as if it were low risk — followed by scored entries in descending `score` order. This is the same underlying ranking as `mitigation_priorities` below (one sort, two projections) — this is the lightweight identity+score view; `mitigation_priorities` is the richer, actionable view. |

**`mitigation_priorities`** — deterministically ranked, top-N list of dependencies to investigate or mitigate first (Phase 5). Reuses the exact `RiskAssessment` objects already in `nodes[].risk_assessment` — computes no new signals. Bounded by the same setting as `risk_summary.ranked_risks` (`risk_ranked_list_max_size`, 25 by default) — the full per-node detail still exists in `nodes[]` regardless of this cap.
| Field | Meaning |
|---|---|
| `priority` | 1-indexed rank; `1` is the top recommendation. Always sequential — no gaps. |
| `node_id` / `name` / `version` | Standard node identity fields. |
| `risk_level` | `"CRITICAL"` \| `"HIGH"` \| `"MEDIUM"` \| `"LOW"` \| `"UNDETERMINED"` — copied from that node's `risk_assessment.level`. |
| `risk_score` | Copied from `risk_assessment.score`. `null` when `risk_level` is `"UNDETERMINED"` — never `0`, never a stand-in for "low". |
| `vulnerability_count` | Copied from `risk_assessment.vulnerability_count`. |
| `affected_dependencies` / `affected_applications` | Raw impact counts (not the 0-100 `blast_radius`/`reachability` scores) — the same numbers `POST /api/simulate` would report for this node. |
| `recommended_action` | `"investigate_immediately"` (CRITICAL) \| `"prioritize_remediation"` (HIGH) \| `"plan_remediation"` (MEDIUM) \| `"monitor"` (LOW) \| `"investigate_vulnerability_data"` (UNDETERMINED). A deterministic, level-driven category for a human security team — **not automated remediation**, no patch, no pull request. |
| `reason` | Short, data-driven sentence — distinct from (and shorter than) `risk_assessment.explanation`. Varies with the actual severity/impact data; never one generic sentence for every package. |

**Only nodes Phase 4 actually assessed can appear here**: a node with a known vulnerability, or an inconclusive vulnerability lookup (`unavailable`/`not_checked`). A dependency that was checked and found clean **never appears** — RippleGuard does not invent a priority entry for a package with no known issue. (The one exception: `POST /api/simulate` can produce a `simulated_no_vulnerability`-basis assessment for a clean package the caller explicitly chose to simulate — but that never appears in `/api/analyze`'s `mitigation_priorities`, only in that one `/api/simulate` call's own `mitigation` field, below.)

**`unresolved_dependencies`** — names declared in `package.json` that a supplied lockfile did not contain. Empty unless `resolution_status` is `lockfile_partial`.

**`warnings`** — human-readable notes about non-fatal issues (e.g. missing project name, no lockfile supplied, OSV lookup failures, skipped no-version nodes). Always check this even on a `200` response.

### Error responses

| Status | When |
|---|---|
| `422` | Missing required `package_json` file (FastAPI's built-in validation error shape: `{"detail": [...]}`. |
| `422` | `package.json` or `package-lock.json` is not valid JSON, not a JSON object, or (for the lockfile) uses an unsupported `lockfileVersion`. Shape: `{"detail": {"error_type": "ManifestParseError" \| "LockfileParseError" \| "UnsupportedLockfileVersionError", "message": "..."}}`. |

RippleGuard never crashes on malformed input — every documented failure
mode above returns a structured JSON error, not a 500.

---

## `POST /api/simulate` — **IMPLEMENTED (Phases 3–4–5: compromise simulation + downstream propagation + blast radius + contextual risk + single-node mitigation recommendation)**

Given an `analysis_id` (from a prior `POST /api/analyze` call) and a
`node_id` from that analysis's dependency graph, simulates that node
being compromised, reports the downstream blast radius (which other
dependencies — and possibly the analyzed application itself — would be
affected, how many hops away, and via which propagation paths), combines
that impact with the node's known vulnerability data (if any) into a
contextual risk assessment, and returns a recommended action + short
reason for that one node.

**Does NOT return a project-wide mitigation ranking.** That's
`/api/analyze`'s `mitigation_priorities` field — this endpoint's
`mitigation` field is scoped to the single simulated node only; there is
no `mitigation_priorities` key in this response. The simulation itself is
**vulnerability-agnostic**: any dependency node with a resolved version
can be simulated, regardless of whether OSV found anything for it — this
lets you ask "what if this were compromised?" even for a package with no
known vulnerability today. When it has none, `risk_assessment.basis` is
`"simulated_no_vulnerability"`, not `"known_vulnerability"`, and the
`mitigation.reason` explicitly says so — never implying a real
vulnerability exists — see the field reference below.

### Request

`Content-Type: application/json`

```json
{
  "analysis_id": "3b593c95-f508-45e9-b64f-9fce764067c1",
  "node_id": "body-parser@1.20.2"
}
```

| Field | Required | Type | Description |
|---|---|---|---|
| `analysis_id` | Yes | string | An id returned by a prior `POST /api/analyze` call. |
| `node_id` | Yes | string | A node id from that analysis's `nodes[]` — the dependency to simulate as compromised. Must not be the root, and must have a resolved version (i.e. not from a `direct_dependencies_only` analysis). |

### Response `200` — `SimulateResponse`

This is real, captured output from a live call: analyzing the `simple`
fixture (`my-app -> express -> body-parser -> bytes`, plus `my-app ->
axios -> follow-redirects`) and simulating compromise of
`body-parser@1.20.2`.

```json
{
  "analysis_id": "3b593c95-f508-45e9-b64f-9fce764067c1",
  "compromised_node": {
    "node_id": "body-parser@1.20.2",
    "name": "body-parser",
    "version": "1.20.2"
  },
  "blast_radius": {
    "affected_nodes": 2,
    "affected_dependencies": 1,
    "affected_applications": 1,
    "max_propagation_depth": 2,
    "propagation_path_count": 1,
    "propagation_paths_truncated": false
  },
  "affected_nodes": [
    {
      "node_id": "express@4.18.2",
      "name": "express",
      "version": "4.18.2",
      "relation": "direct",
      "impact_type": "direct",
      "depth": 1
    },
    {
      "node_id": "my-app",
      "name": "my-app",
      "version": "1.0.0",
      "relation": "root",
      "impact_type": "indirect",
      "depth": 2
    }
  ],
  "propagation_paths": [
    ["body-parser@1.20.2", "express@4.18.2", "my-app"]
  ],
  "application_impact": {
    "affected": true,
    "root_node_id": "my-app",
    "shortest_path_depth": 2
  },
  "risk_assessment": {
    "score": 54,
    "level": "MEDIUM",
    "basis": "simulated_no_vulnerability",
    "breakdown": {
      "severity": 0,
      "reachability": 70,
      "blast_radius": 10,
      "propagation": 40,
      "structural_importance": 25
    },
    "explanation": "No known OSV vulnerability for this dependency; simulated compromise shows downstream reachability to the analyzed application through 1 propagation path(s), affecting 1 dependencies at depth up to 2.",
    "vulnerability_count": 0,
    "highest_severity": null
  },
  "mitigation": {
    "recommended_action": "monitor",
    "reason": "No known vulnerability, but simulated compromise; reaches the analyzed application. Overall contextual risk: Medium."
  },
  "warnings": []
}
```

(`risk_assessment`/`mitigation` here use `basis: "simulated_no_vulnerability"`
/ a "No known vulnerability, but simulated compromise…" reason because
`body-parser@1.20.2` had no known OSV vulnerability in this example —
compare with the live `known_vulnerability` example in `/api/analyze`
above, where `lodash@4.17.15`'s real advisories drive the score, and a
`plan_remediation` recommendation, instead.)

Note the propagation path is reported `body-parser -> express -> my-app`
— the IMPACT direction — even though the underlying dependency graph
stores the opposite edge direction (`my-app -> express -> body-parser`,
"my-app depends on express depends on body-parser"). Never read
`propagation_paths` as dependency edges; see ARCHITECTURE.md, "the
critical direction rule".

### Field reference

**`compromised_node`** — `{ node_id, name, version }` of the simulated node.

**`blast_radius`**
| Field | Meaning |
|---|---|
| `affected_nodes` | Total distinct nodes reachable from the compromised node in the impact direction (dependencies + the root, if reached). |
| `affected_dependencies` | `affected_nodes` excluding the root. |
| `affected_applications` | `1` if the root/application is reachable, else `0` (single-project MVP — always 0 or 1). |
| `max_propagation_depth` | Longest shortest-hop depth among all affected nodes. **Always exact** — computed from full graph reachability, never degraded by path-count bounding. |
| `propagation_path_count` | Number of paths in `propagation_paths` (bounded — see `propagation_paths_truncated`). |
| `propagation_paths_truncated` | `true` if path enumeration stopped at a bound (currently 10 paths, 200 hops max per path) and more paths may exist beyond `propagation_path_count`. RippleGuard never silently reports a bounded count as if it were exhaustive. |

**`affected_nodes[]`** — one entry per affected node (the compromised node itself is never included).
| Field | Meaning |
|---|---|
| `node_id` / `name` / `version` | Standard node identity fields, same meaning as in `/api/analyze`. |
| `relation` | `"root"` \| `"direct"` \| `"transitive"` — this node's Phase 1 dependency relation to the *project root*. |
| `impact_type` | `"direct"` \| `"indirect"` — this node's relation to the *compromised node*: `"direct"` means it directly depends on the compromised node (`depth == 1`); `"indirect"` means it's affected through one or more intermediate dependents. **Do not confuse with `relation`** — a node can be a direct impact type while being a transitive project dependency, and vice versa. |
| `depth` | Hops from the compromised node in the impact direction. |

**`propagation_paths[]`** — each path is an ordered list of node ids in IMPACT direction: `[compromised_node_id, ..., root_node_id]`. Bounded (see `propagation_paths_truncated`) — not necessarily every possible path.

**`application_impact`**
| Field | Meaning |
|---|---|
| `affected` | Whether the root (analyzed application) is reachable from the compromised node — a genuine graph reachability check, not a heuristic. |
| `root_node_id` | The root node's id, for convenience. |
| `shortest_path_depth` | Hop depth at which the root was reached, or `null` if `affected` is `false`. |

**`risk_assessment`** — the `RiskAssessment` object (documented under `/api/analyze`'s `nodes[].risk_assessment` above — the shape is identical). Unlike a node's `risk_assessment` in `/api/analyze`, this field is **always present** here (never `null`): simulating a node always produces a risk assessment, whether it's driven by a real known vulnerability (`basis: "known_vulnerability"`) or is purely hypothetical (`basis: "simulated_no_vulnerability"`, since the node had no known vulnerability but the caller explicitly asked to simulate its compromise anyway).

**`mitigation`** — a recommendation for the single simulated node (Phase 5). **Not a ranked list** — there is no `priority` field and no `mitigation_priorities` key in this response; that's `/api/analyze`'s job.
| Field | Meaning |
|---|---|
| `recommended_action` | Same deterministic, level-driven categories as `/api/analyze`'s `mitigation_priorities[].recommended_action` (`investigate_immediately` \| `prioritize_remediation` \| `plan_remediation` \| `monitor` \| `investigate_vulnerability_data`), derived from `risk_assessment.level`. Not automated remediation. |
| `reason` | Short, data-driven reason, same style as a `mitigation_priorities` entry's `reason`. When `risk_assessment.basis` is `"simulated_no_vulnerability"`, this always states "No known vulnerability, but simulated compromise…" so it can never be mistaken for a real finding. |

**`warnings`** — e.g. a note when `propagation_paths_truncated` is true, explaining which fields remain exact regardless.

### Error responses

| Status | When | Shape |
|---|---|---|
| `404` | `analysis_id` is unknown or has expired from the in-memory store. | `{"detail": {"error_type": "AnalysisNotFoundError", "message": "..."}}` |
| `422` | `node_id` doesn't exist in that analysis, **or** is the root node, **or** has no resolved version (no-lockfile analysis). | `{"detail": {"error_type": "InvalidSimulationNodeError", "message": "..."}}` |
| `422` | Malformed request body (missing `analysis_id`/`node_id`). | FastAPI's built-in validation error shape. |

### Analysis storage (why `analysis_id` exists, and its limits)

`POST /api/analyze` stores its full result in an in-process, in-memory
`AnalysisStore` (see ARCHITECTURE.md) and returns the generated key as
`analysis_id`. This is **not a database** — no persistence across
restarts, no external infrastructure:

- **Bounded size**: 100 analyses by default; the oldest is evicted (FIFO)
  once full.
- **TTL**: 1 hour by default, checked lazily on access.
- **Ephemeral**: a server restart clears everything. Don't rely on an
  `analysis_id` surviving longer than the demo session that created it —
  re-run `/api/analyze` if a `404` comes back unexpectedly.

---

## Conventions (apply to all endpoints, current and future)

- **Errors:** default is FastAPI/Starlette's standard shape,
  `{"detail": "message"}` (or its built-in validation-error array form).
  Domain-level parsing/validation failures instead return
  `{"detail": {"error_type": "...", "message": "..."}}`, normally at
  `422` — except a missing/expired `analysis_id` on `/api/simulate`,
  which is a `404` (`AnalysisNotFoundError`) since that's a missing
  resource, not malformed input. See each endpoint above for its
  concrete error types.
- **CORS:** enabled for local frontend dev servers (see
  `backend/app/core/config.py` → `cors_allow_origins`); update that list if
  the frontend runs on a different port.
- **Versioning:** all routes live under `/api`. No `/v1`-style versioning
  yet — not needed for a hackathon MVP with a single consumer.
