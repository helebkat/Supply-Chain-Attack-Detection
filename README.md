# Supply Chain Attack Detection via npm Dependency Graph Analysis

**MSML606 Bonus Project 2** — University of Maryland

A graph-algorithms application that crawls the npm dependency graph from a
user-supplied seed package, traverses every transitive dependency, cross-checks
each one against the OSV vulnerability database, and flags the exact dependency
chains that lead to malicious or suspicious packages.

## Authors

- Helen Li (UID: 118466200)
- Yaxita Amin (UID: 121292483)

## AI Statement

No AI was used for the core algorithmic logic or the initial design approach.
All code, in-code comments, and documentation are authored manually by the
team.

---

## Problem

Modern JavaScript projects routinely pull in 1,000–5,000+ transitive
dependencies from a handful of direct `package.json` entries. A single
compromised package buried four or five hops deep (e.g. the 2018
`event-stream` → `flatmap-stream` incident) is invisible to a developer doing
linear inspection. The only way to expose the full attack surface is to
materialize the dependency graph and traverse it.

This project treats the npm registry as a directed graph and applies classical
graph algorithms (BFS, DFS, cycle detection, topological sort) to surface
high-risk packages along with the exact root → leaf path that introduced them.

## How it works

```
   seed package name
          │
          ▼
   ┌──────────────┐    cached JSON     ┌──────────────────┐
   │  NpmCrawler  │ ─────────────────► │ data/cache/      │
   │   (BFS)      │ ◄───────────────── │   registry/, dl/ │
   └──────┬───────┘                    └──────────────────┘
          │  Node + edges
          ▼
   ┌──────────────┐
   │   DiGraph    │  BFS depths, DFS paths, cycles, Kahn's toposort
   └──────┬───────┘
          │  graph + in-degrees
          ▼
   ┌──────────────┐    cached JSON     ┌──────────────────┐
   │  OsvClient   │ ─────────────────► │ data/cache/osv/  │
   │              │ ◄───────────────── │                  │
   └──────┬───────┘                    └──────────────────┘
          │  vulnerability hits
          ▼
   ┌──────────────┐
   │    Scorer    │  5 weighted signals → suspicion score per node
   └──────┬───────┘
          │
          ▼
     JSON report
   (stdout + reports/<seed>.json)
```

## Datasets

### 1. npm Registry API — graph source

- Endpoint: `https://registry.npmjs.org/<package>`
- Format: JSON manifest per package
- Fields used: `dist-tags.latest`, `versions[v].dependencies`,
  `versions[v].devDependencies`, `time` (publish timestamps), `maintainers`
- Companion endpoint: `https://api.npmjs.org/downloads/point/<range>/<package>`
  for weekly download counts

A single popular seed package (`express`, `react`, `lodash`) expands to
500–2,000+ nodes and 1,000–5,000+ edges within 4–6 BFS levels.

### 2. OSV (Open Source Vulnerability) Database — ground-truth labels

- Endpoint: `POST https://api.osv.dev/v1/query`
  with body `{"package": {"ecosystem": "npm", "name": "<package>"}}`
- Format: JSON vulnerability records
- Fields used: `id` (CVE/GHSA), `affected[].package.name`,
  `affected[].ranges`, `severity`, `summary`, `details`

OSV provides the labeled positives that turn this from a graph crawler into a
quantitatively evaluable detection system.

## Core Algorithms

| Algorithm                       | Role in the system                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------------ |
| BFS                             | Crawl the registry level-by-level from a seed; annotate every node with depth from root.  |
| DFS                             | Enumerate all root-to-node paths so every flagged package can be reported with provenance. |
| Cycle detection (DFS back-edge) | Surface circular dependency chains; npm forbids publish-time cycles, so any cycle is anomalous. |
| Topological sort (Kahn's)       | After cycle resolution, rank nodes by in-degree to find the highest-blast-radius packages. |

All four are hand-implemented in `src/graph.py` (no `networkx` dependency).

## Suspicion Scoring

Each node receives a single 0..1 suspicion score combining five weighted
signals (see `src/scoring.py`):

| Signal               | Weight | Captures                                                          |
| -------------------- | -----: | ----------------------------------------------------------------- |
| OSV hit              |  0.50  | Hard ground-truth label from osv.dev                              |
| Low downloads        |  0.15  | Near-zero weekly downloads sitting under a popular parent         |
| Recent ownership     |  0.15  | Maintainer transferred within the last 30/90/180 days             |
| Typosquatting        |  0.10  | Levenshtein ≤ 2 to a top-1k npm package name                      |
| High in-degree       |  0.10  | Many packages depend on this node (from Kahn's pass)              |

A node is *flagged* when its score crosses `DEFAULT_THRESHOLD = 0.30`
(tunable per run).

## Example Alert

```
You installed express.
At depth 4, event-stream@3.3.6 is flagged:
  • OSV: GHSA-mh6f-8j2x-4483 (CRITICAL, malicious dependency injection)
  • Path: express -> body-parser -> qs -> ... -> event-stream
  • Weekly downloads: 0
  • Maintainer transferred 180 days before flag
```

---

## Project Structure

```
.
├── README.md               this file
├── TODO.md                 shared task tracker, split by owner
├── requirements.txt        runtime + test dependencies (3 packages)
├── .gitignore              ignores caches, reports, venv
├── src/
│   ├── __init__.py
│   ├── graph.py            DiGraph + BFS / DFS / cycle / toposort     [Helen]
│   ├── crawler.py          npm registry BFS w/ on-disk cache          [Helen]
│   ├── osv_client.py       OSV /v1/query + semver range matching      [Yaxita]
│   ├── scoring.py          5-signal suspicion heuristic               [Yaxita]
│   ├── analyzer.py         end-to-end pipeline + JSON report          [Yaxita]
│   └── cli.py              python -m src.cli <package>                [Yaxita]
├── tests/
│   ├── __init__.py
│   ├── test_graph.py                                                   [Helen]
│   ├── test_crawler.py                                                 [Helen]
│   ├── test_osv_client.py                                              [Yaxita]
│   ├── test_scoring.py                                                 [Yaxita]
│   └── fixtures/           cached registry/OSV JSON for offline tests
├── data/
│   └── cache/              local crawl + OSV caches (git-ignored)
└── reports/                generated JSON analysis reports (git-ignored)
```

## Getting Started

### Prerequisites

- Python ≥ 3.10 (we use the `dataclasses`, `from __future__ import
  annotations`, and `list[str]` style annotations throughout)
- An internet connection on first run (subsequent runs are served entirely
  from `data/cache/`)

### One-time setup

```bash
git clone <this-repo>
cd Supply-Chain-Attack-Detection

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

`requirements.txt` pulls only three packages:

| Package      | Why                                                          |
| ------------ | ------------------------------------------------------------ |
| `requests`   | HTTP calls to the npm registry and osv.dev                   |
| `packaging`  | Robust semver parsing for OSV `affected[].ranges` matching   |
| `pytest`     | Test runner                                                  |

### Run the tests

```bash
pytest -q
```

Until each `raise NotImplementedError` is replaced, the tests will fail
loudly — that is the intended TDD signal. Pick a checkbox in
[`TODO.md`](./TODO.md), implement it, and re-run.

### Run the analyzer (once implemented)

```bash
# basic
python -m src.cli express

# tune depth and write a JSON report
python -m src.cli express --max-depth 4 --output reports/express.json

# include devDependencies (much larger graph, optional)
python -m src.cli react --include-dev
```

The first invocation against a given seed will populate `data/cache/` from
the live registry and OSV; every subsequent run is served from disk and is
fully offline / deterministic.

---

## Development

### Work split

The project is intentionally divided into two non-overlapping tracks so the
two team members can implement in parallel without merge conflicts:

| Track                | Owner       | Files                                                              |
| -------------------- | ----------- | ------------------------------------------------------------------ |
| Graph & crawler      | Helen Li    | `src/graph.py`, `src/crawler.py`, `tests/test_graph.py`, `tests/test_crawler.py` |
| Detection & pipeline | Yaxita Amin | `src/osv_client.py`, `src/scoring.py`, `src/analyzer.py`, `src/cli.py`, `tests/test_osv_client.py`, `tests/test_scoring.py` |

The granular checklist of stubs to fill in lives in
[`TODO.md`](./TODO.md). When you finish an item, flip its `[ ]` to `[x]`
and commit so the other person can pull and integrate.

### Shared contract

The `Node` dataclass at the top of `src/graph.py` is the single shared
interface between the two tracks. The scorer reads:

- `node.weekly_downloads`
- `node.osv_ids`
- `node.maintainers`
- `node.published_at`
- `node.version`

…all of which the crawler must populate. Lock those field names before
either track starts implementing.

### Suggested implementation order

**Helen** — graph track:
1. `DiGraph` storage + accessors (`add_node`, `add_edge`, `children`, `parents`, `__len__`)
2. `bfs` → unblocks `test_bfs_*`
3. `find_cycles` and `topological_sort` → unblocks `test_topo_*`
4. `dfs_paths`
5. `crawler.fetch_manifest` + `resolve_latest_version` (the rest of `crawl` is glue)

**Yaxita** — detection track (independent of Helen's bodies; only depends on `Node` field names):
1. `osv_client.version_in_range` — pure function, easiest win
2. `osv_client.query` — cache-only path is testable immediately
3. `scoring._typosquat_signal` (Levenshtein), `_osv_signal` (severity map)
4. `scoring.score_graph`
5. `analyzer.analyze` + `cli.main` (last; glues everything together)

---

## Status / Roadmap

- [x] Datasets verified live (npm registry, npm downloads, OSV `/v1/query`)
- [x] Project skeleton, dependency manifest, work split
- [ ] `graph.py` algorithms + tests
- [ ] `crawler.py` BFS + on-disk cache + tests
- [ ] `osv_client.py` query + semver range matching + tests
- [ ] `scoring.py` 5-signal heuristic + tests
- [ ] `analyzer.py` pipeline + JSON report
- [ ] `cli.py` entry point
- [ ] Commit fixture JSONs under `tests/fixtures/`
- [ ] Evaluation on `express`, `react`, `lodash` seeds with quantitative metrics
- [ ] Final write-up with case studies (including `event-stream`)

## References

- npm Registry API: <https://registry.npmjs.org/>
- npm Downloads API: <https://github.com/npm/registry/blob/main/docs/download-counts.md>
- OSV Database & API: <https://osv.dev> · <https://google.github.io/osv.dev/api/>
- GHSA-mh6f-8j2x-4483 — `event-stream` / `flatmap-stream` case study
