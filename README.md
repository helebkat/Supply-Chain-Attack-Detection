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
| Recent ownership     |  0.15  | Latest publish was within the last 30/90/180 days                 |
| Typosquatting        |  0.10  | Levenshtein ≤ 2 to a popular npm package name                     |
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
├── TODO.md                 task tracker
├── requirements.txt        runtime + test dependencies (3 packages)
├── .gitignore              ignores caches, reports, venv
├── src/
│   ├── __init__.py
│   ├── graph.py            DiGraph + BFS / DFS / cycle / toposort
│   ├── crawler.py          npm registry BFS w/ on-disk cache
│   ├── osv_client.py       OSV /v1/query + semver range matching
│   ├── scoring.py          5-signal suspicion heuristic
│   ├── analyzer.py         end-to-end pipeline + JSON report
│   └── cli.py              python -m src.cli <package>
├── tests/
│   ├── __init__.py
│   ├── test_graph.py
│   ├── test_crawler.py
│   ├── test_osv_client.py
│   ├── test_scoring.py
│   └── fixtures/           cached registry / downloads / OSV JSON
├── proposal/               original project proposal PDF
├── presentation/           final presentation slides + supporting media
├── data/
│   └── cache/              local crawl + OSV caches (git-ignored)
└── reports/                generated JSON analysis reports (git-ignored)
```

## Getting Started

### Prerequisites

- Python ≥ 3.9 (every module uses `from __future__ import annotations`,
  so generic syntax like `list[str]` works on 3.9+ as well as 3.10+)
- An internet connection on first run; subsequent runs are served entirely
  from `data/cache/`

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

Tests run fully offline against committed fixtures in `tests/fixtures/`; no
network is required to validate the implementation.

### Run the analyzer

```bash
# basic
python -m src.cli express

# tune depth and write a JSON report to disk
python -m src.cli express --max-depth 4 --output reports/express.json

# include devDependencies (much larger graph, optional)
python -m src.cli react --include-dev
```

The first invocation against a given seed populates `data/cache/` from the
live registry and OSV; every subsequent run is served from disk and is fully
offline / deterministic.

#### Sample output

```
express: 53 nodes, 90 edges, max depth 2, 0 cycles

Top in-degree (highest blast radius):
  debug                             in-degree=5
  parseurl                          in-degree=4
  statuses                          in-degree=4
  encodeurl                         in-degree=4
  mime-types                        in-degree=4

No suspicious packages detected.
```

### Programmatic use

The same pipeline is callable directly from Python; this is the entry point a
GUI / web frontend should use instead of shelling out to the CLI:

```python
from src.analyzer import analyze

report = analyze("express", max_depth=4)
# report is a JSON-serializable dict with keys:
#   "seed", "stats", "cycles", "top_in_degree", "flagged"
```

---

## Status / Roadmap

- [x] Datasets verified live (npm registry, npm downloads, OSV `/v1/query`)
- [x] Project skeleton + dependency manifest
- [x] `graph.py` — BFS, DFS, cycle detection, Kahn's toposort + 9 unit tests
- [x] `crawler.py` — BFS crawler with on-disk cache + 6 fixture-based tests
- [x] `osv_client.py` — `/v1/query` + semver range matching + 9 unit tests
- [x] `scoring.py` — 5-signal heuristic + 13 unit tests
- [x] `analyzer.py` — end-to-end pipeline + JSON report
- [x] `cli.py` — `python -m src.cli <package>` entry point
- [x] Test fixtures committed under `tests/fixtures/`
- [x] **37 / 37 tests passing**
- [ ] Graphical UI (in progress)
- [ ] Evaluation on `express`, `react`, `lodash` seeds with quantitative metrics
- [ ] Final write-up with case studies (including `event-stream`)

## Course Deliverables

| Deliverable          | Location                                               |
| -------------------- | ------------------------------------------------------ |
| Source code          | [`src/`](./src/)                                       |
| Tests                | [`tests/`](./tests/)                                   |
| Setup instructions   | [Getting Started](#getting-started) above              |
| Original proposal    | [`proposal/`](./proposal/)                             |
| Final presentation   | [`presentation/`](./presentation/)                     |

## References

- npm Registry API: <https://registry.npmjs.org/>
- npm Downloads API: <https://github.com/npm/registry/blob/main/docs/download-counts.md>
- OSV Database & API: <https://osv.dev> · <https://google.github.io/osv.dev/api/>
- GHSA-mh6f-8j2x-4483 — `event-stream` / `flatmap-stream` case study
