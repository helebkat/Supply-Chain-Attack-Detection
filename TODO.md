# Work Split & TODO Tracker

This file is the contract between the two of us. Each task lists its owner
and is satisfied by the matching `raise NotImplementedError` getting
replaced with a real implementation **plus** the corresponding test passing.

When you finish an item, change `[ ]` to `[x]` and commit, so the other
person can pull and integrate.

---

## Helen Li — Graph track

Owns: `src/graph.py`, `src/crawler.py`, `tests/test_graph.py`,
`tests/test_crawler.py`

### `src/graph.py`
- [x] `DiGraph.__init__` — pick the adjacency-list storage (see file comment)
- [x] `DiGraph.add_node` / `add_edge` / accessors (`children`, `parents`, `nodes`, `__len__`)
- [x] `DiGraph.bfs(source)` — return depth map, also write `depth` onto each Node
- [x] `DiGraph.dfs_paths(source, target, max_paths)` — bounded simple-path enumeration
- [x] `DiGraph.find_cycles()` — DFS with WHITE/GRAY/BLACK coloring (iterative)
- [x] `DiGraph.topological_sort()` — Kahn's algorithm; return `(order, in_degrees)`

### `src/crawler.py`
- [x] `NpmCrawler.fetch_manifest` — HTTP + on-disk JSON cache
- [x] `NpmCrawler.fetch_weekly_downloads`
- [x] `NpmCrawler.resolve_latest_version`
- [x] `NpmCrawler.crawl(seed)` — BFS up to `max_depth`, returns a populated `DiGraph`

### Tests
- [x] `tests/test_graph.py` — 9 cases pass
- [x] `tests/test_crawler.py` — 6 cases pass against committed fixtures

---

## Yaxita Amin — Detection track

Owns: `src/osv_client.py`, `src/scoring.py`, `src/analyzer.py`, `src/cli.py`,
`tests/test_osv_client.py`, `tests/test_scoring.py`

### `src/osv_client.py`
- [ ] `OsvClient.query(package)` — POST + cache + parse into `Vulnerability` list
- [ ] `OsvClient.version_in_range(version, ranges)` — semver event-walking
- [ ] `OsvClient.annotate_graph(graph)` — attach `osv_ids` onto every Node

### `src/scoring.py`
- [ ] `Scorer._osv_signal`
- [ ] `Scorer._downloads_signal`
- [ ] `Scorer._ownership_signal`
- [ ] `Scorer._typosquat_signal` (hand-rolled Levenshtein, no extra dep)
- [ ] `Scorer._in_degree_signal`
- [ ] `Scorer.score_graph` — combine all 5 signals into one `Score` per node

### `src/analyzer.py`
- [ ] `analyze(seed, max_depth, include_dev, output)` — full pipeline + JSON report

### `src/cli.py`
- [ ] `main()` — argparse + pretty stdout for the `flagged` section

### Tests
- [ ] `tests/test_osv_client.py` — 3 cases pass
- [ ] `tests/test_scoring.py` — 3 cases pass

---

## Shared sync points (do these together)

- [x] **Lock the `Node` dataclass in `graph.py` before either of us starts.**
      Yaxita's scorer reads fields (`weekly_downloads`, `osv_ids`,
      `published_at`, `maintainers`) that Helen's crawler must populate.
- [x] Commit representative cached JSON files under
      `tests/fixtures/registry/` (5 packages: pkg-a..pkg-e) and
      `tests/fixtures/downloads/`.
      Yaxita still needs to drop OSV fixtures under `tests/fixtures/osv/`.
- [ ] Run `pytest -q` before every push.
- [ ] Final integration run on `express`, `react`, `lodash` seeds; capture
      output under `reports/` for the write-up.

---

## Workflow

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                       # current state: every test xfails / NotImplementedError
python -m src.cli express       # will work once analyzer + cli are filled in
```
