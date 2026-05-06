# TODO Tracker

When you finish an item, change `[ ]` to `[x]` and commit, so the other
person can pull and integrate.

---

## Helen Li — Graph track

Owns: `src/graph.py`, `src/crawler.py`, `tests/test_graph.py`,
`tests/test_crawler.py`

### `src/graph.py`
- [x] `DiGraph.__init__` — adjacency-list storage
- [x] `DiGraph.add_node` / `add_edge` / accessors (`children`, `parents`, `nodes`, `__len__`)
- [x] `DiGraph.bfs(source)` — depth map, writes `Node.depth`
- [x] `DiGraph.dfs_paths(source, target, max_paths)` — bounded simple-path enumeration
- [x] `DiGraph.find_cycles()` — iterative DFS with WHITE/GRAY/BLACK coloring
- [x] `DiGraph.topological_sort()` — Kahn's algorithm; returns `(order, in_degrees)`

### `src/crawler.py`
- [x] `NpmCrawler.fetch_manifest` — HTTP + on-disk JSON cache
- [x] `NpmCrawler.fetch_weekly_downloads`
- [x] `NpmCrawler.resolve_latest_version`
- [x] `NpmCrawler.crawl(seed)` — BFS up to `max_depth`, returns a populated `DiGraph`

### Tests
- [x] `tests/test_graph.py` — 9 cases pass
- [x] `tests/test_crawler.py` — 6 cases pass against committed fixtures

---

## Yaxita Amin — Detection & UI track

Owns: `src/osv_client.py`, `src/scoring.py`, `src/analyzer.py`, `src/cli.py`,
`tests/test_osv_client.py`, `tests/test_scoring.py`, **plus the UI**.

### `src/osv_client.py`
- [x] `OsvClient.query(package)` — POST + cache + parse into `Vulnerability` list
- [x] `OsvClient.version_in_range(version, ranges)` — semver event-walking
- [x] `OsvClient.annotate_graph(graph)` — attach `osv_ids` onto every Node

### `src/scoring.py`
- [x] `Scorer._osv_signal` — severity → 0..1
- [x] `Scorer._downloads_signal` — anomaly under popular parent
- [x] `Scorer._ownership_signal` — recent publish bucketing
- [x] `Scorer._typosquat_signal` — hand-rolled Levenshtein
- [x] `Scorer._in_degree_signal` — normalized in-degree
- [x] `Scorer.score_graph` — combine all 5 signals into one `Score` per node

### `src/analyzer.py`
- [x] `analyze(seed, max_depth, include_dev, output)` — full pipeline + JSON report

### `src/cli.py`
- [x] `main()` — argparse + pretty stdout for the `flagged` section

### Tests
- [x] `tests/test_osv_client.py` — 9 cases pass
- [x] `tests/test_scoring.py` — 13 cases pass

### UI (Yaxita)
- [ ] Build the graphical / web UI on top of `analyzer.analyze()`.
      The pipeline returns a JSON-serializable dict with keys
      `seed`, `stats`, `cycles`, `top_in_degree`, `flagged` — wire that
      into whichever frontend stack you pick.

---

## Shared sync points

- [x] Lock the `Node` dataclass in `graph.py` (the contract the scorer reads).
- [x] Commit cached JSON fixtures under `tests/fixtures/registry/`,
      `tests/fixtures/downloads/`, `tests/fixtures/osv/`.
- [ ] Run `pytest -q` before every push (currently 37 / 37 passing).
- [ ] Final integration run on `express`, `react`, `lodash` seeds; capture
      output under `reports/` for the write-up.

---

## Workflow

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                                  # 37 / 37 pass
python -m src.cli express --max-depth 4    # end-to-end CLI run
```
