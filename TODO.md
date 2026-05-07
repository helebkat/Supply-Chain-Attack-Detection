# TODO

## Done

- **Helen — graph & crawler track**
  - `src/graph.py` — `DiGraph` with BFS, DFS, cycle detection (iterative DFS coloring), Kahn's topological sort
  - `src/crawler.py` — npm registry BFS crawler with on-disk JSON cache
  - `tests/test_graph.py` (9 cases) and `tests/test_crawler.py` (6 cases)
  - Committed registry + downloads fixtures under `tests/fixtures/`
  - Captured a JSON report from a real seed (`express`, `react`, or
      `lodash`) — e.g.
      `python -m src.cli express --max-depth 4 --output reports/express.json`
      — and commit it under `reports/` so the artifact ships with the repo

- **Yaxita — detection & UI track**
  - `src/osv_client.py` — `/v1/query` client with semver event-walking range matching
  - `src/scoring.py` — 5-signal suspicion heuristic (OSV / downloads / ownership / typosquat / in-degree) with hand-rolled Levenshtein
  - `src/analyzer.py` — end-to-end pipeline returning a JSON-serializable report
  - `src/cli.py` — `python -m src.cli <package>` entry point
  - `app.py` — Streamlit dashboard wrapping `analyzer.analyze()`
  - `tests/test_osv_client.py` (9 cases) and `tests/test_scoring.py` (13 cases)
  - Committed OSV fixture under `tests/fixtures/osv/`

- **Shared**
  - `Node` dataclass locked as the cross-module contract
  - **37 / 37 tests passing**, fully offline against committed fixtures

> The Streamlit UI in `app.py` is the primary live demonstration; the
> committed JSON capture above is just a static snapshot to back it up.

## Workflow reminder

```bash
pytest -q                                  # before every push
python -m src.cli express --max-depth 4    # CLI run
streamlit run app.py                       # UI run
```
