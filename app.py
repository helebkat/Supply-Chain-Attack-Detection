"""
Streamlit UI for the Supply Chain Attack Detection tool.

Wires into src/analyzer.analyze() and presents the returned report
as an interactive dashboard.

Run with:
    streamlit run app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Make sure the project root is on the path so `src` is importable
sys.path.insert(0, str(Path(__file__).parent))

from src.analyzer import analyze

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Supply Chain Attack Detector",
    page_icon="🔍",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #e63946;
        margin-bottom: 0;
    }
    .subtitle {
        font-size: 1rem;
        color: #6c757d;
        margin-top: 0;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background: #1e1e2e;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        text-align: center;
        border: 1px solid #2d2d3f;
    }
    .metric-label {
        font-size: 0.75rem;
        color: #9ca3af;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #f0f0f0;
        line-height: 1.2;
    }
    .metric-value.danger { color: #e63946; }
    .metric-value.warning { color: #f4a261; }
    .metric-value.safe { color: #2ec4b6; }
    .flagged-card {
        background: #2a1a1a;
        border: 1px solid #e63946;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        margin-bottom: 1rem;
    }
    .safe-card {
        background: #1a2a1a;
        border: 1px solid #2ec4b6;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.5rem;
    }
    .dep-path {
        font-family: monospace;
        font-size: 0.85rem;
        color: #a8dadc;
        background: #12121f;
        padding: 0.4rem 0.8rem;
        border-radius: 5px;
        margin-top: 0.5rem;
        word-break: break-all;
    }
    .reason-tag {
        display: inline-block;
        background: #3d1a1a;
        color: #f4a261;
        border: 1px solid #e63946;
        border-radius: 20px;
        font-size: 0.75rem;
        padding: 0.15rem 0.6rem;
        margin: 0.1rem 0.2rem;
    }
    .score-bar-bg {
        background: #2d2d3f;
        border-radius: 6px;
        height: 8px;
        margin-top: 4px;
    }
    .section-header {
        font-size: 1.2rem;
        font-weight: 600;
        color: #e0e0f0;
        border-bottom: 1px solid #2d2d3f;
        padding-bottom: 0.4rem;
        margin-bottom: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown('<p class="main-title">🔍 Supply Chain Attack Detector</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="subtitle">Crawl the npm dependency graph, detect vulnerabilities via OSV, '
    "and surface suspicious packages with exact dependency paths.</p>",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar — controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Settings")

    seed = st.text_input(
        "Npm package name",
        value="express",
        placeholder="e.g. express, react, lodash",
        help="The root package to start crawling from.",
    )

    max_depth = st.slider(
        "Max crawl depth",
        min_value=1,
        max_value=6,
        value=3,
        help="How many hops of transitive dependencies to follow.",
    )

    include_dev = st.toggle(
        "Include devDependencies",
        value=False,
        help="Also crawl devDependencies (makes the graph much larger).",
    )

    threshold = st.slider(
        "Suspicion threshold",
        min_value=0.0,
        max_value=1.0,
        value=0.30,
        step=0.05,
        help="Packages scoring above this are flagged.",
    )

    run = st.button("🚀 Run analysis", use_container_width=True, type="primary")

    st.divider()
    st.markdown("**Signal weights**")
    st.markdown(
        "- OSV vulnerability hit — `0.50`\n"
        "- Low download count — `0.15`\n"
        "- Recent ownership change — `0.15`\n"
        "- Typosquatting — `0.10`\n"
        "- High in-degree (blast radius) — `0.10`"
    )
    st.divider()
    st.caption("MSML606 Bonus Project 2 · University of Maryland")

# ---------------------------------------------------------------------------
# Main area
# ---------------------------------------------------------------------------
if not run:
    st.info("👈 Enter a package name in the sidebar and click **Run analysis** to start.")

    # Show a quick example of what the output looks like
    with st.expander("What does this tool do?"):
        st.markdown(
            """
This tool treats the npm registry as a **directed graph** and applies classical graph
algorithms to surface high-risk packages.

**How it works:**
1. Starting from your seed package, it performs a **BFS crawl** of the npm registry,
   building a full dependency graph up to the configured depth.
2. Every discovered package is checked against the **OSV vulnerability database**.
3. Each package gets a **suspicion score** from five weighted signals.
4. Flagged packages are reported with the exact **root → leaf dependency path** that
   introduced them into your project.

**Typical graph sizes:**
| Seed | Depth | Nodes | Edges |
|------|-------|-------|-------|
| express | 2 | ~53 | ~90 |
| express | 4 | ~300+ | ~600+ |
| react | 3 | ~200+ | ~400+ |
            """
        )
    st.stop()

# ---------------------------------------------------------------------------
# Run the analysis pipeline
# ---------------------------------------------------------------------------
with st.spinner(f"Crawling npm dependency graph for **{seed}** (depth={max_depth})…"):
    try:
        from src.scoring import DEFAULT_THRESHOLD
        from src.crawler import NpmCrawler
        from src.osv_client import OsvClient
        from src.scoring import Scorer
        from src.analyzer import POPULAR_NPM_PACKAGES

        crawler = NpmCrawler(max_depth=max_depth, include_dev=include_dev)
        osv_client = OsvClient()
        scorer = Scorer(popular_names=POPULAR_NPM_PACKAGES, threshold=threshold)

        report = analyze(
            seed,
            max_depth=max_depth,
            include_dev=include_dev,
            crawler=crawler,
            osv_client=osv_client,
            scorer=scorer,
        )
    except Exception as exc:
        st.error(f"Analysis failed: {exc}")
        st.stop()

stats = report["stats"]
flagged = report["flagged"]
cycles = report["cycles"]
top_in_degree = report["top_in_degree"]

# ---------------------------------------------------------------------------
# Summary metrics row
# ---------------------------------------------------------------------------
st.markdown('<p class="section-header">📊 Graph summary</p>', unsafe_allow_html=True)

c1, c2, c3, c4, c5 = st.columns(5)

def _metric_html(label: str, value, css_class: str = "") -> str:
    return (
        f'<div class="metric-card">'
        f'<div class="metric-label">{label}</div>'
        f'<div class="metric-value {css_class}">{value}</div>'
        f"</div>"
    )

flag_class = "danger" if flagged else "safe"
cycle_class = "warning" if cycles else "safe"

c1.markdown(_metric_html("Packages", stats["nodes"]), unsafe_allow_html=True)
c2.markdown(_metric_html("Edges", stats["edges"]), unsafe_allow_html=True)
c3.markdown(_metric_html("Max depth", stats["max_depth"]), unsafe_allow_html=True)
c4.markdown(_metric_html("Cycles", stats["cycle_count"], cycle_class), unsafe_allow_html=True)
c5.markdown(
    _metric_html("Flagged", len(flagged), flag_class),
    unsafe_allow_html=True,
)

st.divider()

# ---------------------------------------------------------------------------
# Flagged packages
# ---------------------------------------------------------------------------
st.markdown('<p class="section-header">🚨 Suspicious packages</p>', unsafe_allow_html=True)

if not flagged:
    st.markdown(
        '<div class="safe-card">✅ <strong>No suspicious packages detected.</strong> '
        "All dependencies are below the suspicion threshold.</div>",
        unsafe_allow_html=True,
    )
else:
    st.warning(
        f"**{len(flagged)} package(s)** flagged above threshold `{threshold}`.",
        icon="⚠️",
    )

    for pkg in flagged:
        score_pct = int(pkg["total"] * 100)
        score_color = "#e63946" if pkg["total"] >= 0.5 else "#f4a261"

        path_arrow = " → ".join(pkg["path"])
        reasons_html = "".join(
            f'<span class="reason-tag">{r}</span>' for r in pkg["reasons"]
        )

        osv_ids_str = ""
        if pkg["osv_ids"]:
            osv_ids_str = (
                "<br><strong>OSV IDs:</strong> "
                + ", ".join(
                    f'<a href="https://osv.dev/vulnerability/{oid}" target="_blank">{oid}</a>'
                    for oid in pkg["osv_ids"]
                )
            )

        dl_str = (
            f"{pkg['weekly_downloads']:,}/wk"
            if pkg["weekly_downloads"] is not None
            else "unknown"
        )

        signals = pkg["signals"]

        st.markdown(
            f"""
            <div class="flagged-card">
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <span style="font-size:1.1rem;font-weight:700;color:#e63946;">
                  📦 {pkg['name']}
                  <span style="font-size:0.85rem;color:#9ca3af;font-weight:400;">
                    v{pkg['version'] or '?'} · depth {pkg['depth']}
                  </span>
                </span>
                <span style="font-size:1.4rem;font-weight:700;color:{score_color};">
                  {score_pct}%
                </span>
              </div>

              <div style="margin:0.5rem 0 0.8rem 0;">
                {reasons_html}
              </div>

              <div style="font-size:0.82rem;color:#9ca3af;">
                <strong style="color:#e0e0f0;">Weekly downloads:</strong> {dl_str}
                {osv_ids_str}
              </div>

              <div class="dep-path">🔗 {path_arrow}</div>

              <details style="margin-top:0.8rem;">
                <summary style="cursor:pointer;font-size:0.85rem;color:#9ca3af;">
                  Signal breakdown
                </summary>
                <div style="margin-top:0.6rem;font-size:0.82rem;color:#d0d0e0;">
            """,
            unsafe_allow_html=True,
        )

        signal_labels = {
            "osv": ("OSV vulnerability", 0.50),
            "downloads": ("Low downloads", 0.15),
            "ownership": ("Recent ownership", 0.15),
            "typosquat": ("Typosquatting", 0.10),
            "in_degree": ("High in-degree", 0.10),
        }

        for key, (label, weight) in signal_labels.items():
            raw = signals[key]
            weighted = raw * weight
            bar_pct = int(raw * 100)
            st.markdown(
                f"""
                <div style="margin-bottom:0.4rem;">
                  <div style="display:flex;justify-content:space-between;">
                    <span>{label} (w={weight})</span>
                    <span>{weighted:.3f}</span>
                  </div>
                  <div class="score-bar-bg">
                    <div style="width:{bar_pct}%;height:8px;border-radius:6px;
                                background:{'#e63946' if raw > 0.5 else '#f4a261'};"></div>
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("</div></details></div>", unsafe_allow_html=True)

st.divider()

# ---------------------------------------------------------------------------
# Two-column section: blast radius + cycles
# ---------------------------------------------------------------------------
col_left, col_right = st.columns(2)

with col_left:
    st.markdown('<p class="section-header">💥 Highest blast radius</p>', unsafe_allow_html=True)
    st.caption("Packages with the most dependents (high in-degree = more impact if compromised).")

    if top_in_degree:
        max_deg = top_in_degree[0]["in_degree"] or 1
        for item in top_in_degree:
            pct = int(item["in_degree"] / max_deg * 100)
            st.markdown(
                f"""
                <div style="margin-bottom:0.5rem;font-size:0.88rem;color:#e0e0f0;">
                  <div style="display:flex;justify-content:space-between;">
                    <span>📦 {item['name']}</span>
                    <span style="color:#9ca3af;">{item['in_degree']} dependents</span>
                  </div>
                  <div class="score-bar-bg">
                    <div style="width:{pct}%;height:6px;border-radius:6px;background:#4a90d9;"></div>
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.info("No in-degree data available.")

with col_right:
    st.markdown('<p class="section-header">🔄 Cycle detection</p>', unsafe_allow_html=True)
    st.caption("Circular dependency chains — any cycle in npm is anomalous since publish-time cycles are forbidden.")

    if not cycles:
        st.markdown(
            '<div class="safe-card">✅ No cycles detected in the dependency graph.</div>',
            unsafe_allow_html=True,
        )
    else:
        st.warning(f"{len(cycles)} cycle(s) detected!", icon="⚠️")
        for i, cycle in enumerate(cycles, 1):
            cycle_str = " → ".join(cycle)
            st.markdown(
                f'<div class="dep-path">Cycle {i}: {cycle_str}</div>',
                unsafe_allow_html=True,
            )

st.divider()

# ---------------------------------------------------------------------------
# Raw JSON report (collapsible)
# ---------------------------------------------------------------------------
with st.expander("📄 Raw JSON report"):
    import json
    st.code(json.dumps(report, indent=2), language="json")
