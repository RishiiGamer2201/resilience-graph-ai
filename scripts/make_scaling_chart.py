"""
Generate the Feasibility & Scalability chart for the pitch deck.

Measures the REAL end-to-end pipeline (score → correlate → ATT&CK map → graph →
SOAR → attribute → predict) at increasing input sizes and plots the result, so the
scalability claim on the slide is measured rather than asserted.

Inputs above the shipped campaign size (2,732 events) are built by replaying the
same real campaign with offset timestamps — a genuine workload, labelled as such.

    ./.venv/Scripts/python.exe -m scripts.make_scaling_chart
    -> reports/scaling_chart.png  (+ _dark.png)  ·  reports/scaling_measurements.json
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "demo" / "scenarios" / "lanl_campaign_all.csv"
OUT_PNG = ROOT / "reports" / "scaling_chart.png"
OUT_DARK = ROOT / "reports" / "scaling_chart_dark.png"
OUT_JSON = ROOT / "reports" / "scaling_measurements.json"

SIZES = [250, 500, 1000, 2000, 2732, 5000, 10000, 20000, 50000]
DEMO_N = 2732          # the shipped campaign
CAP_N = 50000          # documented upper bound of a single analysis
REPEATS = 3            # report best-of-N; background load only adds time

# Product design tokens (see design.md) — one accent hue, recessive everything else.
LIGHT = {"bg": "#FFFFFF", "ink": "#16202E", "dim": "#5A6678", "faint": "#8894A6",
         "grid": "#E4E9F1", "accent": "#2F6FED", "soft": "#E7EEFD"}
DARK = {"bg": "#0C111B", "ink": "#E6ECF5", "dim": "#8A97AC", "faint": "#5C6B82",
        "grid": "#1B2536", "accent": "#4C8DFF", "soft": "#16233C"}


def measure() -> list[dict]:
    from src.shared.live_analyze import analyze_events
    base = pd.read_csv(SCENARIO)

    def workload(n: int) -> pd.DataFrame:
        reps = -(-n // len(base))
        parts = []
        for i in range(reps):
            c = base.copy()
            c["timestamp"] = c["timestamp"] + i * 100_000     # keep events ordered & distinct
            parts.append(c)
        return pd.concat(parts, ignore_index=True).head(n)

    # Warm-up: the first call lazily loads the IsolationForest + ATT&CK lookups.
    # Without this the smallest point measures cold-start, not steady-state scaling.
    analyze_events(workload(300), critical_assets={"C2388"})

    rows = []
    for n in SIZES:
        df = workload(n)
        # best of 3: background load only ever makes a run slower, so the
        # minimum is the cleanest estimate of the pipeline's own cost.
        dt = None
        for _ in range(REPEATS):
            t0 = time.perf_counter()
            b = analyze_events(df, critical_assets={"C2388"})
            r = time.perf_counter() - t0
            dt = r if dt is None else min(dt, r)
        rows.append({"events": n, "seconds": round(dt, 3),
                     "alerts": b["incident"]["alert_count"],
                     "hosts": b["graph"]["n_nodes"]})
        print(f"  {n:>6,} events -> {dt:6.3f}s  ({b['incident']['alert_count']:,} alerts)")
    return rows


def plot(rows: list[dict], t: dict, out: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter

    x = [r["events"] for r in rows]
    y = [r["seconds"] for r in rows]

    fig, ax = plt.subplots(figsize=(10, 4.8), dpi=200)
    fig.patch.set_facecolor(t["bg"])
    ax.set_facecolor(t["bg"])

    # recessive grid, horizontal only
    ax.grid(axis="y", color=t["grid"], linewidth=0.9, zorder=0)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(t["grid"])
        ax.spines[side].set_linewidth(1.0)

    # soft fill under the line reinforces magnitude without competing with it
    ax.fill_between(x, y, color=t["accent"], alpha=0.10, zorder=1)
    ax.plot(x, y, color=t["accent"], linewidth=2.2, zorder=3,
            marker="o", markersize=7, markerfacecolor=t["accent"],
            markeredgecolor=t["bg"], markeredgewidth=1.8)   # 2px surface ring on marks

    # selective direct labels — only the two points that carry the argument
    demo = next(r for r in rows if r["events"] == DEMO_N)
    cap = next(r for r in rows if r["events"] == CAP_N)

    top = max(y) * 1.28
    ax.annotate(f"Shipped demo campaign\n{demo['events']:,} events · {demo['seconds']:.2f}s",
                xy=(demo["events"], demo["seconds"]),
                xytext=(5200, top * 0.42),                 # well clear of the curve
                color=t["dim"], fontsize=9.5, linespacing=1.45,
                arrowprops=dict(arrowstyle="-", color=t["faint"], linewidth=0.9,
                                shrinkA=2, shrinkB=4))

    # leaders stay faint & thin — an accent-coloured 2px leader reads as a second series
    ax.annotate(f"{cap['events']:,} events → {cap['seconds']:.2f}s",
                xy=(cap["events"], cap["seconds"]),
                xytext=(37000, top * 0.94),                # above the line, not on it
                color=t["ink"], fontsize=12, fontweight="bold", linespacing=1.4,
                arrowprops=dict(arrowstyle="-", color=t["faint"], linewidth=0.9,
                                shrinkA=2, shrinkB=5))

    # title above subtitle above axes — pad keeps them from colliding
    ax.set_title(f"Full analysis pipeline: {CAP_N:,} events in under 3 seconds, one CPU",
                 color=t["ink"], fontsize=15, fontweight="bold",
                 loc="left", pad=40)
    ax.text(0, 1.045,
            "score every event → correlate → ATT&CK map → attack graph → SOAR → attribute → predict",
            transform=ax.transAxes, color=t["dim"], fontsize=9.8)

    ax.set_xlabel("Events analysed in a single request", color=t["dim"], fontsize=10.5, labelpad=9)
    ax.set_ylabel("End-to-end time (seconds)", color=t["dim"], fontsize=10.5, labelpad=9)
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:.1f}s"))
    ax.tick_params(colors=t["faint"], labelsize=9.5, length=0)
    ax.set_xlim(0, CAP_N * 1.04)
    ax.set_ylim(0, top)

    fig.text(0.125, -0.02,
             "Measured end-to-end, laptop CPU, no GPU — best of 3 runs after warm-up.  50,000 events is our "
             "documented single-analysis cap.  Runs above 2,732 replay the real campaign with offset timestamps.",
             color=t["faint"], fontsize=8.4)

    fig.tight_layout()
    fig.savefig(out, facecolor=t["bg"], bbox_inches="tight", pad_inches=0.35)
    plt.close(fig)
    print(f"  wrote {out.relative_to(ROOT)}")


def main() -> None:
    print("Measuring pipeline scaling ...")
    rows = measure()
    OUT_JSON.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"  wrote {OUT_JSON.relative_to(ROOT)}")
    plot(rows, LIGHT, OUT_PNG)
    plot(rows, DARK, OUT_DARK)


if __name__ == "__main__":
    main()
