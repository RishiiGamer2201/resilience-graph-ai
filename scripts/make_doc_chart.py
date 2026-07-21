"""
Black-only scaling chart for the submission document.

Reads the ALREADY-MEASURED numbers from reports/scaling_measurements.json rather
than re-running the pipeline, so the chart in the document is exactly the data
that was verified and committed.

    ./.venv/Scripts/python.exe -m scripts.make_doc_chart
    -> reports/doc/scaling_bw.png
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "reports" / "scaling_measurements.json"
OUT = ROOT / "reports" / "doc" / "scaling_bw.png"

DEMO_N, CAP_N = 2732, 50000


def main() -> None:
    rows = json.loads(SRC.read_text(encoding="utf-8"))

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter

    x = [r["events"] for r in rows]
    y = [r["seconds"] for r in rows]

    fig, ax = plt.subplots(figsize=(10, 4.6), dpi=200)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    ax.grid(axis="y", color="#000000", linewidth=0.5, alpha=0.25, zorder=0)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#000000")
        ax.spines[s].set_linewidth(1.0)

    ax.fill_between(x, y, color="#000000", alpha=0.06, zorder=1)
    ax.plot(x, y, color="#000000", linewidth=2.0, zorder=3, marker="o",
            markersize=6.5, markerfacecolor="#000000",
            markeredgecolor="#FFFFFF", markeredgewidth=1.6)

    demo = next(r for r in rows if r["events"] == DEMO_N)
    cap = next(r for r in rows if r["events"] == CAP_N)
    top = max(y) * 1.30

    ax.annotate(f"Shipped demo campaign\n{demo['events']:,} events, {demo['seconds']:.2f} s",
                xy=(demo["events"], demo["seconds"]), xytext=(5200, top * 0.42),
                color="#000000", fontsize=9.5, linespacing=1.45,
                arrowprops=dict(arrowstyle="-", color="#000000", linewidth=0.8,
                                shrinkA=2, shrinkB=4))
    ax.annotate(f"{cap['events']:,} events, {cap['seconds']:.2f} s",
                xy=(cap["events"], cap["seconds"]), xytext=(36000, top * 0.94),
                color="#000000", fontsize=11.5, fontweight="bold", linespacing=1.4,
                arrowprops=dict(arrowstyle="-", color="#000000", linewidth=0.8,
                                shrinkA=2, shrinkB=5))

    ax.set_title(f"Full analysis pipeline: {CAP_N:,} events in under 3 seconds on one CPU",
                 color="#000000", fontsize=13.5, fontweight="bold", loc="left", pad=34)
    ax.text(0, 1.045,
            "score every event, correlate, map to ATT&CK, build the graph, "
            "recommend response, attribute, predict",
            transform=ax.transAxes, color="#000000", fontsize=9.3)

    ax.set_xlabel("Events analysed in a single request", color="#000000", fontsize=10.5, labelpad=9)
    ax.set_ylabel("End to end time (seconds)", color="#000000", fontsize=10.5, labelpad=9)
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:.1f} s"))
    ax.tick_params(colors="#000000", labelsize=9.5, length=0)
    ax.set_xlim(0, CAP_N * 1.04)
    ax.set_ylim(0, top)

    fig.text(0.125, -0.02,
             "Measured end to end on a laptop CPU with no GPU, best of 3 runs after warm up. "
             "50,000 events is the documented single analysis cap. "
             "Runs above 2,732 replay the real campaign with offset timestamps.",
             color="#000000", fontsize=8.2)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(OUT, facecolor="white", bbox_inches="tight", pad_inches=0.3)
    plt.close(fig)
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
