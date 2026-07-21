import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

SOURCE = Path(__file__).resolve().parents[1] / "reports" / "scaling_measurements.json"
OUTPUT = Path(__file__).resolve().parents[1] / "reports" / "scaling_chart_detailed.png"

rows = json.loads(SOURCE.read_text(encoding="utf-8"))
x = [r["events"] for r in rows]
y = [r["seconds"] for r in rows]
demo = next(r for r in rows if r["events"] == 2732)
cap = next(r for r in rows if r["events"] == 50000)

navy = "#10233F"
blue = "#2F6DEB"
cyan = "#B8DFF2"
soft = "#EAF5FB"
grid = "#D8E5EE"
gray = "#52657A"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 18,
    "axes.titlesize": 24,
    "axes.labelsize": 18,
    "xtick.labelsize": 18,
    "ytick.labelsize": 18,
})

fig = plt.figure(figsize=(20, 9), dpi=180, facecolor="white")
gs = fig.add_gridspec(2, 2, width_ratios=[1.62, 1], height_ratios=[1, 0.42],
                      left=0.055, right=0.975, top=0.81, bottom=0.045,
                      hspace=0.22, wspace=0.18)
ax = fig.add_subplot(gs[0, 0])
panel = fig.add_subplot(gs[:, 1])
table_ax = fig.add_subplot(gs[1, 0])

fig.suptitle("Measured end-to-end scalability", x=0.055, y=0.975,
             ha="left", color=navy, fontsize=32, fontweight="bold")
fig.text(0.055, 0.885,
         "Score → correlate → ATT&CK map → attack graph → SOAR → attribute → predict",
         color=gray, fontsize=19)

ax.set_facecolor("white")
ax.grid(axis="y", color=grid, linewidth=1.2)
ax.spines[["top", "right"]].set_visible(False)
ax.spines[["left", "bottom"]].set_color(grid)
ax.fill_between(x, y, color=blue, alpha=0.11, zorder=1)
ax.plot(x, y, color=blue, linewidth=4, marker="o", markersize=10,
        markerfacecolor=blue, markeredgecolor="white", markeredgewidth=2.5, zorder=3)
ax.set_xlim(0, 52500)
ax.set_ylim(0, max(y) * 1.14)
ax.set_xlabel("Events analyzed in one request", color=gray, labelpad=12)
ax.set_ylabel("End-to-end time", color=gray, labelpad=12)
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v):,}"))
ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:.1f}s"))
ax.tick_params(colors=gray, length=0, pad=7)

ax.annotate(f"REAL CAMPAIGN\n{demo['events']:,} events - {demo['seconds']:.3f}s",
            xy=(demo["events"], demo["seconds"]), xytext=(7200, 0.60),
            fontsize=18, color=navy, fontweight="bold", linespacing=1.25,
            bbox=dict(boxstyle="round,pad=0.5", fc=soft, ec=blue, lw=1.5),
            arrowprops=dict(arrowstyle="-", color=blue, lw=1.8))
ax.annotate(f"DOCUMENTED CAP\n{cap['events']:,} events - {cap['seconds']:.3f}s",
            xy=(cap["events"], cap["seconds"]), xytext=(30200, max(y) * 1.05),
            fontsize=18, color=navy, fontweight="bold", linespacing=1.25,
            bbox=dict(boxstyle="round,pad=0.5", fc=soft, ec=blue, lw=1.5),
            arrowprops=dict(arrowstyle="-", color=blue, lw=1.8))

table_ax.axis("off")
selected = [r for r in rows if r["events"] in (2732, 10000, 20000, 50000)]
cell_text = [[f'{r["events"]:,}', f'{r["seconds"]:.3f}s', f'{r["alerts"]:,}',
              f'{r["events"] / r["seconds"]:,.0f}/s'] for r in selected]
tbl = table_ax.table(cellText=cell_text,
                     colLabels=["EVENTS", "TIME", "ALERTS", "THROUGHPUT"],
                     cellLoc="center", colLoc="center", loc="center")
tbl.auto_set_font_size(False)
tbl.set_fontsize(18)
tbl.scale(1, 1.8)
for (row, col), cell in tbl.get_celld().items():
    cell.set_edgecolor("white")
    if row == 0:
        cell.set_facecolor(blue)
        cell.get_text().set_color("white")
        cell.get_text().set_fontweight("bold")
    else:
        cell.set_facecolor(soft if row % 2 else "white")
        cell.get_text().set_color(navy)

panel.axis("off")
panel.add_patch(plt.Rectangle((0, 0), 1, 1, transform=panel.transAxes,
                              facecolor=soft, edgecolor="none"))
panel.text(0.07, 0.93, "WHAT THE DATA SHOWS", transform=panel.transAxes,
           fontsize=22, fontweight="bold", color=navy, va="top")

items = [
    (f"{cap['seconds']:.3f}s", "50K-event full-pipeline latency"),
    (f'{cap["events"] / cap["seconds"]:,.0f}/s', "sustained event throughput at the cap"),
    (f'{cap["alerts"]:,}', "alerts produced from the 50K workload"),
    (f"{cap['seconds'] / cap['events'] * 1e6:.1f} ms", "processing time per 1,000 events at 50K"),
]
yy = 0.83
for value, label in items:
    panel.text(0.07, yy, value, transform=panel.transAxes,
               fontsize=29, fontweight="bold", color=blue, va="top")
    panel.text(0.07, yy - 0.055, label, transform=panel.transAxes,
               fontsize=18, color=gray, va="top", wrap=True)
    yy -= 0.145

panel.plot([0.07, 0.93], [0.30, 0.30], transform=panel.transAxes,
           color=cyan, linewidth=2)
panel.text(0.07, 0.27, "VERIFICATION NOTES", transform=panel.transAxes,
           fontsize=20, fontweight="bold", color=navy, va="top")
panel.text(0.07, 0.225,
           "• One laptop CPU; no GPU\n"
           "• Best of 3 runs after warm-up\n"
           "• 2,732 = shipped real campaign\n"
           "• Larger inputs = timestamp-offset replays\n"
           "• 50K = documented design cap",
           transform=panel.transAxes, fontsize=18, color=gray,
           va="top", linespacing=1.38)

fig.savefig(OUTPUT, dpi=180, facecolor="white")
print(OUTPUT)
