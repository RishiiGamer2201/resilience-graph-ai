"""
Milestone 1 · Task 0.1 — CIC-IDS2017 preprocessing (Engine 1).

Reads the 8 labeled flow CSVs from data/raw/cicids2017/MachineLearningCSV.zip,
cleans them, and writes a single model-ready table to
data/processed/cicids2017/flows.parquet.

Handles the 3 known CICIDS-2017 pitfalls (see research/claude/final_pipeline.md):
  A. Extreme class imbalance  -> we DON'T resample here (Engine 1 is unsupervised,
     trained on benign-only). We just report the distribution so the imbalance is
     explicit. Never headline accuracy downstream — use PR-AUC / F1 / recall.
  B. NaN / Infinity           -> Flow Bytes/s & Flow Packets/s overflow in
     CICFlowMeter. Replace Inf->NaN, drop rows with NaN, log how many.
  C. Leakage / duplicates     -> drop identifier column `Destination Port`
     (model must not memorize ports); drop duplicate rows; keep a `day` column so
     downstream can split by day, not by random shuffle.

Run:
    ./.venv/Scripts/python.exe -m src.engine1.prep_cicids
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
RAW_ZIP = ROOT / "data" / "raw" / "cicids2017" / "MachineLearningCSV.zip"
OUT_DIR = ROOT / "data" / "processed" / "cicids2017"
OUT_PARQUET = OUT_DIR / "flows.parquet"
REPORT = ROOT / "reports" / "cicids_prep.md"

# Column dropped to prevent the model memorizing the port (leakage). IP columns
# are not present in the MachineLearningCSV variant.
LEAKAGE_COLS = ["Destination Port"]
# The two columns that overflow to Infinity in CICFlowMeter.
RATE_COLS = ["Flow Bytes/s", "Flow Packets/s"]
LABEL_COL = "Label"


def _day_from_name(name: str) -> str:
    """Extract a day tag from the CSV filename, e.g. 'Wednesday'."""
    base = name.split("/")[-1]
    for day in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday"):
        if base.lower().startswith(day.lower()):
            return day
    return base.replace(".pcap_ISCX.csv", "")


def load_and_clean() -> tuple[pd.DataFrame, dict]:
    stats: dict = {"files": [], "rows_raw": 0, "inf_cells": 0,
                   "rows_dropped_nan": 0, "rows_dropped_dup": 0}
    frames = []

    with zipfile.ZipFile(RAW_ZIP) as z:
        csvs = sorted(n for n in z.namelist() if n.lower().endswith(".csv"))
        for name in csvs:
            with z.open(name) as fh:
                df = pd.read_csv(io.TextIOWrapper(fh, encoding="utf-8", errors="replace"),
                                 low_memory=False)
            # B/whitespace: strip leading/trailing spaces from every column name
            df.columns = [c.strip() for c in df.columns]
            df["day"] = _day_from_name(name)
            stats["files"].append((_day_from_name(name), len(df)))
            stats["rows_raw"] += len(df)
            frames.append(df)

    df = pd.concat(frames, ignore_index=True)

    # --- Pitfall B: Inf -> NaN, then drop NaN rows (count them) ---
    feature_like = [c for c in df.columns if c not in (LABEL_COL, "day")]
    # coerce features to numeric where possible
    for c in feature_like:
        if df[c].dtype == object:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    inf_mask = np.isinf(df[feature_like].to_numpy(dtype="float64", na_value=np.nan))
    stats["inf_cells"] = int(inf_mask.sum())
    df[feature_like] = df[feature_like].replace([np.inf, -np.inf], np.nan)

    before = len(df)
    df = df.dropna(subset=feature_like)
    stats["rows_dropped_nan"] = before - len(df)

    # --- Pitfall C: drop leakage cols + duplicate rows ---
    df = df.drop(columns=[c for c in LEAKAGE_COLS if c in df.columns])
    before = len(df)
    df = df.drop_duplicates()
    stats["rows_dropped_dup"] = before - len(df)

    # --- Labels: keep raw attack label + binary (0 benign / 1 attack) ---
    df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()
    df = df.rename(columns={LABEL_COL: "attack_label"})
    df["label"] = (df["attack_label"].str.upper() != "BENIGN").astype("int64")

    df = df.reset_index(drop=True)
    stats["rows_final"] = len(df)
    stats["n_features"] = len([c for c in df.columns
                               if c not in ("attack_label", "label", "day")])
    return df, stats


def write_report(df: pd.DataFrame, stats: dict) -> None:
    benign = int((df["label"] == 0).sum())
    attack = int((df["label"] == 1).sum())
    benign_pct = 100 * benign / len(df)
    attack_dist = df["attack_label"].value_counts()

    lines = [
        "# CIC-IDS2017 preprocessing report", "",
        f"- Raw rows read: **{stats['rows_raw']:,}** across {len(stats['files'])} daily files",
        f"- Inf cells found (Pitfall B): **{stats['inf_cells']:,}** -> set to NaN",
        f"- Rows dropped (NaN): **{stats['rows_dropped_nan']:,}**",
        f"- Rows dropped (duplicates, Pitfall C): **{stats['rows_dropped_dup']:,}**",
        f"- Leakage cols dropped (Pitfall C): {LEAKAGE_COLS}",
        f"- **Final rows: {stats['rows_final']:,}** · features: {stats['n_features']}",
        "",
        "## Class balance (Pitfall A — imbalance is expected)",
        f"- BENIGN: **{benign:,} ({benign_pct:.1f}%)**  ·  ATTACK: **{attack:,} ({100-benign_pct:.1f}%)**",
        "- ⚠️ Do NOT report accuracy downstream. Use PR-AUC / F1 / recall.",
        "- Engine 1 trains on BENIGN-only (unsupervised) → imbalance does not bias training; SMOTE N/A.",
        "",
        "## Attack-type distribution",
    ]
    for name, cnt in attack_dist.items():
        lines.append(f"- {name}: {cnt:,}")
    lines += ["", "## Rows per day (use `day` col for train/test split, not random shuffle)"]
    for day, cnt in stats["files"]:
        lines.append(f"- {day}: {cnt:,}")
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    print(f"Reading {RAW_ZIP.name} ...")
    df, stats = load_and_clean()
    df.to_parquet(OUT_PARQUET, index=False)
    write_report(df, stats)

    benign_pct = 100 * (df["label"] == 0).mean()
    print("CIC-IDS2017 preprocessing complete.")
    print(f"  raw rows        : {stats['rows_raw']:,}")
    print(f"  inf cells       : {stats['inf_cells']:,} (Pitfall B)")
    print(f"  dropped (NaN)   : {stats['rows_dropped_nan']:,}")
    print(f"  dropped (dupes) : {stats['rows_dropped_dup']:,} (Pitfall C)")
    print(f"  final rows      : {stats['rows_final']:,} · features: {stats['n_features']}")
    print(f"  class balance   : {benign_pct:.1f}% benign / {100-benign_pct:.1f}% attack (Pitfall A)")
    print(f"  -> {OUT_PARQUET.relative_to(ROOT)}")
    print(f"  -> {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
