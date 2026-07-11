"""Milestone 2 · E1.x — prepare the official UNSW-NB15 split.

This task never creates, downloads, augments, or reshuffles data. It cleans the
official training and testing CSVs independently and preserves their split for
the benign-only anomaly evaluation in ``eval_unsw``.

Run:
    python -m src.engine1.prep_unsw
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "data" / "raw" / "unsw_nb15"
OUT_DIR = ROOT / "data" / "processed" / "unsw_nb15"
TRAIN_CSV = RAW_DIR / "UNSW_NB15_training-set.csv"
TEST_CSV = RAW_DIR / "UNSW_NB15_testing-set.csv"
TRAIN_OUT = OUT_DIR / "train.parquet"
TEST_OUT = OUT_DIR / "test.parquet"
REPORT = ROOT / "reports" / "unsw_prep.md"

LABEL = "label"
ATTACK_CATEGORY = "attack_cat"
LEAKAGE_OR_ID_COLUMNS = {"id", ATTACK_CATEGORY}


def clean_split(path: Path) -> tuple[pd.DataFrame, dict]:
    """Clean one official split while retaining label/category for evaluation."""
    if not path.exists():
        raise FileNotFoundError(f"Missing official UNSW-NB15 file: {path}")
    raw = pd.read_csv(path, low_memory=False)
    raw.columns = [str(column).strip().lower() for column in raw.columns]
    if LABEL not in raw:
        raise ValueError(f"{path.name} has no '{LABEL}' column.")

    before = len(raw)
    raw = raw.replace([np.inf, -np.inf], np.nan).drop_duplicates().copy()
    removed_duplicates = before - len(raw)
    numeric = raw.select_dtypes(include=["number"]).columns
    raw[numeric] = raw[numeric].replace([np.inf, -np.inf], np.nan)
    for column in numeric:
        raw[column] = raw[column].fillna(raw[column].median())
    categorical = raw.columns.difference(numeric)
    for column in categorical:
        raw[column] = raw[column].astype("string").fillna("unknown").str.strip()
    raw[LABEL] = pd.to_numeric(raw[LABEL], errors="raise").astype("int8")
    if not set(raw[LABEL].unique()).issubset({0, 1}):
        raise ValueError(f"{path.name} label must be binary 0/1.")

    stats = {
        "source": path.name,
        "rows_raw": before,
        "rows_clean": len(raw),
        "duplicates_removed": removed_duplicates,
        "benign": int((raw[LABEL] == 0).sum()),
        "attack": int((raw[LABEL] == 1).sum()),
        "features_after_leakage_drop": len([c for c in raw.columns if c not in LEAKAGE_OR_ID_COLUMNS | {LABEL}]),
    }
    return raw, stats


def main() -> None:
    train, train_stats = clean_split(TRAIN_CSV)
    test, test_stats = clean_split(TEST_CSV)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    train.to_parquet(TRAIN_OUT, index=False)
    test.to_parquet(TEST_OUT, index=False)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join([
        "# UNSW-NB15 preparation",
        "",
        "The official training/testing split is preserved; no rows are shuffled, synthesized, or moved between splits.",
        "",
        "| Split | Raw rows | Clean rows | Duplicates removed | Benign | Attack | Model features |",
        "|---|---:|---:|---:|---:|---:|---:|",
        *[f"| {name} | {stats['rows_raw']:,} | {stats['rows_clean']:,} | {stats['duplicates_removed']:,} | {stats['benign']:,} | {stats['attack']:,} | {stats['features_after_leakage_drop']} |" for name, stats in (("Train", train_stats), ("Test", test_stats))],
        "",
        "`id` and `attack_cat` are excluded from model features. `label` and `attack_cat` remain in parquet solely for evaluation and reporting.",
    ]), encoding="utf-8")
    print(f"Prepared official UNSW splits -> {TRAIN_OUT.relative_to(ROOT)}, {TEST_OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
