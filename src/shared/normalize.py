"""
Milestone 1 · Task 0.4 — Normalizers into the common event schema.

`schema.py` defines the 12-field contract. This module maps each dataset's
processed frame into that contract so the shared spine (correlation, ATT&CK
mapping, attack-path graph, demo) speaks one language.

    from src.shared.normalize import normalize
    events = normalize(df, source="lanl")     # -> canonical 12 columns

Notes on coverage:
  * LANL auth events map cleanly (user/host/time/status all present).
  * CIC-IDS2017 is flow data with no user/host identity — it feeds the Engine 1
    anomaly MODEL as a feature matrix, not the event view. We still expose a
    schema-shaped view (identity fields blank) so both datasets round-trip
    through the same columns; don't expect user/host to be populated for flows.

Run the round-trip self-test:
    ./.venv/Scripts/python.exe -m src.shared.normalize
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.schema import COLUMNS, coerce, validate, EventType

ROOT = Path(__file__).resolve().parents[2]


def normalize(df: pd.DataFrame, source: str) -> pd.DataFrame:
    """Map a processed dataset frame into the canonical 12-column event schema."""
    if source == "lanl":
        # already schema-aligned (+ extras); coerce drops extras & fixes dtypes
        return coerce(df)

    if source == "cicids":
        out = pd.DataFrame()
        out["event_type"] = [EventType.NETWORK_FLOW.value] * len(df)
        # carry a volume signal if the flow-bytes column exists
        for cand in ("Total Length of Fwd Packets", "Subflow Fwd Bytes"):
            if cand in df.columns:
                out["bytes_out"] = pd.to_numeric(df[cand], errors="coerce").fillna(0)
                break
        if "label" in df.columns:
            out["label"] = df["label"]
        return coerce(out)

    raise ValueError(f"unknown source: {source!r}")


def _selftest() -> None:
    # LANL round-trip on a sample
    lanl_path = ROOT / "data" / "processed" / "lanl" / "auth_redteam_window.parquet"
    cic_path = ROOT / "data" / "processed" / "cicids2017" / "flows.parquet"

    for name, path, src in [("lanl", lanl_path, "lanl"), ("cicids", cic_path, "cicids")]:
        if not path.exists():
            print(f"  [skip] {name}: {path.name} not found")
            continue
        df = pd.read_parquet(path, columns=None).head(50_000)
        ev = normalize(df, source=src)
        validate(ev)
        assert list(ev.columns) == COLUMNS, f"{name}: columns != canonical"
        print(f"  [ok] {name}: {len(ev):,} rows -> {len(ev.columns)} canonical cols, "
              f"validate() passed")

    print("Round-trip self-test complete: both datasets share identical schema columns.")


if __name__ == "__main__":
    _selftest()
