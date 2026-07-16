"""
Export tiny, committable demo event logs to data/demo/scenarios/ so the live
`/api/analyze` flow has 1-click sample inputs without shipping the 11 GB raw data.

The star scenario is the REAL LANL red-team session (busiest compromised user, from
their pivot host, within the attack window) — the same events run_spine analyses,
but exported PRE-scoring as raw schema rows so the API scores them live end-to-end.

Run (needs the local LANL parquet once; output is committed):
    ./.venv/Scripts/python.exe -m scripts.export_demo_events
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.engine1.lanl_detect import engineer

ROOT = Path(__file__).resolve().parents[1]
PARQUET = ROOT / "data" / "processed" / "lanl" / "auth_redteam_window.parquet"
OUT_DIR = ROOT / "data" / "demo" / "scenarios"

# Raw schema-ish columns to export (what the live engine re-engineers + scores).
EXPORT_COLS = ["timestamp", "user", "source_host", "destination_host",
               "event_type", "status", "protocol", "port", "bytes_out",
               "command", "asset_criticality", "label"]


def lanl_u66() -> pd.DataFrame:
    """The real red-team incident window: busiest compromised user's events from
    their pivot host, ±1h around the attack (mirrors run_spine.build_real_incident,
    minus scoring)."""
    df = engineer(pd.read_parquet(PARQUET))
    victim = df[df.label == 1]["user"].value_counts().index[0]
    mal = df[(df.user == victim) & (df.label == 1)]
    pivot = mal["source_host"].mode().iloc[0]
    t0, t1 = mal["timestamp"].min() - 3600, mal["timestamp"].max() + 3600
    sub = (df[(df.user == victim) & (df.source_host == pivot)
              & df.timestamp.between(t0, t1)]
           .sort_values("timestamp").reset_index(drop=True))
    keep = [c for c in EXPORT_COLS if c in sub.columns]
    return sub[keep]


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not PARQUET.exists():
        raise SystemExit(f"Missing {PARQUET} — this export needs the local LANL parquet "
                         "(run src.engine1.prep_lanl once). Output CSVs are committed.")
    df = lanl_u66()
    out = OUT_DIR / "lanl_redteam_u66.csv"
    df.to_csv(out, index=False)
    print(f"wrote {out.relative_to(ROOT)} — {len(df)} events "
          f"({int(df.get('label', pd.Series()).sum() or 0)} labelled red-team)")


if __name__ == "__main__":
    main()
