"""
Milestone 1 · Task 0.2 — LANL red-team window extract (Engine 1, the moat).

Streams the 7.2 GB gzip data/raw/lanl/auth.txt.gz WITHOUT fully decompressing it,
and writes a focused, labeled slice to
data/processed/lanl/auth_redteam_window.parquet.

Strategy (user-centric window):
  * Load redteam.txt.gz (749 ground-truth malicious auths).
  * Keep every auth event that involves a compromised user (as src or dst user) —
    their FULL behavior (benign + malicious) is exactly what a behavioral model
    needs. Plus a 1-in-N background sample of everyone else for a benign baseline.
  * Label an event malicious iff (time, src_user, src_comp, dst_comp) is in the
    red-team set. -> `label` column (1 malicious / 0 benign).
  * Early exit: auth.txt is time-sorted, so stop once we pass the last red-team
    event + 1 day. This skips ~days 30-58 (about half the file).

Output columns follow src/schema.py where possible, plus LANL-specific extras
(dst_user, auth_type, logon_type, auth_orientation) kept for feature engineering.

Run (takes several minutes — stream the whole thing):
    ./.venv/Scripts/python.exe -m src.engine1.prep_lanl
Quick test on first N lines:
    LANL_LIMIT=5000000 ./.venv/Scripts/python.exe -m src.engine1.prep_lanl
"""
from __future__ import annotations

import gzip
import os
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[2]
LANL = ROOT / "data" / "raw" / "lanl"
AUTH = LANL / "auth.txt.gz"
REDTEAM = LANL / "redteam.txt.gz"
OUT_DIR = ROOT / "data" / "processed" / "lanl"
OUT_PARQUET = OUT_DIR / "auth_redteam_window.parquet"
REPORT = ROOT / "reports" / "lanl_prep.md"

BACKGROUND_RATE = 400     # keep 1-in-N events that don't involve a compromised user
DAY = 86400
CHUNK = 500_000           # rows per parquet write
LIMIT = int(os.environ.get("LANL_LIMIT", "0"))  # 0 = full file

COLUMNS = [
    "timestamp", "user", "source_host", "destination_host", "event_type",
    "status", "protocol", "port", "bytes_out", "command", "asset_criticality",
    "label", "dst_user", "logon_type", "auth_orientation",
]


def load_redteam():
    rt_keys, rt_users, rt_comps, times = set(), set(), set(), []
    with gzip.open(REDTEAM, "rt") as f:
        for line in f:
            t, user, src, dst = line.strip().split(",")
            t = int(t)
            rt_keys.add((t, user, src, dst))
            rt_users.add(user)
            rt_comps.update((src, dst))
            times.append(t)
    return rt_keys, rt_users, rt_comps, min(times), max(times)


def _row(t, su, du, sc, dc, atype, ltype, orient, status, label):
    return (t, su, sc, dc, "auth", status.lower(), atype, pd.NA, 0, "",
            "medium", label, du, ltype, orient)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    rt_keys, rt_users, rt_comps, rt_min, rt_max = load_redteam()
    stop_after = rt_max + DAY
    print(f"red-team: {len(rt_keys)} events · {len(rt_users)} users · "
          f"{len(rt_comps)} computers · t=[{rt_min},{rt_max}]")

    writer = None
    buf = []
    n_read = n_kept = n_mal = n_user = n_bg = 0

    def flush():
        nonlocal writer, buf
        if not buf:
            return
        df = pd.DataFrame(buf, columns=COLUMNS)
        table = pa.Table.from_pandas(df, preserve_index=False)
        if writer is None:
            writer = pq.ParquetWriter(OUT_PARQUET, table.schema)
        writer.write_table(table)
        buf = []

    with gzip.open(AUTH, "rt") as f:
        for line in f:
            n_read += 1
            if LIMIT and n_read > LIMIT:
                break
            parts = line.rstrip("\n").split(",")
            if len(parts) != 9:
                continue
            t, su, du, sc, dc, atype, ltype, orient, status = parts
            t = int(t)
            if t > stop_after:            # time-sorted -> safe early exit
                break

            involves_user = su in rt_users or du in rt_users
            is_mal = (t, su, sc, dc) in rt_keys

            keep = False
            if is_mal or involves_user:
                keep = True
                n_user += 1
                if is_mal:
                    n_mal += 1
            elif (n_read % BACKGROUND_RATE) == 0:
                keep = True
                n_bg += 1

            if keep:
                buf.append(_row(t, su, du, sc, dc, atype, ltype, orient,
                                status, int(is_mal)))
                n_kept += 1
                if len(buf) >= CHUNK:
                    flush()
            if n_read % 20_000_000 == 0:
                print(f"  ...{n_read:,} read · {n_kept:,} kept · {n_mal} malicious · t={t}")

    flush()
    if writer is not None:
        writer.close()

    lines = [
        "# LANL red-team window extract", "",
        f"- Lines read from auth.txt: **{n_read:,}** (early-exit at t>{stop_after})",
        f"- Rows kept: **{n_kept:,}**",
        f"  - involving compromised users: {n_user:,}",
        f"  - malicious (red-team ground truth): **{n_mal:,}** / {len(rt_keys)} red-team events",
        f"  - background normal sample (1-in-{BACKGROUND_RATE}): {n_bg:,}",
        f"- Compromised users: {len(rt_users)} · red-team computers: {len(rt_comps)}",
        "",
        "Label: 1 = red-team auth (malicious), 0 = benign. Use for E1.3 lateral-",
        "movement detection (TPR @ fixed FPR vs this ground truth).",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print("LANL extract complete.")
    print(f"  read={n_read:,} kept={n_kept:,} malicious={n_mal}/{len(rt_keys)} "
          f"bg={n_bg:,}")
    print(f"  -> {OUT_PARQUET.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
