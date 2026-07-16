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

import json
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


def lanl_campaign() -> pd.DataFrame:
    """The WHOLE red-team campaign: every compromised account's activity from the
    attacker's pivot hosts, across the full attack window.

    The LANL red team ran 702 authentications against 104 accounts from just FOUR
    source hosts (C17693 alone covers 670 events / 103 accounts) — scoping the demo
    to one account showed 17% of the campaign and hid that concentration.
    """
    df = engineer(pd.read_parquet(PARQUET))
    mal = df[df.label == 1]
    pivots = set(mal["source_host"].unique())
    users = set(mal["user"].unique())
    t0, t1 = mal["timestamp"].min() - 3600, mal["timestamp"].max() + 3600
    sub = (df[df.user.isin(users) & df.source_host.isin(pivots)
              & df.timestamp.between(t0, t1)]
           .sort_values("timestamp").reset_index(drop=True))
    keep = [c for c in EXPORT_COLS if c in sub.columns]
    return sub[keep]


def critical_assets(top_n: int = 20) -> dict:
    """Derive the estate's crown jewels from the data.

    ⚠️ LANL is anonymised and carries NO asset-criticality ground truth (every row
    is 'medium'). The previous demo hard-coded a single "crown jewel" that
    run_spine had picked as the MIDDLE ELEMENT of the reached-host list — an
    arbitrary choice dressed up as a finding.

    Instead we derive it from a real signal: the hosts the most distinct accounts
    authenticate to are the ones the estate depends on (domain controllers, auth
    and file servers). This is a stated heuristic, not a label from the dataset.
    """
    df = pd.read_parquet(PARQUET, columns=["destination_host", "user", "label"])
    depend = df.groupby("destination_host")["user"].nunique().sort_values(ascending=False)
    # LANL computers are named C####; drop non-host auth artifacts that appear as
    # "destinations" but aren't assets — TGT (Kerberos ticket), ANONYMOUS LOGON,
    # user principals (U####@...), etc. A crown jewel must be a real host.
    depend = depend[depend.index.to_series().str.match(r"^C\d+$")]
    top = depend.head(top_n)
    mal = df[df.label == 1]
    reached = set(mal["destination_host"].unique())
    assets = []
    for host, n_accounts in top.items():
        hits = mal[mal.destination_host == host]
        assets.append({
            "host": host,
            "accounts_dependent": int(n_accounts),
            "reached_by_redteam": host in reached,
            "redteam_accounts": int(hits["user"].nunique()),
            "redteam_events": int(len(hits)),
        })
    return {
        "basis": "hosts the most distinct accounts authenticate to (domain "
                 "controllers / auth / file servers)",
        "caveat": "LANL is anonymised and has no asset-criticality labels; this is a "
                  "derived heuristic, not ground truth from the dataset.",
        "assets": assets,
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not PARQUET.exists():
        raise SystemExit(f"Missing {PARQUET} — this export needs the local LANL parquet "
                         "(run src.engine1.prep_lanl once). Output CSVs are committed.")

    crit = critical_assets()
    (OUT_DIR / "critical_assets.json").write_text(json.dumps(crit, indent=2), encoding="utf-8")
    hit = [a["host"] for a in crit["assets"] if a["reached_by_redteam"]]
    print(f"wrote critical_assets.json — {len(crit['assets'])} crown jewels, "
          f"{len(hit)} reached by the red team: {', '.join(hit)}")
    for name, fn in (("lanl_campaign_all", lanl_campaign), ("lanl_redteam_u66", lanl_u66)):
        df = fn()
        out = OUT_DIR / f"{name}.csv"
        df.to_csv(out, index=False)
        n_mal = int(df["label"].sum()) if "label" in df.columns else 0
        print(f"wrote {out.relative_to(ROOT)} — {len(df):,} events · {n_mal} red-team · "
              f"{df['user'].nunique()} accounts · "
              f"{len(set(df.source_host) | set(df.destination_host))} hosts")


if __name__ == "__main__":
    main()
