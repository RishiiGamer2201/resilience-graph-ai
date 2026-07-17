"""
Live analysis engine — run the WHOLE spine on an arbitrary event log at request
time. This is what makes the SOC Command Center actually work rather than replay
one pre-baked incident: feed it events (a CSV/rows in the common schema) and it
scores every event with the real IsolationForest, correlates them into one
incident, builds the attack-path graph, gates SOAR, attributes an actor, and
predicts the next technique — all computed live.

    from src.shared.live_analyze import analyze_events
    bundle = analyze_events(df, critical_assets={"C2388"}, incident_id="INC-LIVE-001")

`bundle` has the same per-screen shapes the cached endpoints serve
(overview / incident / graph / threat_intel / report) plus a `meta` block, so the
frontend renders a live result through the exact same screens.
"""
from __future__ import annotations

import pickle
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.engine1.lanl_detect import FEATURES, engineer
from src.schema import coerce, validate
from src.shared.attack_graph import analyze, build_graph
from src.shared.correlate import correlate
from src.shared.soar import recommend
from src.shared.timeutil import fmt_ist
from src.shared import views

ROOT = Path(__file__).resolve().parents[2]
LANL_MODEL = ROOT / "models" / "iforest_lanl.joblib"
SCORE_REF = ROOT / "api" / "cache" / "score_ref.json"

MAX_ROWS = 50_000          # trust boundary: reject oversized uploads

_state: dict = {}


def _model():
    if "model" not in _state:
        import json
        _state["model"] = joblib.load(LANL_MODEL)
        _state["ref"] = json.loads(SCORE_REF.read_text())
    return _state["model"], _state["ref"]


def _score(df: pd.DataFrame) -> np.ndarray:
    """Score every row 0-100 with the real LANL IsolationForest, calibrated with
    the FIXED score_ref anchors (not batch min/max) so scores are comparable
    across uploads and consistent with the /score-event endpoint."""
    bundle, ref = _model()
    X = df[FEATURES].to_numpy("float32")
    raw = -bundle["model"].score_samples(bundle["scaler"].transform(X))
    lo, hi = ref["lo"], ref["hi"]
    return np.clip((raw - lo) / (hi - lo + 1e-9), 0, 1) * 100


def _prepare(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce to the common schema and ensure the columns engineer() reads exist."""
    if len(df) > MAX_ROWS:
        raise ValueError(f"too many events ({len(df)} > {MAX_ROWS}); upload a focused window")
    if df.empty:
        raise ValueError("no events provided")
    df = coerce(df)
    validate(df)
    for col, default in (("status", "success"), ("protocol", "")):
        if col not in df.columns:
            df[col] = default
    if not (df["user"].astype(str).str.len() > 0).any():
        raise ValueError(
            "events need a 'user' column (behavioral features are per-user). "
            "Accepted names: user, username, account, principal, src_user. "
            "Also need source_host/destination_host (aliases: src/dst, source/destination).")
    return df


def analyze_events(df: pd.DataFrame, critical_assets: set[str] | None = None,
                   incident_id: str = "INC-LIVE-001", account: str | None = None) -> dict:
    """Run score → correlate → graph → SOAR → attribute → report on `df` live.

    `account` scopes the analysis to one compromised account within a campaign log
    (the per-account incident). Features are engineered on the FULL log first, then
    filtered — a user's behavioural baseline (fan-out, host rarity) must be computed
    against everything that happened, not against the slice we're looking at.
    """
    critical_assets = set(critical_assets or set())
    df = _prepare(df)
    df = engineer(df)                       # 7 behavioral features, per-user chronological
    df["anomaly_score"] = _score(df).round().astype(int)
    if account:
        df = df[df["user"].astype(str) == account]
        if df.empty:
            raise ValueError(f"no events for account '{account}' in this log")

    incident = correlate(df, incident_id=incident_id)
    g = build_graph(incident, critical_assets=critical_assets)
    ga = analyze(g, critical_assets=critical_assets)
    soar = recommend(incident, ga)

    # victim = account with the most alerts (label-free); pivot = graph entry host
    alert_users = [s["user"] for s in incident["alerts"] if s["user"]]
    victim = max(set(alert_users), key=alert_users.count) if alert_users else (
        df["user"].dropna().iloc[0] if len(df) else "—")
    pivot = ga.get("entry_host") or "—"

    full = {
        "victim": victim, "pivot": pivot,
        "critical_assets": sorted(critical_assets),
        "incident": incident, "graph": ga, "soar": soar,
    }

    meta = {"source": "live", "n_events": int(len(df)),
            "analyzed_at": fmt_ist(),
            "account": account,
            "accounts_involved": len(incident.get("users_involved", [])),
            "critical_assets": sorted(critical_assets)}

    return {
        "overview": views.overview(full, views.SCORECARD),
        "incident": views.incident_view(full),
        "graph": views.graph_view(full),
        "threat_intel": views.threat_intel_view(full),
        "report": views.report_view(full),
        "attackers": views.attackers_view(full),
        "meta": meta,
    }


def analyze_csv(path: str | Path, **kw) -> dict:
    return analyze_events(pd.read_csv(path), **kw)


if __name__ == "__main__":
    # self-check on the shipped LANL scenario (if exported)
    import json
    scen = ROOT / "data" / "demo" / "scenarios" / "lanl_redteam_u66.csv"
    if scen.exists():
        b = analyze_events(pd.read_csv(scen), critical_assets={"C2388"})
        print(json.dumps({k: (v if k == "meta" else "...") for k, v in b.items()}, indent=2))
        print("incident:", b["incident"]["alert_count"], "alerts,",
              b["incident"]["event_count"], "events, pivot", b["incident"]["pivot"])
    else:
        print(f"scenario not found: {scen} — run scripts/export_demo_events.py first")
