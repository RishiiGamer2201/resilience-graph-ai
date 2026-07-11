"""
Milestone 4 · Shared-spine driver — runs S2→S3→S4→S5 on a REAL LANL incident.

Takes the busiest red-team user's authentications from the LANL window, scores
them with the trained E1.3 detector, correlates into one incident, maps to
ATT&CK, builds the attack-path graph, and recommends gated SOAR actions —
writing an evidence-backed incident report.

    ./.venv/Scripts/python.exe -m src.shared.run_spine
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.engine1.lanl_detect import FEATURES, engineer
from src.shared.attack_graph import analyze, build_graph
from src.shared.correlate import correlate
from src.shared.soar import recommend

ROOT = Path(__file__).resolve().parents[2]
PARQUET = ROOT / "data" / "processed" / "lanl" / "auth_redteam_window.parquet"
MODEL = ROOT / "models" / "iforest_lanl.joblib"
REPORT = ROOT / "reports" / "spine_incident.md"
OUT_JSON = ROOT / "data" / "demo" / "spine_incident.json"
FULL_JSON = ROOT / "data" / "demo" / "spine_incident_full.json"   # incl. per-event steps


def build_real_incident() -> pd.DataFrame:
    """Score the busiest red-team user's session with the trained detector."""
    df = engineer(pd.read_parquet(PARQUET))
    victim = df[df.label == 1]["user"].value_counts().index[0]
    # scope to the ATTACK SESSION: the victim's events within the red-team time
    # window (+/- 1h context) — not their entire lifetime history.
    mal = df[(df.user == victim) & (df.label == 1)]
    pivot = mal["source_host"].mode().iloc[0]        # attacker's pivot host
    t0, t1 = mal["timestamp"].min() - 3600, mal["timestamp"].max() + 3600
    # incident = the victim's activity FROM the pivot host during the attack window
    sub = df[(df.user == victim) & (df.source_host == pivot)
             & df.timestamp.between(t0, t1)].sort_values(
        "timestamp").reset_index(drop=True)

    bundle = joblib.load(MODEL)
    X = bundle["scaler"].transform(sub[FEATURES].to_numpy("float32"))
    raw = -bundle["model"].score_samples(X)
    # scale anomaly score to 0-100 for readability
    lo, hi = raw.min(), raw.max()
    sub["anomaly_score"] = (100 * (raw - lo) / (hi - lo + 1e-9)).round().astype(int)
    return sub, victim, pivot


def main() -> None:
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    sub, victim, pivot = build_real_incident()

    # mark a plausible crown-jewel among the hosts the attacker reached
    reached = sub[sub.label == 1]["destination_host"].tolist()
    critical = {reached[len(reached) // 2]} if reached else set()

    incident = correlate(sub, incident_id="INC-PS7-LANL-001")
    g = build_graph(incident, critical_assets=critical)
    ga = analyze(g, critical_assets=critical)
    soar = recommend(incident, ga)

    OUT_JSON.write_text(json.dumps(
        {"incident": {k: v for k, v in incident.items() if k not in ("steps", "alerts")},
         "graph": ga, "soar": soar}, indent=2), encoding="utf-8")

    # full version (with per-event steps) for the Live Incident screen
    FULL_JSON.write_text(json.dumps(
        {"victim": victim, "pivot": pivot, "critical_assets": sorted(critical),
         "incident": incident, "graph": ga, "soar": soar}, indent=2), encoding="utf-8")

    # summarize the chain as unique tactics with counts (the full alternating
    # list is long; the incident object keeps it in full)
    from collections import Counter
    tac_counts = Counter(incident["attack_chain"])
    tchain = " · ".join(f"{t} (×{c})" for t, c in tac_counts.most_common()) or "(no alerts)"
    lines = [
        "# Shared-Spine Incident Report (real LANL red-team data)",
        "",
        f"**Incident:** {incident['incident_id']} · **Severity:** {incident['severity'].upper()} "
        f"(max anomaly {incident['max_anomaly_score']}/100)",
        f"**Compromised account:** {victim} · **alerts:** {incident['alert_count']} "
        f"correlated from {incident['event_count']} events (alert-fatigue reduction).",
        "",
        "## S2 — Correlated attack chain (ATT&CK tactics)",
        f"`{tchain}`",
        f"- Techniques: {', '.join(incident['technique_ids']) or '—'}",
        "",
        "## S4 — Attack-path graph",
        f"- Graph: **{ga['n_nodes']} hosts**, {ga['n_edges']} movement edges.",
        f"- Entry / pivot host: **{ga['entry_host']}** (fan-out to {ga['blast_radius_size']} hosts).",
        f"- Critical assets reachable: {ga['critical_assets_at_risk'] or '—'}.",
        f"- Choke points to isolate (betweenness): {ga['choke_points'] or '—'}.",
        f"- **Recommended isolation: {ga['recommended_isolation']}** "
        f"→ cuts a blast radius of {ga['blast_radius_size']} hosts.",
        "",
        "## S5 — Simulated SOAR response (confidence-gated)",
        f"- Policy: {soar['gating_policy']}",
        f"- ATT&CK mitigations: {', '.join(soar['mitre_mitigations']) or '—'}",
        "",
        "| Tactic | Action | Mode |",
        "|---|---|---|",
    ]
    for a in soar["actions"]:
        lines.append(f"| {a['tactic']} | {a['action']} | {a['mode']} |")
    lines += ["", "_All response actions are simulated. Built on real LANL red-team "
              "authentications; scores from the E1.3 IsolationForest detector._"]
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print(f"Spine ran on real incident for {victim}:")
    print(f"  {incident['alert_count']} alerts from {incident['event_count']} events · "
          f"severity {incident['severity']}")
    print(f"  graph {ga['n_nodes']} hosts, entry {ga['entry_host']}, "
          f"blast radius {ga['blast_radius_size']}")
    print(f"  {len(soar['actions'])} gated SOAR actions")
    print(f"  -> {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
