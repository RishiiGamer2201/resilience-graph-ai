"""
Screen-payload transforms — turn a spine `full` incident dict into the JSON each
UI screen consumes. Shared by BOTH the offline cache builder (scripts/build_cache.py)
and the live analysis engine (src/shared/live_analyze.py) so cached and live results
are identical in shape and computed the same way (no hardcoded numbers).

A `full` dict is what run_spine / live_analyze produce:
    {victim, pivot, critical_assets, incident, graph, soar}
where incident carries per-event `steps` (each with anomaly_score, tactic,
technique_id, is_alert, timestamps).
"""
from __future__ import annotations

import pickle
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from src.engine2.attribution import load_artifacts, rank_actors
from src.shared.attack_mapper import explanation

ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
MARKOV = ROOT / "models" / "next_technique_markov.pkl"

# Industry dwell-time reference — a CITATION, not our measurement. Mandiant
# M-Trends 2024 reports a global median attacker dwell time of ~10 days; APT
# campaigns run longer. We compare our per-log detection latency against it.
DWELL_CITATION_DAYS = 10
DWELL_CITATION = "Mandiant M-Trends 2024 - global median dwell ~10 days"

# Model-level benchmark scorecard — mirrors reports/ (Engine 1/2 eval reports).
# Upload-independent (it describes the detectors, not the analysed log), so both
# the cached Overview and a live analysis show the same evidence.
SCORECARD = [
    {"name": "LANL lateral movement", "metric": "ROC-AUC", "value": 0.988, "kind": "real red-team"},
    {"name": "CICIDS anomaly (autoencoder)", "metric": "PR-AUC", "value": 0.570, "kind": "real"},
    {"name": "UNSW-NB15", "metric": "ROC-AUC", "value": 0.829, "kind": "2nd benchmark"},
    {"name": "Next-technique (Markov)", "metric": "top-3", "value": 0.386, "kind": "honest"},
]


def _names() -> dict:
    with LOOKUPS.open("rb") as f:
        return pickle.load(f)["technique_to_name"]


def _human_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds == 0:
        return "immediate"
    if seconds < 60:
        return "< 1 min"
    if seconds < 5400:
        return f"{round(seconds / 60)} min"
    if seconds < 172800:
        return f"{round(seconds / 3600)} h"
    return f"{round(seconds / 86400)} d"


def compute_mttd(full: dict) -> dict:
    """Detection latency measured from the incident's OWN timestamps — the time
    from the first event in the log to the first correlated alert. No hardcoding.
    Industry dwell time is attached as a labelled citation for the weeks→minutes
    comparison, not as our own claim."""
    steps = full["incident"].get("steps", [])
    if steps:
        t0 = min(s["timestamp"] for s in steps)
        alert_ts = [s["timestamp"] for s in steps if s.get("is_alert")]
        t_alert = min(alert_ts) if alert_ts else t0
        secs = max(0, int(t_alert - t0))
    else:
        secs = 0
    return {
        "ours_seconds": secs,
        "value": _human_duration(secs),
        "was": "weeks",
        "traditional_days": DWELL_CITATION_DAYS,
        "ours_minutes": round(secs / 60, 1),
        "citation": DWELL_CITATION,
        "note": "time to first correlated alert in this log (measured); "
                "industry dwell is a cited comparison, not our claim",
    }


def _summary(full: dict) -> str:
    inc = full["incident"]
    names = _names()
    top = Counter(inc["attack_chain"]).most_common(1)
    tactic = top[0][0] if top else "anomalous"
    tech = names.get(inc["technique_ids"][0], inc["technique_ids"][0]) if inc["technique_ids"] else "—"
    return (f"{tactic} centred on {tech}; {inc['alert_count']} anomaly alerts "
            f"correlated from {inc['event_count']} events into one incident.")


def overview(full: dict, scorecard: list[dict]) -> dict:
    inc = full["incident"]
    # real anomaly-score trend across the correlated alerts (drives the sparkline;
    # no invented arrays). Cap for display.
    trend = [s["anomaly_score"] for s in inc["steps"] if s.get("is_alert")]
    if len(trend) > 60:
        step = len(trend) / 60
        trend = [trend[int(i * step)] for i in range(60)]
    return {
        "mttd": compute_mttd(full),
        "active_incident": {"id": inc["incident_id"], "severity": inc["severity"],
                            "account": full["victim"],
                            "summary": _summary(full)},
        "blast_radius_contained": full["graph"]["blast_radius_size"],
        "alerts_correlated": {"alerts": inc["alert_count"], "events": inc["event_count"]},
        "score_trend": trend,
        "scorecard": scorecard,
    }


def incident_view(full: dict) -> dict:
    inc = full["incident"]
    alerts = [s for s in inc["steps"] if s["is_alert"]][:80]   # cap payload
    return {
        "incident_id": inc["incident_id"], "severity": inc["severity"],
        "max_anomaly_score": inc["max_anomaly_score"],
        "account": full["victim"], "pivot": full["pivot"],
        "alert_count": inc["alert_count"], "event_count": inc["event_count"],
        "attack_chain": inc["attack_chain"], "technique_ids": inc["technique_ids"],
        "steps": alerts,
    }


def graph_view(full: dict) -> dict:
    g = full["graph"]
    crit = set(full.get("critical_assets", []))
    node_ids, edges, seen = set(), [], set()
    for s in full["incident"]["steps"]:
        if not s["is_alert"]:
            continue
        src, dst = s["source_host"], s["destination_host"]
        if not src or not dst:
            continue
        node_ids.update((src, dst))
        if (src, dst) in seen:
            continue
        seen.add((src, dst))
        edges.append({"from": src, "to": dst, "technique": s["technique_id"],
                      "tactic": s["tactic"], "score": s["anomaly_score"]})
    nodes = [{"id": n, "critical": n in crit, "pivot": n == g["entry_host"]}
             for n in sorted(node_ids)]
    return {
        "entry_host": g["entry_host"],
        "critical_assets_at_risk": g["critical_assets_at_risk"],
        "paths_to_critical": g["paths_to_critical"],
        "choke_points": g["choke_points"],
        "blast_radius_size": g["blast_radius_size"],
        "recommended_isolation": g["recommended_isolation"],
        "n_nodes": g["n_nodes"], "n_edges": g["n_edges"],
        "nodes": nodes, "edges": edges,
    }


def threat_intel_view(full: dict) -> dict:
    inc = full["incident"]
    profiles, emb = load_artifacts()
    names = _names()
    ranked = rank_actors(inc["technique_ids"], profiles, emb)[:5] if inc["technique_ids"] else []
    mapping = [{"technique_id": t, "name": names.get(t, t), "explanation": explanation(t)}
               for t in inc["technique_ids"]]
    attribution = [{"actor": r["actor"], "score": round(r["score"], 3),
                    "coverage": round(r["coverage"], 3),
                    "matched": r["observed_matches"], "justification": r["justification"]}
                   for r in ranked]
    return {"mapping": mapping, "attribution": attribution,
            "note": "Attribution is transparent profile retrieval over public ATT&CK "
                    "group usage — not a trained classifier."}


def report_view(full: dict) -> dict:
    """Audit-ready incident report assembled from the spine + attribution + prediction."""
    inc, g, soar = full["incident"], full["graph"], full["soar"]
    names = _names()

    profiles, emb = load_artifacts()
    top = rank_actors(inc["technique_ids"], profiles, emb)[0] if inc["technique_ids"] else None
    with MARKOV.open("rb") as f:
        trans = pickle.load(f)
    last = inc["technique_ids"][-1] if inc["technique_ids"] else None
    nxt = (trans.get(last, []) or [])[:3]

    crit = ", ".join(g["critical_assets_at_risk"]) or "—"
    tac = Counter(inc["attack_chain"])
    br = g["blast_radius_size"]
    summary = (
        f"A {inc['severity'].upper()} incident on the {full['victim']} account. "
        f"From pivot host {full['pivot']}, the account authenticated to "
        f"{br} hosts, reaching the critical asset {crit}. "
        f"{inc['alert_count']} anomaly alerts were correlated from "
        f"{inc['event_count']} events into this single incident."
    )
    mttd = compute_mttd(full)
    return {
        "incident_id": inc["incident_id"],
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "severity": inc["severity"], "max_anomaly_score": inc["max_anomaly_score"],
        "account": full["victim"], "pivot": full["pivot"],
        "summary": summary,
        "attack_chain": [{"tactic": t, "count": c} for t, c in tac.most_common()],
        "techniques": [{"technique_id": t, "name": names.get(t, t)} for t in inc["technique_ids"]],
        "attack_path": next(iter(g["paths_to_critical"].values()), []),
        "attributed_actor": ({"actor": top["actor"], "justification": top["justification"]}
                             if top else {"actor": "—", "justification": "no techniques observed"}),
        "predicted_next": [{"technique_id": t, "name": names.get(t, t)} for t in nxt],
        "response_actions": soar["actions"],
        "mitigations": soar.get("mitre_mitigations", []),
        "mttd": {"traditional_days": mttd["traditional_days"], "ours_minutes": mttd["ours_minutes"],
                 "ours_seconds": mttd["ours_seconds"], "value": mttd["value"],
                 "citation": mttd["citation"], "note": mttd["note"]},
        "evidence": {"lanl_roc_auc": 0.988, "basis": "real LANL red-team labels"},
    }
