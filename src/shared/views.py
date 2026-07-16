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
from pathlib import Path

from src.engine2.attribution import load_artifacts, rank_actors
from src.shared.attack_mapper import explanation
from src.shared.timeutil import fmt_ist

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


def attackers_view(full: dict) -> list[dict]:
    """Per-account breakdown of the incident/campaign.

    A campaign log covers many compromised accounts; this is the "who" table —
    each account's own footprint, computed from its alerts only.
    """
    by_user: dict[str, dict] = {}
    for s in full["incident"]["steps"]:
        if not s.get("is_alert"):
            continue
        u = s.get("user") or "—"
        a = by_user.setdefault(u, {
            "user": u, "alerts": 0, "hosts": set(), "pivots": set(),
            "techniques": [], "max_score": 0,
            "first_seen": s["timestamp"], "last_seen": s["timestamp"],
        })
        a["alerts"] += 1
        if s.get("destination_host"):
            a["hosts"].add(s["destination_host"])
        if s.get("source_host"):
            a["pivots"].add(s["source_host"])
        tid = s.get("technique_id")
        if tid and tid != "-" and tid not in a["techniques"]:
            a["techniques"].append(tid)
        a["max_score"] = max(a["max_score"], s["anomaly_score"])
        a["first_seen"] = min(a["first_seen"], s["timestamp"])
        a["last_seen"] = max(a["last_seen"], s["timestamp"])

    crit = set(full.get("critical_assets", []))
    out = []
    for a in by_user.values():
        out.append({**a,
                    "hosts_reached": len(a["hosts"]),
                    "critical_reached": sorted(a["hosts"] & crit),
                    "pivots": sorted(a["pivots"]),
                    "hosts": sorted(a["hosts"])[:50],
                    "severity": ("critical" if a["max_score"] >= 90 else "high" if a["max_score"] >= 70
                                 else "medium" if a["max_score"] >= 45 else "low")})
    out.sort(key=lambda a: (-a["alerts"], -a["max_score"]))
    return out


def _is_campaign(full: dict) -> bool:
    return len(full["incident"].get("users_involved", [])) > 1


def _account_label(full: dict) -> str:
    """Never label a multi-account campaign with a single victim's name."""
    users = full["incident"].get("users_involved", [])
    if len(users) > 1:
        return f"{len(users)} accounts"
    return full.get("victim") or (users[0] if users else "—")


def _summary(full: dict) -> str:
    inc = full["incident"]
    names = _names()
    top = Counter(inc["attack_chain"]).most_common(1)
    tactic = top[0][0] if top else "anomalous"
    tech = names.get(inc["technique_ids"][0], inc["technique_ids"][0]) if inc["technique_ids"] else "—"
    if _is_campaign(full):
        n_users = len(inc["users_involved"])
        pivots = {s["source_host"] for s in inc["steps"] if s.get("is_alert") and s.get("source_host")}
        return (f"Campaign across {n_users} compromised accounts from {len(pivots)} attacker "
                f"host(s); {tactic} centred on {tech}. {inc['alert_count']} alerts correlated "
                f"from {inc['event_count']} events.")
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
                            "account": _account_label(full),
                            "summary": _summary(full)},
        "blast_radius_contained": full["graph"]["blast_radius_size"],
        "alerts_correlated": {"alerts": inc["alert_count"], "events": inc["event_count"]},
        "score_trend": trend,
        "accounts_involved": len(inc.get("users_involved", [])),
        "is_campaign": _is_campaign(full),
        "scorecard": scorecard,
    }


def incident_view(full: dict) -> dict:
    inc = full["incident"]
    alerts = [s for s in inc["steps"] if s["is_alert"]][:80]   # cap payload
    return {
        "incident_id": inc["incident_id"], "severity": inc["severity"],
        "max_anomaly_score": inc["max_anomaly_score"],
        "account": _account_label(full), "pivot": full["pivot"],
        "alert_count": inc["alert_count"], "event_count": inc["event_count"],
        "attack_chain": inc["attack_chain"], "technique_ids": inc["technique_ids"],
        "is_campaign": _is_campaign(full),
        "accounts_involved": inc.get("users_involved", []),
        "steps": alerts,
        "steps_shown": len(alerts), "steps_total": inc["alert_count"],
    }


def graph_view(full: dict) -> dict:
    g = full["graph"]
    crit = set(full.get("critical_assets", []))
    names = _names()

    # One edge per (src,dst) host pair, carrying the underlying event(s) so the UI
    # can drill from a drawn edge back to the authentications that produced it.
    node_ids: set = set()
    by_pair: dict[tuple, dict] = {}
    for s in full["incident"]["steps"]:
        if not s["is_alert"]:
            continue
        src, dst = s["source_host"], s["destination_host"]
        if not src or not dst:
            continue
        node_ids.update((src, dst))
        e = by_pair.get((src, dst))
        if e is None:
            by_pair[(src, dst)] = {
                "from": src, "to": dst,
                "technique": s["technique_id"],
                "technique_name": names.get(s["technique_id"], ""),
                "tactic": s["tactic"],
                "score": s["anomaly_score"],          # max across the pair's events
                "explanation": s.get("explanation", ""),
                # a campaign sends MANY accounts down the same host pair — keep them
                # all, otherwise filtering the graph by account silently loses edges
                "users": [s["user"]] if s.get("user") else [],
                "first_seen": s["timestamp"], "last_seen": s["timestamp"],
                "event_count": 1,
            }
        else:
            e["event_count"] += 1
            e["score"] = max(e["score"], s["anomaly_score"])
            e["first_seen"] = min(e["first_seen"], s["timestamp"])
            e["last_seen"] = max(e["last_seen"], s["timestamp"])
            if s.get("user") and s["user"] not in e["users"]:
                e["users"].append(s["user"])
    edges = list(by_pair.values())
    for e in edges:
        e["user"] = e["users"][0] if len(e["users"]) == 1 else f"{len(e['users'])} accounts"
    # every attacker-controlled source is a pivot, not just the busiest one
    pivots = set(g.get("attacker_pivots") or [g.get("entry_host")])
    nodes = [{"id": n, "critical": n in crit, "pivot": n in pivots,
              "entry": n == g["entry_host"]}
             for n in sorted(node_ids)]
    return {
        "entry_host": g["entry_host"],
        "attacker_pivots": g.get("attacker_pivots", []),
        "n_pivots": g.get("n_pivots", 1),
        "critical_assets_at_risk": g["critical_assets_at_risk"],
        "paths_to_critical": g["paths_to_critical"],
        "choke_points": g["choke_points"],
        "blast_radius_size": g["blast_radius_size"],
        "recommended_isolation": g["recommended_isolation"],
        "isolation_cuts": g.get("isolation_cuts", g["blast_radius_size"]),
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
    if _is_campaign(full):
        n_users = len(inc["users_involved"])
        summary = (
            f"A {inc['severity'].upper()} campaign spanning {n_users} compromised accounts. "
            f"From pivot host {full['pivot']}, the attacker authenticated to "
            f"{br} hosts, reaching the critical asset {crit}. "
            f"{inc['alert_count']} anomaly alerts were correlated from "
            f"{inc['event_count']} events into this single campaign."
        )
    else:
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
        "generated_at": fmt_ist(),
        "severity": inc["severity"], "max_anomaly_score": inc["max_anomaly_score"],
        "account": _account_label(full), "pivot": full["pivot"],
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
