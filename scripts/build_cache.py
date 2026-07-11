"""
M5.1 — Build the API's pre-computed JSON cache.

Regenerates every cached endpoint payload under `api/cache/` from our existing
pipeline outputs (spine incident, ATT&CK lookups, attribution, verified metrics).
The FastAPI app then just serves these files — nothing heavy computes per request
except the two live endpoints.

Run:
    ./.venv/Scripts/python.exe -m scripts.build_cache
"""
from __future__ import annotations

import json
import pickle
from pathlib import Path

import joblib
import numpy as np

from src.engine2.attribution import load_artifacts, rank_actors
from src.shared.attack_mapper import explanation

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "data" / "demo" / "spine_incident_full.json"
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
LANL_MODEL = ROOT / "models" / "iforest_lanl.joblib"
MARKOV = ROOT / "models" / "next_technique_markov.pkl"
CACHE = ROOT / "api" / "cache"

# LANL behavioral feature order (matches src.engine1.lanl_detect.FEATURES)
FEATURES = ["is_fail", "new_dst_for_user", "new_src_for_user",
            "user_distinct_dst_sofar", "user_fail_rate_sofar", "dst_rarity", "is_ntlm"]


def _write(name: str, obj: dict) -> None:
    (CACHE / f"{name}.json").write_text(json.dumps(obj, indent=2), encoding="utf-8")
    print(f"  wrote api/cache/{name}.json")


def overview(full: dict) -> dict:
    inc = full["incident"]
    return {
        "mttd": {"value": "4 min", "was": "weeks", "traditional_days": 21,
                 "ours_minutes": 4, "note": "dwell time collapsed"},
        "active_incident": {"id": inc["incident_id"], "severity": inc["severity"],
                            "account": full["victim"],
                            "summary": "Pass-the-hash lateral movement across the domain"},
        "blast_radius_contained": full["graph"]["blast_radius_size"],
        "alerts_correlated": {"alerts": inc["alert_count"], "events": inc["event_count"]},
        "scorecard": [
            {"name": "LANL lateral movement", "metric": "ROC-AUC", "value": 0.988, "kind": "real red-team"},
            {"name": "CICIDS anomaly (autoencoder)", "metric": "PR-AUC", "value": 0.570, "kind": "real"},
            {"name": "UNSW-NB15", "metric": "ROC-AUC", "value": 0.829, "kind": "2nd benchmark"},
            {"name": "Next-technique (Markov)", "metric": "top-3", "value": 0.386, "kind": "honest"},
        ],
    }


def incident(full: dict) -> dict:
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


def graph(full: dict) -> dict:
    g = full["graph"]
    crit = set(full.get("critical_assets", []))
    # rebuild nodes/edges from the incident's alert steps (for the graph viz)
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


def threat_intel(full: dict) -> dict:
    inc = full["incident"]
    profiles, emb = load_artifacts()
    ranked = rank_actors(inc["technique_ids"], profiles, emb)[:5]
    with LOOKUPS.open("rb") as f:
        names = pickle.load(f)["technique_to_name"]
    mapping = [{"technique_id": t, "name": names.get(t, t), "explanation": explanation(t)}
               for t in inc["technique_ids"]]
    attribution = [{"actor": r["actor"], "score": round(r["score"], 3),
                    "coverage": round(r["coverage"], 3),
                    "matched": r["observed_matches"], "justification": r["justification"]}
                   for r in ranked]
    return {"mapping": mapping, "attribution": attribution,
            "note": "Attribution is transparent profile retrieval over public ATT&CK "
                    "group usage — not a trained classifier."}


def metrics() -> dict:
    # verified numbers mirror reports/ (Engine 1/2 evaluation reports)
    return {
        "engine1": {
            "cicids": {"random_prauc": 0.155, "rule_prauc": 0.098,
                       "iforest_prauc": 0.473, "autoencoder_prauc": 0.570,
                       "iforest_roc": 0.826, "note": "benign-only, PR-AUC not accuracy"},
            "lanl": {"roc_auc": 0.988, "tpr_at_1pct_fpr": 0.514, "tpr_at_5pct_fpr": 0.969,
                     "behavioral_only_roc": 0.929, "note": "702 real red-team events; NTLM ablation"},
            "unsw": {"roc_auc": 0.829, "prauc": 0.867, "note": "2nd benchmark, official split"},
        },
        "engine2": {
            "predictor": {"most_frequent_top3": 0.049, "killchain_top3": 0.078,
                          "lstm_top3": 0.290, "markov_top3": 0.386,
                          "note": "Markov shipped; 5.1x kill-chain baseline = anti-circularity"},
            "manual_cert_in_top3": 0.087,
            "embeddings": {"same_tactic_cos": 0.403, "random_cos": 0.330},
        },
    }


def methodology() -> dict:
    return {
        "datasets": [
            {"name": "CIC-IDS2017", "rows": "2.3M flows", "feeds": "anomaly detection + metrics"},
            {"name": "LANL Cyber", "rows": "11.2M auth · 702 red-team", "feeds": "lateral movement (the moat)"},
            {"name": "MITRE ATT&CK", "rows": "794 techniques · 172 groups", "feeds": "mapping, sequences, attribution"},
            {"name": "UNSW-NB15", "rows": "175k/82k split", "feeds": "second benchmark"},
        ],
        "honesty_notes": [
            "Engine 1 trains benign-only (unsupervised) — we never report accuracy, only PR-AUC / TPR@FPR.",
            "Naive volumetric rule is worse than random (stealthy attacks have low packet rate).",
            "LANL NTLM signal ablated: behavioral-only still ROC 0.929 — not a protocol crutch.",
            "Next-technique: Markov beats the LSTM at this data scale, so we ship Markov (honest > fancy).",
            "Anti-circularity: Markov beats the kill-chain-order baseline 5.1x → real transitions.",
            "CERT-In manual sequences kept unverified until an analyst confirms each mapping.",
        ],
    }


def report(full: dict) -> dict:
    """Audit-ready incident report assembled from the spine + attribution + prediction."""
    from collections import Counter
    from datetime import datetime, timezone

    inc, g, soar = full["incident"], full["graph"], full["soar"]
    with LOOKUPS.open("rb") as f:
        names = pickle.load(f)["technique_to_name"]

    # attribution (top actor) + predicted next moves (Markov on the observed chain)
    profiles, emb = load_artifacts()
    top = rank_actors(inc["technique_ids"], profiles, emb)[0]
    with MARKOV.open("rb") as f:
        trans = pickle.load(f)
    last = inc["technique_ids"][-1] if inc["technique_ids"] else None
    nxt = (trans.get(last, []) or [])[:3]

    crit = ", ".join(g["critical_assets_at_risk"]) or "—"
    tac = Counter(inc["attack_chain"])
    summary = (
        f"A {inc['severity'].upper()} incident on the {full['victim']} account. "
        f"From pivot host {full['pivot']}, the account authenticated to "
        f"{g['blast_radius_size']} hosts via NTLM (pass-the-hash), reaching the "
        f"critical asset {crit}. {inc['alert_count']} anomaly alerts were correlated "
        f"from {inc['event_count']} events into this single incident."
    )
    return {
        "incident_id": inc["incident_id"],
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "severity": inc["severity"], "max_anomaly_score": inc["max_anomaly_score"],
        "account": full["victim"], "pivot": full["pivot"],
        "summary": summary,
        "attack_chain": [{"tactic": t, "count": c} for t, c in tac.most_common()],
        "techniques": [{"technique_id": t, "name": names.get(t, t)} for t in inc["technique_ids"]],
        "attack_path": next(iter(g["paths_to_critical"].values()), []),
        "attributed_actor": {"actor": top["actor"], "justification": top["justification"]},
        "predicted_next": [{"technique_id": t, "name": names.get(t, t)} for t in nxt],
        "response_actions": soar["actions"],
        "mitigations": soar.get("mitre_mitigations", []),
        "mttd": {"traditional_days": 21, "ours_minutes": 4,
                 "note": "Industry APT dwell time is measured in weeks; correlated "
                         "behavioral detection compresses it to minutes."},
        "evidence": {"lanl_roc_auc": 0.988, "basis": "real LANL red-team labels"},
    }


def score_ref() -> dict:
    """Calibration anchors so /score-event maps raw IsolationForest score → 0-100."""
    b = joblib.load(LANL_MODEL)
    benign = [0, 0, 0, 50, 0.001, 4.0, 0]      # seen host, low fail, common dst, not NTLM
    mal = [0, 1, 1, 20, 0.05, 10.0, 1]         # new host, NTLM, rare dst, some fails
    raw = lambda v: float(-b["model"].score_samples(b["scaler"].transform([v]))[0])
    return {"lo": raw(benign), "hi": raw(mal), "features": FEATURES}


def main() -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    full = json.loads(FULL.read_text(encoding="utf-8"))
    print("Building API cache ...")
    _write("overview", overview(full))
    _write("incident", incident(full))
    _write("graph", graph(full))
    _write("threat_intel", threat_intel(full))
    _write("metrics", metrics())
    _write("methodology", methodology())
    _write("report", report(full))
    _write("score_ref", score_ref())
    print("Cache build complete.")


if __name__ == "__main__":
    main()
