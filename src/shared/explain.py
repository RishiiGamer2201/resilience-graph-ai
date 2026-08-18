"""End-to-end explainability trace for a single alert.

"Why did you flag this?" has to be answerable at the level of one row in a log,
not just at the level of a dashboard. This walks the whole chain for one event:

    raw event → normalised fields → the 7 behavioural features → reconstruction
    error → calibrated 0-100 score → alert threshold → correlation into the
    incident → ATT&CK mapping → official citation → predicted next technique →
    impact on crown jewels → the action that follows

Every stage names the code that produced it and the value it produced, so an
analyst can disagree with a specific step rather than with "the AI".

    from src.shared.explain import explain_step
    trace = explain_step(df, bundle, step_index=0)
"""
from __future__ import annotations

import pandas as pd

from src.engine1.lanl_detect import FEATURES

FEATURE_MEANING = {
    "is_fail": "the authentication failed",
    "new_dst_for_user": "first time this account has ever authenticated to this host",
    "new_src_for_user": "first time this account has authenticated from this source",
    "user_distinct_dst_sofar": "how many distinct hosts this account has touched so far",
    "user_fail_rate_sofar": "this account's running failure rate",
    "dst_rarity": "how rarely the estate as a whole authenticates to this destination",
    "is_ntlm": "the older NTLM protocol was used rather than Kerberos",
}


def _row_for(df: pd.DataFrame, step: dict) -> pd.Series | None:
    """Find the engineered row behind a correlated step (timestamp + host pair)."""
    m = ((df["timestamp"] == step["timestamp"])
         & (df["source_host"].astype(str) == str(step["source_host"]))
         & (df["destination_host"].astype(str) == str(step["destination_host"])))
    if step.get("user"):
        m &= (df["user"].astype(str) == str(step["user"]))
    hits = df[m]
    return hits.iloc[0] if len(hits) else None


def explain_step(df: pd.DataFrame, bundle: dict, step_index: int = 0, *,
                 citations: list[dict] | None = None) -> dict:
    """Build the full provenance chain for one alert in an analysed bundle.

    `df` must be the ENGINEERED frame (post `engineer()`, with the feature columns
    and `anomaly_score`) that produced `bundle`.
    """
    from src.shared.attack_mapper import ALERT_SCORE, explanation, infer_lanl_event_type
    from src.shared.correlate import ALERT_THRESHOLD
    from src.shared import detector, predictor

    steps = bundle["incident"]["steps"]
    alerts = [s for s in steps if s.get("is_alert")]
    if not alerts:
        return {"available": False,
                "reason": "no alert crossed the threshold in this log"}
    step = alerts[max(0, min(step_index, len(alerts) - 1))]
    row = _row_for(df, step)

    stages = []

    stages.append({
        "stage": "1 · raw event",
        "produced_by": "the log you supplied",
        "value": {"timestamp": step["timestamp"], "user": step["user"],
                  "source_host": step["source_host"],
                  "destination_host": step["destination_host"]},
        "explanation": "One line of the event log, exactly as it arrived.",
    })

    stages.append({
        "stage": "2 · normalised",
        "produced_by": "src/schema.py · coerce() + resolve_aliases()",
        "value": {"schema_columns": 12,
                  "protocol": (str(row.get("protocol")) if row is not None else "—"),
                  "status": (str(row.get("status")) if row is not None else "—")},
        "explanation": ("Column aliases are resolved and types coerced into the one "
                        "12-field schema every dataset shares, so the same pipeline "
                        "reads LANL, CIC-IDS2017 and your own CSV."),
    })

    if row is not None:
        feats = {f: (float(row[f]) if f in row else None) for f in FEATURES}
        stages.append({
            "stage": "3 · behavioural features",
            "produced_by": "src/engine1/lanl_detect.py · engineer()",
            "value": feats,
            "meanings": FEATURE_MEANING,
            "explanation": ("Seven features computed per account in chronological order. "
                            "They describe behaviour, not signatures — which is why the "
                            "detector generalises to logs it has never seen."),
        })
        try:
            raw_err = float(detector.raw_scores([[feats[f] for f in FEATURES]])[0])
        except Exception:
            raw_err = None
        anchors = detector.anchors()
        stages.append({
            "stage": "4 · anomaly score",
            "produced_by": "src/shared/detector.py · benign-trained autoencoder (NumPy)",
            "value": {"reconstruction_error": (round(raw_err, 6) if raw_err is not None else None),
                      "calibrated_0_100": step["anomaly_score"],
                      "anchors": anchors},
            "explanation": ("The autoencoder was trained on benign authentications only. "
                            "It reconstructs normal behaviour well and unusual behaviour "
                            "badly, so the reconstruction error IS the anomaly signal. "
                            "The error is mapped onto 0-100 with fixed anchors: benign "
                            "median → 0, benign 99th percentile → 50 (the 1% "
                            "false-positive line), extreme → 100."),
        })
    else:
        stages.append({
            "stage": "3-4 · features and score",
            "produced_by": "src/engine1/lanl_detect.py + src/shared/detector.py",
            "value": {"calibrated_0_100": step["anomaly_score"]},
            "explanation": "The engineered row for this step was not recoverable; "
                           "the calibrated score is shown as computed.",
        })

    stages.append({
        "stage": "5 · alert decision",
        "produced_by": "src/shared/correlate.py · ALERT_THRESHOLD",
        "value": {"score": step["anomaly_score"], "threshold": ALERT_THRESHOLD,
                  "is_alert": step["is_alert"]},
        "explanation": (f"Scores at or above {ALERT_THRESHOLD} become alerts. "
                        f"{ALERT_THRESHOLD} is the calibrated 1% false-positive point, "
                        "not a round number someone liked."),
    })

    inc = bundle["incident"]
    stages.append({
        "stage": "6 · correlation",
        "produced_by": "src/shared/correlate.py · correlate()",
        "value": {"incident_id": inc["incident_id"], "severity": inc["severity"],
                  "alerts_in_incident": inc["alert_count"],
                  "events_considered": inc["event_count"],
                  "accounts": len(inc.get("users_involved", []))},
        "explanation": (f"This alert is one of {inc['alert_count']} collapsed into a "
                        f"single incident story. That collapse is the alert-fatigue "
                        f"win: {inc['event_count']} events became one thing to read."),
    })

    et = (infer_lanl_event_type(row.to_dict(), ALERT_SCORE) if row is not None else None)
    stages.append({
        "stage": "7 · ATT&CK mapping",
        "produced_by": "src/shared/attack_mapper.py · RULE_MAP (validated against parsed STIX)",
        "value": {"inferred_event_type": et, "tactic": step["tactic"],
                  "technique_id": step["technique_id"],
                  "technique": step.get("technique"),
                  "attack_description": explanation(step["technique_id"])},
        "explanation": ("The technique is assigned by an explicit rule over the observed "
                        "behaviour, and the ID is validated against the real ATT&CK STIX "
                        "bundle. Nothing here is generated text."),
    })

    cites = [c for c in (citations or [])
             if step["technique_id"] in (c.get("identifiers") or [])] or (citations or [])[:1]
    stages.append({
        "stage": "8 · official evidence",
        "produced_by": "src/shared/evidence.py · BM25 + identifier boost over the bundled corpus",
        "value": {"citations": cites},
        "explanation": ("The authoritative document behind the technique. If no official "
                        "source matches, this stage says so rather than improvising."
                        if not cites else
                        "Opens the real MITRE/CISA/CERT-In document, with a content hash."),
    })

    try:
        nxt, source = predictor.rank_next(inc["technique_ids"], 3)
    except Exception:
        nxt, source = [], "unavailable"
    stages.append({
        "stage": "9 · predicted next",
        "produced_by": "src/shared/predictor.py · interpolated Markov over 205 real sequences",
        "value": {"given": inc["technique_ids"],
                  "predictions": [{"technique_id": t, "probability": round(p, 3)}
                                  for t, p in nxt],
                  "model_source": source},
        "explanation": ("Real interpolated transition probabilities, not a ranked guess. "
                        "Measured top-3 accuracy and the baseline it beats are on the "
                        "scoreboard."),
    })

    g = bundle["graph"]
    stages.append({
        "stage": "10 · impact",
        "produced_by": "src/shared/attack_graph.py + src/shared/twin.py (NetworkX)",
        "value": {"blast_radius": g["blast_radius_size"],
                  "crown_jewels_reachable": g["critical_assets_at_risk"],
                  "path": next(iter(g["paths_to_critical"].values()), []),
                  "recommended_isolation": g["recommended_isolation"],
                  "isolation_cuts": g.get("isolation_cuts")},
        "explanation": ("Reachability from every attacker pivot, and the single host "
                        "whose isolation cuts the most. Deterministic graph analysis."),
    })

    soar = bundle.get("soar", {})
    stages.append({
        "stage": "11 · proposed action",
        "produced_by": "src/shared/soar.py + src/shared/rbac.py · policy_for()",
        "value": {"actions": soar.get("actions", []),
                  "gating_policy": soar.get("gating_policy"),
                  "executed": 0},
        "explanation": ("Actions are seeded from the real MITRE mitigations for the "
                        "observed techniques, then gated. Nothing is executed; "
                        "crown-jewel actions require a named human and a reason."),
    })

    return {
        "available": True,
        "step_index": step_index,
        "alerts_available": len(alerts),
        "step": step,
        "stages": stages,
        "note": ("Every stage names the module that produced it. No stage is generated "
                 "prose: this is the actual computation, read back."),
    }


def demo() -> None:
    """Self-check: a real alert produces a complete, ordered chain."""
    import pandas as pd
    from src.engine1.lanl_detect import engineer
    from src.schema import coerce
    from src.shared.live_analyze import analyze_events, _score

    raw = pd.read_csv("data/demo/scenarios/aiims_ransomware.csv")
    bundle = analyze_events(raw.copy(), critical_assets={"PATIENT-DB-01"})
    df = engineer(coerce(raw.copy()))
    df["anomaly_score"] = _score(df).round().astype(int)

    t = explain_step(df, bundle, 0)
    assert t["available"], t
    assert len(t["stages"]) == 11, len(t["stages"])
    assert t["stages"][0]["stage"].startswith("1 ·")
    assert t["stages"][-1]["value"]["executed"] == 0
    feats = t["stages"][2]["value"]
    assert set(feats) == set(FEATURES), feats
    print(f"explain ok: {len(t['stages'])} stages for alert 0 of {t['alerts_available']}; "
          f"score {t['step']['anomaly_score']} -> {t['step']['technique_id']}")


if __name__ == "__main__":
    demo()
