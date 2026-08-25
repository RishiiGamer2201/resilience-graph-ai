"""
Build the API's pre-computed JSON cache.

The Overview / Live Incident / Attack Graph / Threat Intel / Report payloads are
now produced by running the REAL live analysis engine on the shipped LANL demo
scenario — so the committed "sample" cache is literally a live analysis of a real
red-team event log, identical in pipeline to what /api/analyze does on an upload.
Metrics / Methodology / score_ref are static model-level artifacts.

Run:
    ./.venv/Scripts/python.exe -m scripts.build_cache
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd

from src.shared.live_analyze import analyze_events
from src.shared.osint import collect as collect_osint


def agent_pipeline(df, incident_id: str) -> dict:
    """Run the 10-agent lane over the same log the cache is built from.

    The cached sample is a real analysis, so it carries the agent lane exactly
    as a live analysis does. Without this the deployed landing page showed no
    agent panel until someone ran an analysis, which reads as a broken feature.
    """
    try:
        from api.main import _agent_pipeline_summary
        from src.agents.orchestrator import run_pipeline
        result = run_pipeline(df, scenario="lanl_campaign_all",
                              incident_id=incident_id, use_llm=False)
        summary = _agent_pipeline_summary(result)
        print(f"    10-agent lane: {summary.get('status')} · "
              f"{len(summary.get('agent_traces', []))} agents")
        return summary
    except Exception as e:                      # never block the cache build
        print(f"    10-agent lane skipped: {type(e).__name__}: {e}")
        return {"enabled": False, "status": "failed", "error": str(e),
                "agent_traces": []}

ROOT = Path(__file__).resolve().parents[1]
# Default view = the WHOLE red-team campaign (104 compromised accounts, 702 red-team
# events from 4 attacker pivots), not a single account's slice of it.
SCENARIO = ROOT / "data" / "demo" / "scenarios" / "lanl_campaign_all.csv"
LANL_MODEL = ROOT / "models" / "iforest_lanl.joblib"
CACHE = ROOT / "api" / "cache"

CRITICAL_JSON = ROOT / "data" / "demo" / "scenarios" / "critical_assets.json"


def demo_critical() -> set[str]:
    """The estate's crown jewels, derived in export_demo_events (hosts the most
    accounts depend on). Falls back to nothing rather than inventing an asset."""
    if CRITICAL_JSON.exists():
        return {a["host"] for a in json.loads(CRITICAL_JSON.read_text())["assets"]}
    return set()

FEATURES = ["is_fail", "new_dst_for_user", "new_src_for_user",
            "user_distinct_dst_sofar", "user_fail_rate_sofar", "dst_rarity", "is_ntlm"]


def _write(name: str, obj: dict) -> None:
    (CACHE / f"{name}.json").write_text(json.dumps(obj, indent=2), encoding="utf-8")
    print(f"  wrote api/cache/{name}.json")


def metrics() -> dict:
    # canonical numbers from reports/metrics.json (written by the eval scripts) —
    # no hand-copying, so the Metrics screen can't drift from the reports again.
    from src.shared.metrics_store import load as load_metrics
    return load_metrics()


def methodology() -> dict:
    import pickle
    lk = pickle.loads((ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl").read_bytes())
    n_tech = len(lk["technique_to_name"])
    n_groups = len(lk["group_to_techniques"])
    n_manual = n_verified = 0
    mf = ROOT / "data" / "manual" / "cert_in_sequences.json"
    if mf.exists():
        import json as _json
        ms = _json.loads(mf.read_text(encoding="utf-8"))
        n_manual = len(ms)
        n_verified = sum(1 for m in ms if m.get("verified"))
    return {
        "datasets": [
            {"name": "CIC-IDS2017", "rows": "2.3M flows", "feeds": "anomaly detection + metrics"},
            {"name": "LANL Cyber", "rows": "11.2M auth · 702 red-team", "feeds": "lateral movement (the moat)"},
            {"name": "MITRE ATT&CK", "rows": f"{n_tech} techniques · {n_groups} groups (Enterprise + ICS + Mobile)",
             "feeds": "mapping, sequences, attribution, Threat Radar"},
            {"name": "UNSW-NB15", "rows": "175k/82k split", "feeds": "second benchmark"},
            {"name": "CERT-In advisories", "rows": f"{n_verified}/{n_manual} verified India sequences",
             "feeds": "non-circular predictor test · India scenarios"},
        ],
        "honesty_notes": [
            "Engine 1 trains benign-only (unsupervised) — we never report accuracy, only PR-AUC / TPR@FPR.",
            "Naive volumetric rule is worse than random (stealthy attacks have low packet rate).",
            "LANL NTLM signal ablated: behavioral-only still ROC 0.906 — not a protocol crutch.",
            "Next-technique: interpolated Markov beats the LSTM and biLSTM at this data scale, so we ship it (honest > fancy).",
            "Anti-circularity: interpolated Markov beats the kill-chain-order baseline 5.4x → real transitions.",
            f"CERT-In manual sequences now analyst-verified ({n_verified}/{n_manual}); real report-ordered "
            "timelines score top-3 10% vs 37% on kill-chain-ordered auto sets — real orderings are harder.",
            "Mobile ATT&CK added so India's mobile-heavy threats (banking trojans) map to real technique IDs.",
            "LANL is authentication-only, so incidents honestly map to just pass-the-hash / brute-force / "
            "remote-services — we never invent techniques the data can't evidence.",
            "Crown jewels are a stated heuristic (hosts the most accounts depend on), not a dataset label; "
            "actor names are similar public ATT&CK profiles; attribution abstains until independently calibrated thresholds exist.",
            "Every screen renders live analysis output — the sample view is a real analysis of a shipped red-team log.",
        ],
    }


def score_ref() -> dict:
    """Calibration anchors so the shipped detector maps to 0-100.

    Two canonical feature vectors, not batch min/max, so a score means the same
    thing on every upload and matches /api/score-event exactly.
    """
    from src.shared import detector
    ref = detector.anchors()
    if ref is not None:
        # Piecewise-log anchors measured at training time (see detector.calibrate):
        # benign median -> 0, benign p99 -> 50 (the 1% FPR alert line), hi -> 100.
        out = {"p50": ref["p50"], "p99": ref["p99"], "hi": ref["hi"],
               "basis": "piecewise-log: benign p50->0, p99->50 (1% FPR), attack range->100"}
    else:
        benign = [0, 0, 0, 50, 0.001, 4.0, 0]  # seen host, low fail, common dst, not NTLM
        mal = [0, 1, 1, 20, 0.05, 10.0, 1]     # new host, NTLM, rare dst, some fails
        raw = detector.raw_scores([benign, mal])
        out = {"lo": float(raw[0]), "hi": float(raw[1]),
               "basis": "canonical benign/malicious feature vectors (linear fallback)"}
    out["features"] = FEATURES
    out["detector"] = "autoencoder" if detector.available() else "iforest"
    return out


def main() -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    print("Building API cache ...")
    # score_ref FIRST — the live engine reads it to calibrate scores.
    _write("score_ref", score_ref())

    print("  running live analysis on the full LANL campaign ...")
    events = pd.read_csv(SCENARIO)
    bundle = analyze_events(events, critical_assets=demo_critical(),
                            incident_id="INC-PS7-LANL-CAMPAIGN")
    # The cached sample carries the agent lane too, so the landing page shows it
    # without needing a live run first.
    agents = agent_pipeline(events, "INC-PS7-LANL-CAMPAIGN")
    bundle["overview"]["agent_pipeline"] = agents
    # The cached sample is a real analysis, so it carries the same analysis layer
    # every live path does — claims, the four-number assessment, the progression
    # forecast and the cross-check. Without this the landing page showed a
    # thinner product than a live run, for no reason a viewer could see.
    from src.shared.enrich import enrich_bundle
    bundle = enrich_bundle(bundle, df=events, scenario="lanl_campaign_all",
                           critical=sorted(demo_critical()),
                           agent_summary=agents)
    bundle["overview"]["analysis"] = bundle["analysis"]
    print(f"    analysis layer: {len(bundle['analysis']['claims'])} claims · "
          f"forecast {bundle['analysis']['progression_forecast'].get('headline_probability')}%")
    print(f"    {bundle['incident']['alert_count']} alerts · "
          f"{len(bundle['attackers'])} compromised accounts · "
          f"{bundle['graph']['n_nodes']} hosts")
    for name in ("overview", "incident", "graph", "threat_intel", "report", "attackers"):
        _write(name, bundle[name])
    _write("attackers_meta", {"scenario": "lanl_campaign_all"})

    _write("metrics", metrics())
    _write("methodology", methodology())

    # Threat Radar — fetch external CTI now so the deployed app has intel on day
    # one without needing network at request time (refresh endpoint updates it live).
    print("  fetching external threat intel (free CTI sources) ...")
    try:
        radar = collect_osint()
        ok = [s["source"] for s in radar["sources"] if s["ok"]]
        skipped = [s["source"] for s in radar["sources"] if not s["ok"]]
        print(f"    {len(radar['items'])} items from {len(ok)} sources"
              + (f" · skipped: {', '.join(skipped)}" if skipped else ""))
        _write("threat_radar", radar)
    except Exception as e:                       # offline build must still succeed
        print(f"    [threat radar skipped: {e}] — keeping existing cache")

    print("Cache build complete.")


if __name__ == "__main__":
    main()
