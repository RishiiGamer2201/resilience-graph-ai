"""One enrichment, shared by every path that analyses a log.

There are four ways an analysis bundle gets produced in this repo -- the
investigation workflow, `POST /api/analyze`, `POST /api/analyze/upload`,
`GET /api/analyze/stream`, and the offline cache build -- and they had drifted
into attaching different things. The investigation had claims, the four-number
assessment, the progression forecast and the agent cross-check; the analyze path
had only the agent lane; the cache had neither. Same product, same log, different
answers depending on which button you pressed.

This module is the single place that turns a raw spine bundle into an enriched
one. Every entry point calls it, so every screen sees the same fields no matter
how the analysis was started.

    from src.shared.enrich import enrich_bundle
    bundle = enrich_bundle(bundle, df=events, scenario="aiims_ransomware",
                           critical=["PATIENT-DB-01"])
    bundle["analysis"]["assessment"]["summary"]

What it attaches, all under `bundle["analysis"]`:
    claims                ATT&CK claims with status, confidence, missing evidence
    assessment            anomaly / likelihood / impact / confidence, kept apart
    attack_progression_likelihood, evidence_confidence, crown_jewel_exposure
    progression_forecast  K-step forward simulation
    crosscheck            the agent lane's second opinion, when it ran
plus `bundle["meta"]["agent_pipeline"]` for the agent lane's own trace.
"""
from __future__ import annotations

import pandas as pd


def build_claims(incident: dict) -> list[dict]:
    """One claim per distinct technique, from the strongest step that produced it.

    Not one per alert -- that would be thousands of duplicates of the same
    assertion, and duplicates are exactly what the confidence model must not
    reward.
    """
    from src.shared.attack_mapper import claim_for_event

    best: dict[str, dict] = {}
    for step in incident.get("steps", []):
        tid = step.get("technique_id")
        if not tid or tid == "-" or not step.get("is_alert"):
            continue
        cur = best.get(tid)
        if cur is None or step.get("anomaly_score", 0) > cur.get("anomaly_score", 0):
            best[tid] = step
    return [claim_for_event(s) for _, s in sorted(best.items())]


def run_agent_lane(df: pd.DataFrame | None, scenario: str | None,
                   incident_id: str) -> dict | None:
    """The 10-agent second opinion. Advisory, and never fatal."""
    if df is None:
        return None
    try:
        from src.shared.agent_view import _agent_pipeline_summary
        from src.agents.orchestrator import run_pipeline
        result = run_pipeline(df, scenario=scenario or "events",
                              incident_id=incident_id, use_llm=False)
        return _agent_pipeline_summary(result)
    except Exception as e:
        return {"enabled": True, "status": "failed", "error": str(e)[:200],
                "agent_traces": [], "ranked_chains": [], "predictions": [],
                "evidence_refs": [],
                "notes": ["agent lane failed; the deterministic analysis is unaffected"]}


def attach_agent_lane(bundle: dict, agent_summary: dict) -> dict:
    """Expose the agent lane on a bundle without changing any screen contract.

    Lives here rather than in api.main so src/shared never has to import the API
    layer. src.shared.workflow used to do exactly that, inside a function, which
    hid the inversion from the import graph but not from the design.
    """
    bundle.setdefault("meta", {})["agent_pipeline"] = agent_summary
    bundle["meta"]["pipeline"] = "standard+10-agent"
    if agent_summary.get("status") != "failed":
        try:
            from src.shared.agent_view import _map_agent_bundle
            bundle = _map_agent_bundle(bundle, agent_summary)
        except Exception:
            # The mapping is presentation only. A bundle without it is complete;
            # a bundle that failed to build is not.
            pass
    return bundle


def enrich_bundle(bundle: dict, *, df: pd.DataFrame | None = None,
                  scenario: str | None = None,
                  critical: list[str] | None = None,
                  cited_techniques: int = 0,
                  agent_summary: dict | None = None,
                  run_agents: bool = True,
                  k_steps: int | None = None) -> dict:
    """Attach the full analysis layer to a spine bundle, in place.

    `agent_summary` lets a caller that already ran the agent lane pass it in
    rather than paying for it twice.
    """
    from src.shared.claims import Assessment
    from src.shared.crosscheck import crosscheck as compare
    from src.shared.rollout import FORECAST_HORIZON, simulate_progression
    # one horizon, defined next to the decay it depends on
    k_steps = FORECAST_HORIZON if k_steps is None else k_steps
    from src.shared.workflow import (crown_jewel_exposure, evidence_confidence,
                                     progression_likelihood)

    inc = bundle.get("incident", {})
    graph = bundle.get("graph", {})
    critical = list(critical or [])
    incident_id = inc.get("incident_id", "INC-LIVE-001")
    if scenario:
        bundle.setdefault("meta", {})["scenario"] = scenario

    if agent_summary is None and run_agents:
        agent_summary = run_agent_lane(df, scenario, incident_id)
    if agent_summary is not None:
        bundle.setdefault("meta", {})["agent_pipeline"] = agent_summary
        bundle["meta"]["pipeline"] = "standard+10-agent"
        if agent_summary.get("status") != "failed":
            # No try/except. This used to import from api.main, which made the
            # import circular-adjacent and therefore un-failable, so it was
            # swallowed -- and a raised mapping left the UNMAPPED graph on a
            # bundle still claiming "standard+10-agent". A failure here is now
            # recorded and the claim is withdrawn with it.
            from src.shared.agent_view import _map_agent_bundle
            try:
                bundle = _map_agent_bundle(bundle, agent_summary)
            except Exception as e:
                bundle["meta"]["pipeline"] = "standard (agent mapping failed)"
                bundle["meta"].setdefault("degraded", []).append(
                    f"agent graph mapping failed: {type(e).__name__}: {e}"[:200])

    cc = None
    if agent_summary and agent_summary.get("status") != "failed":
        cc = compare({"signals": {"incident": inc}}, agent_summary)

    claims = build_claims(inc)
    exposure = crown_jewel_exposure(graph, critical)
    likelihood = progression_likelihood(inc, graph)
    confidence = evidence_confidence(claims, cited_techniques,
                                     len(inc.get("technique_ids", [])), cc)
    forecast = simulate_progression(inc.get("technique_ids", []), graph,
                                    k_steps=k_steps, crown_jewels=critical)

    assessment = Assessment(
        anomaly=float(inc.get("max_anomaly_score", 0) or 0),
        likelihood=likelihood["value"],
        impact=exposure["value"],
        confidence=confidence["value"],
        missing_evidence=confidence.get("missing_evidence", []),
    )

    bundle["analysis"] = {
        "claims": claims,
        "assessment": assessment.as_dict(),
        "attack_progression_likelihood": likelihood,
        "evidence_confidence": confidence,
        "crown_jewel_exposure": exposure,
        "progression_forecast": forecast,
        "crosscheck": cc,
        "note": ("Produced by src.shared.enrich for every analysis path, so the "
                 "Investigation, Analyze and cached-sample views cannot disagree "
                 "about the same log."),
    }
    return bundle


def demo() -> None:
    """Self-check: one log, enriched once, carries the whole analysis layer."""
    from src.shared.live_analyze import analyze_events

    df = pd.read_csv("data/demo/scenarios/aiims_ransomware.csv")
    crit = ["PATIENT-DB-01", "DC-AIIMS-01"]
    bundle = enrich_bundle(analyze_events(df.copy(), critical_assets=set(crit)),
                           df=df, scenario="aiims_ransomware", critical=crit)

    a = bundle["analysis"]
    for key in ("claims", "assessment", "attack_progression_likelihood",
                "evidence_confidence", "crown_jewel_exposure",
                "progression_forecast", "crosscheck"):
        assert key in a, key
    assert a["claims"], "no claims built"
    assert a["assessment"]["impact"]["value"] is not None
    assert a["progression_forecast"]["available"] is True
    assert bundle["meta"]["agent_pipeline"]["status"] in ("ok", "partial", "failed")

    # no dataframe -> no agent lane, but everything deterministic still lands
    lean = enrich_bundle(analyze_events(df.copy(), critical_assets=set(crit)),
                         critical=crit, run_agents=False)
    assert lean["analysis"]["claims"]
    assert lean["analysis"]["crosscheck"] is None

    print(f"enrich ok: {len(a['claims'])} claims · "
          f"{a['assessment']['summary'][:60]}… · "
          f"forecast {a['progression_forecast']['headline_probability']}% @ step "
          f"{a['progression_forecast']['reliable_horizon']} · "
          f"crosscheck {a['crosscheck']['verdict'] if a['crosscheck'] else 'n/a'}")


if __name__ == "__main__":
    demo()
