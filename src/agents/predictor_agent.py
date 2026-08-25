"""
src/agents/predictor_agent.py — Agent 9: ATT&CK Association Ranking

The shipped Engine 2 model ranks co-occurring techniques from tactic-sorted
ATT&CK profiles. It does not claim that the ranked techniques happen next.

This is a thin wrapper around src/shared/predictor.py. The only new logic is:
  - extract the technique sequence from the Reasoner's output
  - call the existing Markov predictor
  - return results in AgentResult format for the Orchestrator to validate

Input:  AgentResult from Reasoner (technique_chain field)
Output: AgentResult with ranked investigation leads + association scores.

Usage:
    from src.agents.predictor_agent import run
    result = run(reasoner_result)
"""
from __future__ import annotations

import time

from src.agents import AgentResult, AgentStatus
from src.shared.predictor import (
    generate_prediction_narrative,
    rank_associations,
    temporal_prediction_status,
)


def run(reasoner_result: AgentResult) -> AgentResult:
    """Rank 2-3 ATT&CK techniques associated with the observed set.

    Returns AgentResult with:
        output["predictions"]: legacy field containing {technique_id, association_score, rank}
        output["projection_narrative"]: plain-English multi-sentence projection
        output["technique_chain_used"]: the observed sequence used as input
    """
    t0 = time.perf_counter()

    technique_chain: list[str] = reasoner_result.output.get("technique_chain", [])

    if not technique_chain:
        return AgentResult(
            agent="prediction",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            notes=["No technique chain from Reasoner; cannot rank associations."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    try:
        raw_predictions, source = rank_associations(technique_chain, k=3)
    except Exception as e:
        return AgentResult(
            agent="prediction",
            status=AgentStatus.FAILED,
            confidence=0.0,
            notes=[f"Predictor error: {e}"],
            ms=(time.perf_counter() - t0) * 1000,
        )

    if not raw_predictions:
        return AgentResult(
            agent="prediction",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            output={"technique_chain_used": technique_chain, "predictions": [], "projection_narrative": ""},
            notes=["Association ranker returned no candidates for this technique set."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    try:
        from src.shared.views import _names
        names = _names()
    except Exception:
        names = {}

    predictions = []
    for rank, (tid, prob) in enumerate(raw_predictions, start=1):
        predictions.append({
            "rank": rank,
            "technique_id": str(tid),
            "name": names.get(str(tid), str(tid)),
            "association_score": round(float(prob), 4),
            "source": source,
        })

    projection_narrative = generate_prediction_narrative(predictions, technique_chain)
    return AgentResult(
        agent="prediction",
        status=AgentStatus.OK if predictions else AgentStatus.DEGRADED,
        # Profile association strength is not calibrated confidence.
        confidence=0.0,
        output={
            "technique_chain_used": technique_chain,
            "predictions": predictions,
            "projection_narrative": projection_narrative,
            "n_predictions": len(predictions),
            "mode": "association-only",
            "temporal_prediction": temporal_prediction_status(),
        },
        evidence_refs=[p["technique_id"] for p in predictions],
        notes=[
            f"Ranked {len(predictions)} associated technique(s) from {len(technique_chain)} observations.",
            f"Top association: {predictions[0]['technique_id']} @ score {predictions[0]['association_score']:.1%}" if predictions else "",
            "Association strength is not a probability or calibrated confidence.",
        ],
        ms=(time.perf_counter() - t0) * 1000,
    )
