"""
src/agents/predictor_agent.py — Agent 9: Prediction (Next-Move Anticipation)

Sarthak's doc: "predicts the attacker's likely next 2-3 moves (this is our
existing Engine 2 — Markov-based predictor, since it beat the LSTM)."

This is a thin wrapper around src/shared/predictor.py. The only new logic is:
  - extract the technique sequence from the Reasoner's output
  - call the existing Markov predictor
  - return results in AgentResult format for the Orchestrator to validate

Input:  AgentResult from Reasoner (technique_chain field)
Output: AgentResult with ranked list of next likely techniques + probabilities.

Usage:
    from src.agents.predictor_agent import run
    result = run(reasoner_result)
"""
from __future__ import annotations

import time

from src.agents import AgentResult, AgentStatus
from src.shared.predictor import rank_next


def run(reasoner_result: AgentResult) -> AgentResult:
    """Predict the attacker's likely next 2-3 ATT&CK techniques.

    Returns AgentResult with:
        output["predictions"]: list of {technique_id, probability, rank}
        output["technique_chain_used"]: the observed sequence used as input
    """
    t0 = time.perf_counter()

    technique_chain: list[str] = reasoner_result.output.get("technique_chain", [])

    if not technique_chain:
        return AgentResult(
            agent="prediction",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            notes=["No technique chain from Reasoner; cannot predict next moves."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    try:
        raw_predictions, source = rank_next(technique_chain, k=3)
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
            output={"technique_chain_used": technique_chain, "predictions": []},
            notes=["Predictor returned no predictions for this sequence."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    predictions = []
    for rank, (tid, prob) in enumerate(raw_predictions, start=1):
        predictions.append({
            "rank": rank,
            "technique_id": str(tid),
            "probability": round(float(prob), 4),
            "source": source,
        })

    top_conf = predictions[0]["probability"] if predictions else 0.0

    return AgentResult(
        agent="prediction",
        status=AgentStatus.OK if predictions else AgentStatus.DEGRADED,
        confidence=round(top_conf, 3),
        output={
            "technique_chain_used": technique_chain,
            "predictions": predictions,
            "n_predictions": len(predictions),
        },
        evidence_refs=[p["technique_id"] for p in predictions],
        notes=[
            f"Predicted next {len(predictions)} move(s) from chain of {len(technique_chain)} techniques.",
            f"Top prediction: {predictions[0]['technique_id']} @ {predictions[0]['probability']:.1%}" if predictions else "",
        ],
        ms=(time.perf_counter() - t0) * 1000,
    )
