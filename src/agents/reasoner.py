"""
src/agents/reasoner.py — Agent 8: Reasoning (Incident Narrative)

Sarthak's doc: "produces the human-readable explanation — what happened, in
what order, and why it looks like a real attack, in plain language a
non-technical stakeholder could follow. This is also the natural place for
your incident-level context summarization (Point B)."

Wraps:  src/shared/explain.py   (per-step provenance chain)
        src/agents/summarizer   (Point B incident narrative)

Input:  AgentResult from Prioritizer (ranked chains)
        Point-A summaries (list[dict]) for Point-B condensation
        technique_chain (list[str]) from Intelligence
Output: AgentResult with incident narrative + per-chain explanation + citations.

Usage:
    from src.agents.reasoner import run
    result = run(prioritizer_result, point_a_summaries, technique_chain)
"""
from __future__ import annotations

import time

from src.agents import AgentResult, AgentStatus
from src.agents.summarizer import summarize_incident


def _chain_explanation(chain: dict) -> str:
    """Template-based explanation for one ranked chain."""
    entity = chain.get("entity", "unknown")
    tids = chain.get("technique_ids", [])
    tactics = chain.get("tactic_chain", [])
    signals = chain.get("corroborating_signals", [])
    confirmation = chain.get("confirmation", "unconfirmed")
    risk_band = chain.get("risk_band", "low")
    blast = chain.get("blast_radius", 0)
    actor_match = chain.get("actor_match", False)

    tactic_str = " → ".join(tactics) if tactics else "unknown tactic chain"
    tech_str = ", ".join(tids[:5]) if tids else "no techniques identified"
    signal_str = "; ".join(signals[:4]) if signals else "no corroborating signals"

    actor_note = (
        " The technique sequence matches a known advanced persistent threat (APT) group's profile."
        if actor_match else ""
    )
    blast_note = f" Isolating this entity would cut access to {blast} downstream node(s)." if blast > 0 else ""

    return (
        f"Entity '{entity}' ({confirmation}, {risk_band} risk): "
        f"Observed tactic chain — {tactic_str}. "
        f"Mapped techniques: {tech_str}. "
        f"Corroborating evidence: {signal_str}.{actor_note}{blast_note}"
    )


def run(
    prioritizer_result: AgentResult,
    point_a_summaries: list[dict],
    technique_chain: list[str],
    *,
    incident_id: str = "INC-001",
    use_llm: bool = True,
) -> AgentResult:
    """Produce the final incident narrative grounded in cited evidence.

    Returns AgentResult with:
        output["incident_narrative"]: Point-B narrative string
        output["chain_explanations"]: per-chain plain-language text
        output["incident_id"]: incident identifier
        output["severity"]: critical | high | medium | low
        output["point_b_method"]: "llm" | "template"
    """
    t0 = time.perf_counter()

    ranked = prioritizer_result.output.get("ranked_chains", [])
    top = prioritizer_result.output.get("top_chain", {})

    if not ranked:
        return AgentResult(
            agent="reasoner",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            notes=["No ranked chains from Prioritizer."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    # ── Point B: Incident Summarizer ────────────────────────────────────────
    point_b = summarize_incident(
        point_a_summaries,
        technique_chain,
        use_llm=use_llm,
    )

    # ── Per-chain plain-language explanations ───────────────────────────────
    chain_explanations: list[dict] = []
    for chain in ranked[:5]:  # Top 5 chains
        chain_explanations.append({
            "entity": chain["entity"],
            "confirmation": chain["confirmation"],
            "risk_band": chain["risk_band"],
            "explanation": _chain_explanation(chain),
        })

    # ── Severity from top chain ──────────────────────────────────────────────
    severity = top.get("risk_band", "low") if top else "low"
    evidence_refs = list(set(
        t for chain in ranked for t in chain.get("technique_ids", [])
    ))

    return AgentResult(
        agent="reasoner",
        status=AgentStatus.OK,
        confidence=prioritizer_result.confidence,
        output={
            "incident_id": incident_id,
            "severity": severity,
            "incident_narrative": point_b["narrative"],
            "point_b_method": point_b["method"],
            "point_b_disclaimer": point_b.get("disclaimer", ""),
            "chain_explanations": chain_explanations,
            "technique_chain": technique_chain,
            "top_entity": top.get("entity", ""),
            "top_risk_score": top.get("risk_score", 0.0),
        },
        evidence_refs=evidence_refs,
        notes=[
            f"Narrative generated via {point_b['method']}.",
            "LLM output (if used) is non-authoritative and labelled accordingly.",
        ],
        ms=(time.perf_counter() - t0) * 1000,
    )
