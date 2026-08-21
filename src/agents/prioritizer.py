"""
src/agents/prioritizer.py — Agent 7: Prioritization (Risk Ranking)

Sarthak's doc: "ranks paths by exploitability and attacker behavior, not static
CVSS-style severity — factors like: how reachable is this path right now, does
this match a technique sequence real actors actually use, how many downstream
assets does this path touch."

Wraps:  src/shared/twin.py  (blast-radius & reachability analysis)
        src/shared/vuln.py  (6-signal vulnerability priority scoring)

Input:  AgentResult from Validator (confirmed/partial/unconfirmed chains)
        AgentResult from KB Connector (live NetworkX graph)
Output: AgentResult with chains ranked by composite risk score, highest first.

Scoring formula (all factors normalized 0-1, weights sum to 1.0):
  0.35 × max_anomaly_score / 100
  0.25 × blast_radius / total_nodes
  0.20 × technique_actor_match (1 if known APT uses this technique, else 0)
  0.20 × confirmation_weight (confirmed=1.0, partial=0.5, unconfirmed=0.2)

Usage:
    from src.agents.prioritizer import run
    result = run(validator_result, kb_result)
"""
from __future__ import annotations

import time

from src.agents import AgentResult, AgentStatus

# ─── Scoring weights ───────────────────────────────────────────────────────────
W_SCORE = 0.35
W_BLAST = 0.25
W_ACTOR = 0.20
W_CONF  = 0.20

CONFIRMATION_WEIGHTS = {
    "confirmed": 1.0,
    "partially_confirmed": 0.5,
    "unconfirmed": 0.2,
}


def _blast_radius(entity: str, graph) -> int:
    """Return the blast radius for an entity: number of nodes reachable from it."""
    if graph is None or entity not in graph:
        return 0
    try:
        import networkx as nx
        reachable = nx.descendants(graph, entity)
        return len(reachable)
    except Exception:
        return 0


def _actor_match(technique_ids: list[str]) -> float:
    """Returns 1.0 if any technique is in a known APT group's profile."""
    try:
        from src.shared.parse_attack import load_attack
        attack = load_attack()
        tech_to_groups = attack.get("tech_to_groups", {})
        for tid in technique_ids:
            if tech_to_groups.get(tid):
                return 1.0
    except Exception:
        pass
    return 0.0


def run(
    validator_result: AgentResult,
    kb_result: AgentResult,
) -> AgentResult:
    """Rank validated chains by composite real-world risk score.

    Returns AgentResult with:
        output["ranked_chains"]: chains sorted by risk_score descending
        output["top_chain"]: the single highest-risk chain
    """
    t0 = time.perf_counter()

    chains: list[dict] = validator_result.output.get("chains", [])
    G = kb_result.output.get("_graph")
    total_nodes = kb_result.output.get("node_count", 1) or 1

    if not chains:
        return AgentResult(
            agent="prioritizer",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            notes=["No chains from Validator."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    ranked: list[dict] = []
    for chain in chains:
        entity = chain["entity"]
        tech_ids = chain.get("technique_ids", [])
        max_score = chain.get("max_anomaly_score", 0)
        confirmation = chain.get("confirmation", "unconfirmed")

        blast = _blast_radius(entity, G)
        actor = _actor_match(tech_ids)
        conf_w = CONFIRMATION_WEIGHTS.get(confirmation, 0.2)

        risk_score = (
            W_SCORE * (max_score / 100)
            + W_BLAST * min(blast / total_nodes, 1.0)
            + W_ACTOR * actor
            + W_CONF  * conf_w
        )

        ranked.append({
            **chain,
            "blast_radius": blast,
            "actor_match": bool(actor),
            "risk_score": round(risk_score, 4),
            "risk_band": (
                "critical" if risk_score >= 0.75
                else "high" if risk_score >= 0.55
                else "medium" if risk_score >= 0.35
                else "low"
            ),
        })

    ranked.sort(key=lambda c: c["risk_score"], reverse=True)
    top = ranked[0] if ranked else {}

    return AgentResult(
        agent="prioritizer",
        status=AgentStatus.OK,
        confidence=round(top.get("risk_score", 0), 3),
        output={
            "ranked_chains": ranked,
            "top_chain": top,
            "total_ranked": len(ranked),
        },
        evidence_refs=[t for c in ranked for t in c.get("technique_ids", [])],
        notes=[
            f"Ranked {len(ranked)} chains. Top entity: {top.get('entity','')} "
            f"risk={top.get('risk_score',0):.3f} ({top.get('risk_band','')}).",
        ],
        ms=(time.perf_counter() - t0) * 1000,
    )
