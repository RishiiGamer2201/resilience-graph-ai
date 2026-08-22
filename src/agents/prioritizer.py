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

# Risk bands. Read off the rounded score so the printed number and the printed
# band can never disagree.
BAND_CRITICAL, BAND_HIGH, BAND_MEDIUM = 0.75, 0.55, 0.35


def _band(score: float) -> str:
    return ("critical" if score >= BAND_CRITICAL
            else "high" if score >= BAND_HIGH
            else "medium" if score >= BAND_MEDIUM
            else "low")


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


_TECH_TO_GROUPS: dict[str, list[str]] | None = None


def _tech_to_groups() -> dict[str, list[str]]:
    """technique id -> the real ATT&CK groups documented as using it.

    This used to call `load_attack()` from src.shared.parse_attack, a function
    that does not exist there, inside a bare `except Exception: pass`. The
    ImportError was swallowed on every call, so _actor_match returned 0.0 for
    every chain in every scenario and 20% of the risk score (W_ACTOR) was dead
    weight. Inverted once from the pickled lookups the rest of the app uses.
    """
    global _TECH_TO_GROUPS
    if _TECH_TO_GROUPS is None:
        from src.shared.attack_mapper import _lookups
        out: dict[str, list[str]] = {}
        for group, techs in _lookups().get("group_to_techniques", {}).items():
            for tid in techs:
                out.setdefault(tid, []).append(group)
        _TECH_TO_GROUPS = out
    return _TECH_TO_GROUPS


def _actor_match(technique_ids: list[str]) -> float:
    """1.0 if any technique appears in a known ATT&CK group's profile."""
    t2g = _tech_to_groups()
    return 1.0 if any(t2g.get(tid) for tid in technique_ids) else 0.0


def _matched_actors(technique_ids: list[str], limit: int = 5) -> list[str]:
    """The groups behind the match, so the score can be read rather than trusted."""
    t2g = _tech_to_groups()
    seen: list[str] = []
    for tid in technique_ids:
        for g in t2g.get(tid, []):
            if g not in seen:
                seen.append(g)
    return sorted(seen)[:limit]


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
            "matched_actors": _matched_actors(tech_ids) if actor else [],
            "risk_score": round(risk_score, 4),
            # Band from the SAME rounded number the UI shows. Banding the raw
            # float printed "risk=0.55" next to "medium" for a 0.54999 chain.
            "risk_band": _band(round(risk_score, 4)),
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
            # Say how weak this term is rather than let a reader take an APT name
            # for an attribution. 525 of 794 ATT&CK techniques have at least one
            # documented group, so "a known group uses this" is close to always
            # true and mostly raises the whole distribution.
            f"Actor match fired on {sum(c['actor_match'] for c in ranked)} of "
            f"{len(ranked)} chains. It records that a documented group uses the "
            f"technique, not that this group is responsible.",
        ],
        ms=(time.perf_counter() - t0) * 1000,
    )
