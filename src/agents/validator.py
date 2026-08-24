"""
src/agents/validator.py — Agent 6: Validation (False-Positive Filter)

Sarthak's doc: "confirms each proposed attack chain is real by checking for
corroborating evidence across signals, not just one detector's opinion.
Chains without at least 2 independent corroborating signals get downgraded to
'unconfirmed' rather than dropped."

Corroborating signal sources:
  1. Evidence index (MITRE ATT&CK citations, CISA KEV matches)
  2. Semantic RAG retrieval (technique description match)
  3. Anomaly score above high threshold (>= 75)
  4. Multiple independent flagged chunks for same entity
  5. Technique appears in a known APT group's profile

Wraps:  src/shared/evidence.py   (BM25 lexical evidence search)
        src/retrieval/query.py   (semantic RAG)

Input:  AgentResult from KB Connector (connected graph)
Output: AgentResult with chains tagged confirmed / partially_confirmed / unconfirmed.

Usage:
    from src.agents.validator import run
    result = run(kb_result, intelligence_result)
"""
from __future__ import annotations

import time
from collections import defaultdict

from src.agents import AgentResult, AgentStatus

# ─── Thresholds ────────────────────────────────────────────────────────────────
HIGH_SCORE_THRESHOLD = 75   # anomaly score that counts as a corroboration signal
MIN_SIGNALS_CONFIRMED = 2   # minimum independent signals for "confirmed"
TOTAL_SIGNALS = 5           # evidence index, RAG, anomaly score, multi-chunk, APT

# A probe returns 1 (corroborates), 0 (does not), or UNAVAILABLE (cannot be
# evaluated here at all). The third state is the whole point: `except: return 0`
# made "the retriever is not installed" indistinguishable from "no evidence
# corroborates this technique", and the deploy image ships without chromadb or
# sentence-transformers, so the RAG probe was silently 0 for EVERY technique
# while still being counted out of five.
UNAVAILABLE = None


def _evidence_search(tid: str) -> int | None:
    """1 if the evidence index cites this technique, 0 if not, UNAVAILABLE if
    the index cannot be consulted."""
    try:
        from src.shared.evidence import repository
    except Exception:
        return UNAVAILABLE
    try:
        repo = repository()
    except Exception:
        return UNAVAILABLE
    try:
        return 1 if repo.search(tid, k=1) else 0
    except Exception:
        return UNAVAILABLE


def _rag_search(tid: str, text: str) -> int | None:
    """1 on a confident semantic match, 0 on no match, UNAVAILABLE if the
    vector store is not built or its dependencies are not installed.

    The deploy image excludes chromadb and sentence-transformers on purpose,
    so UNAVAILABLE is the NORMAL answer in production, not an error.
    """
    try:
        from src.retrieval.query import RAGQueryEngine
    except Exception:
        return UNAVAILABLE          # dependency absent: the slim deploy image
    try:
        rag = RAGQueryEngine()
    except Exception:
        return UNAVAILABLE          # store not built
    try:
        results = rag.retrieve(text or tid, top_k=1, source_filter=["mitre_attack"])
    except Exception:
        return UNAVAILABLE
    return 1 if results and results[0].get("score", 0) >= 0.55 else 0


def _apt_profile_match(tid: str) -> int:
    """Returns 1 if this technique appears in any known APT group's profile."""
    try:
        from src.shared.parse_attack import load_attack
        attack = load_attack()
        tech_to_groups = attack.get("tech_to_groups", {})
        return 1 if tech_to_groups.get(tid) else 0
    except Exception:
        return 0


def _tag_confidence(n_signals: int, n_unavailable: int = 0) -> tuple[str, float]:
    """Corroboration strength as a SHARE OF THE PROBES THAT COULD RUN.

    This used to be `min(0.5 + n_signals * 0.12, 0.95)` -- five constants,
    inline and uncommented, fitted against nothing, producing a number labelled
    "confidence" and rendered on screen. In a codebase whose whole argument is
    that every number carries where it came from, that was the loudest
    exception.

    It is now a fraction with a stated denominator, which is a thing that can
    be checked: k corroborating probes out of the n that were able to run.
    Still not a calibrated probability, and deliberately not called one -- the
    chain also carries `n_signals` and `n_signals_available` so a reader can
    see the fraction rather than trust the float.

    `n_unavailable` shrinks the denominator instead of the numerator. The deploy
    image ships without the vector store, so scoring a missing probe as a
    failure understated every chain by up to a fifth.
    """
    available = max(TOTAL_SIGNALS - n_unavailable, 1)
    share = min(n_signals, available) / available
    if n_signals >= MIN_SIGNALS_CONFIRMED:
        return "confirmed", round(share, 3)
    if n_signals == 1:
        return "partially_confirmed", round(share, 3)
    return "unconfirmed", round(share, 3)


def run(
    kb_result: AgentResult,
    intelligence_result: AgentResult,
) -> AgentResult:
    """Validate each attack chain with corroborating evidence.

    Returns AgentResult with:
        output["chains"]: list of chain records with confirmation tag + evidence
        output["confirmed_count"]: fully confirmed chains
        output["partial_count"]: partially confirmed
        output["unconfirmed_count"]: unconfirmed (kept, not dropped)
    """
    t0 = time.perf_counter()

    mapped: list[dict] = intelligence_result.output.get("mapped", [])
    graph_analysis = kb_result.output.get("graph_analysis", {})

    if not mapped:
        return AgentResult(
            agent="validator",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            notes=["No mapped chunks to validate."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    # Group by entity to form "chains"
    entity_chunks: dict[str, list[dict]] = defaultdict(list)
    for chunk in mapped:
        entity_chunks[chunk.get("entity", "unknown")].append(chunk)

    chains: list[dict] = []
    evidence_refs: list[str] = []

    for entity, chunks in entity_chunks.items():
        # Distinct techniques in the order the entity first exhibited them. Chunks
        # arrive time-ordered, so this IS the observed progression -- which is what
        # the predictor, the actor match and the narrative all want. Undeduplicated
        # it read "chain of 49 techniques" for U66 when every one of them was the
        # same T1550.002, and the UI printed the ID 49 times in one table cell.
        raw_tids = [c.get("technique_id") for c in chunks if c.get("technique_id")]
        technique_ids = list(dict.fromkeys(raw_tids))
        max_score = max((c.get("anomaly_score", 0) for c in chunks), default=0)
        technique_texts = " ".join(c.get("point_a_text", "") for c in chunks)

        signals: list[str] = []
        # Probes that could not run at all. Counted separately so the score has
        # an honest denominator instead of silently losing a fifth of itself.
        unavailable: list[str] = []

        # Signal 1: Evidence index citation for primary technique
        ev = UNAVAILABLE
        for tid in technique_ids[:2]:
            if not tid:
                continue
            ev = _evidence_search(tid)
            if ev == 1:
                signals.append(f"evidence_index:{tid}")
                break
            if ev == 0:
                break
        if ev is UNAVAILABLE:
            unavailable.append("evidence_index")

        # Signal 2: RAG retrieval match
        primary_tid = technique_ids[0] if technique_ids else ""
        rag = _rag_search(primary_tid, technique_texts) if primary_tid else UNAVAILABLE
        if rag == 1:
            signals.append(f"rag_match:{primary_tid}")
        elif rag is UNAVAILABLE:
            unavailable.append("rag_match")

        # Signal 3: High anomaly score
        if max_score >= HIGH_SCORE_THRESHOLD:
            signals.append(f"high_anomaly_score:{max_score}")

        # Signal 4: Multiple independent flagged chunks from same entity
        if len(chunks) >= 2:
            signals.append(f"multi_chunk_entity:{len(chunks)}_chunks")

        # Signal 5: Technique in known APT profile
        for tid in technique_ids:
            if tid and _apt_profile_match(tid):
                signals.append(f"apt_profile_match:{tid}")
                break

        tag, conf = _tag_confidence(len(signals), len(unavailable))
        for tid in technique_ids:
            evidence_refs.append(tid)

        chains.append({
            "entity": entity,
            "technique_ids": technique_ids,
            "n_technique_events": len(raw_tids),
            "tactic_chain": list(dict.fromkeys(
                c.get("tactic", "") for c in chunks if c.get("tactic")
            )),
            "max_anomaly_score": max_score,
            "n_chunks": len(chunks),
            "confirmation": tag,
            "confidence": conf,
            "corroborating_signals": signals,
            "n_signals": len(signals),
            # The denominator. Without these two a reader cannot tell a genuine
            # 2-of-5 from a 2-of-4 where the fifth probe was never installed.
            "n_signals_available": TOTAL_SIGNALS - len(unavailable),
            "signals_unavailable": unavailable,
        })

    confirmed = sum(1 for c in chains if c["confirmation"] == "confirmed")
    partial = sum(1 for c in chains if c["confirmation"] == "partially_confirmed")
    unconfirmed = sum(1 for c in chains if c["confirmation"] == "unconfirmed")

    avg_conf = sum(c["confidence"] for c in chains) / max(len(chains), 1)

    return AgentResult(
        agent="validator",
        status=AgentStatus.OK,
        confidence=round(avg_conf, 3),
        output={
            "chains": chains,
            "confirmed_count": confirmed,
            "partial_count": partial,
            "unconfirmed_count": unconfirmed,
            "total_chains": len(chains),
        },
        evidence_refs=list(set(evidence_refs)),
        notes=[
            f"Validated {len(chains)} entity chains: "
            f"{confirmed} confirmed, {partial} partial, {unconfirmed} unconfirmed.",
            "Unconfirmed chains retained — not discarded.",
        ],
        ms=(time.perf_counter() - t0) * 1000,
    )
