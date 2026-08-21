"""
src/agents/intelligence.py — Agent 3: Intelligence (ATT&CK Technique Mapping)

Sarthak's doc: "matches each flagged event against known MITRE ATT&CK techniques
— rule-based lookup first (fast, deterministic), RAG-grounded matching against
technique descriptions for anything ambiguous."

HARD RULE: Only assigns real ATT&CK IDs from the parsed 794-technique lookup.
           Never generates or invents a technique ID. Orchestrator enforces this
           as a hard gate.

Wraps:
  src/shared/attack_mapper.py  — rule-based event→technique mapping
  src/retrieval/query.py       — semantic RAG fallback for ambiguous events

Input:  AgentResult from Detection (scored chunks with flagged=True)
Output: AgentResult with technique_id + tactic + confidence per flagged chunk.

Usage:
    from src.agents.intelligence import run
    result = run(detection_result)
"""
from __future__ import annotations

import re
import time

from src.agents import AgentResult, AgentStatus
from src.shared.attack_mapper import infer_lanl_event_type, map_event

# ─── Valid ATT&CK ID pattern (enforced as hard gate) ──────────────────────────
_ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# ─── RAG query engine (lazy-loaded, optional) ──────────────────────────────────
_rag_query = None


def _get_rag():
    global _rag_query
    if _rag_query is None:
        try:
            from src.retrieval.query import RAGQueryEngine
            _rag_query = RAGQueryEngine()
        except Exception:
            _rag_query = False   # mark as unavailable
    return _rag_query if _rag_query is not False else None


def _validate_technique_id(tid: str) -> bool:
    """Returns True only if tid matches a real ATT&CK ID pattern."""
    return bool(_ATTACK_ID_RE.match(str(tid or "")))


def _rule_based_map(chunk_record: dict) -> dict | None:
    """Use attack_mapper.py's deterministic lookup for a scored chunk."""
    stats = chunk_record.get("stats", {})
    fail_rate = stats.get("failure_rate", 0.0)
    n_dst = stats.get("destination_host_unique", 1)
    n_events = stats.get("n_events", 1)
    score = chunk_record.get("anomaly_score", 0)

    # Synthesize an event type string for the rule engine
    event_types_top = stats.get("event_type_top", {})
    dominant_type = max(event_types_top, key=event_types_top.get, default="normal_auth")

    # Enrich with lateral-movement hints
    if n_dst >= 5 and fail_rate < 0.3:
        dominant_type = "lateral_movement"
    elif fail_rate >= 0.5 and n_events >= 5:
        dominant_type = "brute_force"
    elif stats.get("bytes_out_total", 0) > 10_000_000:
        dominant_type = "large_outbound"

    mapping = map_event(dominant_type)
    tid = mapping.get("technique", "")
    if not _validate_technique_id(tid):
        return None

    return {
        "technique_id": tid,
        "technique_name": mapping.get("technique_name", ""),
        "tactic": mapping.get("tactic", ""),
        "confidence": min(1.0, score / 100 * mapping.get("confidence", 0.6)),
        "method": "rule_based",
    }


def _rag_based_map(chunk_record: dict) -> dict | None:
    """RAG-grounded fallback for ambiguous events."""
    rag = _get_rag()
    if not rag:
        return None

    text = chunk_record.get("point_a_text", "")
    if not text:
        return None

    try:
        results = rag.retrieve(text, top_k=1, source_filter=["mitre_attack"])
        if not results:
            return None
        top = results[0]
        tids = top.get("technique_ids", [])
        tid = tids[0] if tids else top.get("id", "")
        if not _validate_technique_id(tid):
            return None
        return {
            "technique_id": tid,
            "technique_name": top.get("title", ""),
            "tactic": top.get("tactic", ""),
            "confidence": round(float(top.get("score", 0.5)), 3),
            "method": "rag",
        }
    except Exception:
        return None


def run(detection_result: AgentResult) -> AgentResult:
    """Map each flagged chunk to an ATT&CK technique.

    Only processes chunks with flagged=True. Rule-based first; RAG if
    rule-based returns no valid ID. If both fail, the chunk is marked
    technique_id=None (Orchestrator notes it as low-confidence).

    Returns AgentResult with:
        output["mapped"]: list of chunk records with technique annotations
        output["mapped_count"]: number of chunks with a valid technique ID
        output["unmapped_count"]: chunks where both methods failed
    """
    t0 = time.perf_counter()

    scored: list[dict] = detection_result.output.get("scored", [])
    flagged = [c for c in scored if c.get("flagged")]

    if not flagged:
        return AgentResult(
            agent="intelligence",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            notes=["No flagged chunks received from Detection."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    mapped: list[dict] = []
    unmapped_count = 0

    for chunk in flagged:
        tech = _rule_based_map(chunk)

        if not tech:
            tech = _rag_based_map(chunk)

        if tech:
            record = {**chunk, **tech}
        else:
            unmapped_count += 1
            record = {
                **chunk,
                "technique_id": None,
                "technique_name": None,
                "tactic": None,
                "confidence": 0.3,
                "method": "unmapped",
            }

        mapped.append(record)

    valid_mapped = [m for m in mapped if m.get("technique_id")]
    avg_conf = (
        sum(m["confidence"] for m in valid_mapped) / max(len(valid_mapped), 1)
    )

    return AgentResult(
        agent="intelligence",
        status=AgentStatus.OK if valid_mapped else AgentStatus.DEGRADED,
        confidence=round(avg_conf, 3),
        output={
            "mapped": mapped,
            "mapped_count": len(valid_mapped),
            "unmapped_count": unmapped_count,
        },
        evidence_refs=[m["technique_id"] for m in valid_mapped],
        notes=[
            f"Mapped {len(valid_mapped)}/{len(flagged)} flagged chunks to ATT&CK techniques.",
            f"{unmapped_count} chunks could not be mapped (flagged low-confidence by Orchestrator).",
        ],
        ms=(time.perf_counter() - t0) * 1000,
    )
