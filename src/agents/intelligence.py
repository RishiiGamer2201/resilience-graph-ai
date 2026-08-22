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

import os
import re
import time

from src.agents import AgentResult, AgentStatus
from src.shared.attack_mapper import RULE_MAP, infer_lanl_event_type, map_event

# ─── Valid ATT&CK ID pattern (enforced as hard gate) ──────────────────────────
_ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# ─── Behavioural rule thresholds ──────────────────────────────────────────────
# Named, not inline, because they decide which ATT&CK technique reaches a screen.
NTLM_DOMINANT = 0.8      # share of the chunk's logins negotiating NTLM
NTLM_MIN_HOSTS = 2       # ...and reaching at least this many distinct hosts
FAIL_BURST_RATE = 0.5    # failed-login share that reads as brute force
FAIL_BURST_EVENTS = 5    # ...over at least this many attempts

# ─── RAG query engine (lazy-loaded, optional) ──────────────────────────────────
_rag_query = None


def _get_rag():
    """The shared retrieval dispatcher, or None when it is unavailable.

    This used to import `RAGQueryEngine` from src.retrieval.query, a class that
    does not exist there, so the fallback was permanently dead. Routed through
    src.shared.evidence.search, which picks the semantic backend when the vector
    store is built and the lexical one otherwise.
    """
    global _rag_query
    if _rag_query is None:
        try:
            from src.shared.evidence import search as _search
            _rag_query = _search
        except Exception:
            _rag_query = False
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
    ntlm_rate = stats.get("ntlm_rate", 0.0)
    score = chunk_record.get("anomaly_score", 0)

    # Synthesize an event type string for the rule engine
    event_types_top = stats.get("event_type_top", {})
    dominant_type = max(event_types_top, key=event_types_top.get, default="normal_auth")

    # Enrich with behavioural hints. These MUST be real RULE_MAP keys -- the
    # previous values ("lateral_movement", "brute_force", "large_outbound") are
    # not in the table, so every one of them fell through to "Unmapped".
    #
    # Ordered by how much the pattern actually establishes, strongest first.
    # Before this the lane could only ever reach new_host_auth: it mapped 60 of
    # 229 flagged LANL chunks and every one of them to T1021, so the entity
    # chains carried a single technique and the prioritiser scored the campaign
    # medium against the workflow's critical.
    if ntlm_rate >= NTLM_DOMINANT and n_dst >= NTLM_MIN_HOSTS:
        # NTLM alone is not pass-the-hash: 30% of benign logins in the LANL demo
        # slice use it. NTLM *plus* fan-out to several hosts is the signature the
        # ntlm_lateral_movement rule is named for, and the rule already carries
        # claim_status "inferred" with the missing evidence spelled out.
        dominant_type = "ntlm_lateral_movement"
    elif fail_rate >= FAIL_BURST_RATE and n_events >= FAIL_BURST_EVENTS:
        dominant_type = "failed_login_burst"
    elif stats.get("bytes_out_total", 0) > 10_000_000:
        dominant_type = "large_outbound_transfer"
    elif n_dst >= 5 and fail_rate < 0.3:
        dominant_type = "new_host_auth"
    elif fail_rate == 0.0 and n_events >= 2:
        # An anomalous chunk that is entirely successful and does not fan out.
        # T1078 at claim_strength 0.3, status "inferred", never actionable on its
        # own -- the deliberately weak reading. Asserting it any harder is the
        # over-assertion the research doc warns about and that we already made
        # once by mapping every anomalous login to T1078 to inflate coverage.
        dominant_type = "unusual_successful_login"
    elif dominant_type not in RULE_MAP:
        # an event_type straight from the log that the table does not know
        dominant_type = "normal_auth"

    mapping = map_event(dominant_type)
    # map_event returns the NAME under "technique" and the ID under
    # "technique_id". Validating the name against an ATT&CK id regex can never
    # match, which is why this mapped 0 of 5 chunks.
    tid = mapping.get("technique_id", "")
    if not _validate_technique_id(tid):
        return None

    # The rule's own calibrated weight (src.shared.attack_mapper.CLAIM_RULES),
    # not an invented 0.6 default. An anomaly score scales it; it never exceeds
    # what the rule itself can support.
    rule_strength = float(mapping.get("claim_strength", 0.3))
    return {
        "technique_id": tid,
        "technique_name": mapping.get("technique", ""),
        "tactic": mapping.get("tactic", ""),
        "confidence": round(min(1.0, (score / 100.0) * rule_strength), 3),
        "claim_status": mapping.get("claim_status", "inferred"),
        "missing_evidence": mapping.get("missing_evidence", []),
        "alternatives": mapping.get("alternatives", []),
        "method": "rule_based",
    }


# Semantic fallback is OFF by default. rules.md: "Precision over recall in ATT&CK
# mapping. A wrong technique on screen is worse than none." Enabled, it attached
# T1110.003 and T1496.003 to an authentication log on the strength of wording
# similarity alone. An unmapped chunk staying unmapped is a legitimate, honest
# result; a speculative technique in the incident chain is not.
RAG_FALLBACK = os.getenv("NEXTATTACK_AGENT_RAG_FALLBACK", "").lower() in ("1", "true", "yes")


def _rag_based_map(chunk_record: dict) -> dict | None:
    """Semantic fallback for chunks no behavioural rule matched. Opt-in."""
    if not RAG_FALLBACK:
        return None
    rag = _get_rag()
    if not rag:
        return None

    text = chunk_record.get("point_a_text", "")
    if not text:
        return None

    try:
        hits = rag(text, k=3, publishers=["MITRE"])
        for top in hits:
            tid = next((i for i in top.get("identifiers", [])
                        if _validate_technique_id(i)), "")
            if not tid:
                continue
            return {
                "technique_id": tid,
                "technique_name": top.get("title", ""),
                "tactic": "",
                # Retrieval similarity is not a claim strength. A semantic hit
                # says the wording resembles a technique page; it is weaker
                # evidence than a behavioural rule, and is scored accordingly.
                "confidence": 0.2,
                "claim_status": "inferred",
                "missing_evidence": ["a behavioural rule or corroborating telemetry "
                                     "for this technique"],
                "alternatives": ["text that merely resembles the technique description"],
                "method": "rag",
            }
        return None
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
