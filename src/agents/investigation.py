"""
src/agents/investigation.py — Agent 1: Investigation (Triage & Context)

Sarthak's doc: "Investigation now focuses on triage and context-building:
reviews each incoming chunk, cross-references it against recent related chunks
(same user/host/session) to build short-term context, flags anything Stage 0
marked as low-confidence or missing fields, and decides which chunks are worth
escalating to Detection versus which are routine/low-signal."

Input:  List[EventChunk] — pre-processed, schema-normalized, Point-A summarized.
Output: AgentResult with triaged chunks tagged priority + short-term context.

Priorities:
  "urgent"   — multiple suspicious chunks from same entity in recent window
  "elevated" — single anomalous pattern or missing critical fields
  "routine"  — low-signal, well-understood behavior

Usage:
    from src.agents.investigation import run
    result = run(chunks, point_a_summaries)
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import TYPE_CHECKING

from src.agents import AgentResult, AgentStatus

if TYPE_CHECKING:
    from src.agents.chunker import EventChunk

# ─── Thresholds ────────────────────────────────────────────────────────────────
RECENT_WINDOW_SEC = 3_600       # "recent" = last 1 hour
ELEVATED_DST_THRESHOLD = 3      # unique destinations → elevated
URGENT_DST_THRESHOLD = 5        # unique destinations → urgent
URGENT_REPEAT_THRESHOLD = 2     # N suspicious chunks from same entity → urgent
REQUIRED_FIELDS = {"timestamp", "user", "source_host"}


def _priority(
    chunk_summary: dict,
    entity_history: list[dict],
) -> tuple[str, float, str]:
    """Return (priority, confidence, reason) for a single chunk."""
    n_dst = chunk_summary.get("stats", {}).get("destination_host_unique", 1)
    fail_rate = chunk_summary.get("stats", {}).get("failure_rate", 0.0)
    n_events = chunk_summary.get("n_events", 1)
    entity = chunk_summary.get("entity", "")

    # Count recent suspicious chunks for this entity
    recent_suspicious = sum(
        1 for h in entity_history
        if h.get("priority") in ("urgent", "elevated")
    )

    # Urgent: repeated suspicious pattern OR extreme fan-out
    if recent_suspicious >= URGENT_REPEAT_THRESHOLD or n_dst >= URGENT_DST_THRESHOLD:
        reason = (
            f"{recent_suspicious} prior suspicious chunk(s) from {entity!r}"
            if recent_suspicious >= URGENT_REPEAT_THRESHOLD
            else f"fan-out to {n_dst} unique destinations"
        )
        return "urgent", 0.9, reason

    # Elevated: moderate fan-out OR high failure rate OR large event burst
    if n_dst >= ELEVATED_DST_THRESHOLD or fail_rate >= 0.5 or n_events >= 20:
        reason = (
            f"fail_rate={fail_rate:.0%}" if fail_rate >= 0.5
            else f"{n_dst} unique destinations" if n_dst >= ELEVATED_DST_THRESHOLD
            else f"{n_events} events in window"
        )
        return "elevated", 0.7, reason

    return "routine", 0.4, "low-signal, normal authentication pattern"


def _check_fields(chunk: "EventChunk") -> list[str]:
    """Return list of missing required fields."""
    missing = []
    for field in REQUIRED_FIELDS:
        if field not in chunk.events.columns or chunk.events[field].isna().all():
            missing.append(field)
    return missing


def run(
    chunks: list["EventChunk"],
    point_a_summaries: list[dict],
    *,
    incident_id: str = "INC-001",
) -> AgentResult:
    """Triage and annotate all chunks with priority, context, and missing-field flags.

    Returns AgentResult with:
        output["triaged"]: list of annotated chunk records
        output["escalate_count"]: number of chunks to escalate to Detection
        output["routine_count"]: number of routine chunks (deprioritized)
    """
    t0 = time.perf_counter()

    # Build a summary lookup by chunk_id
    summary_by_id = {s["chunk_id"]: s for s in point_a_summaries}

    # Track history per entity (short-term context)
    entity_history: dict[str, list[dict]] = defaultdict(list)

    triaged: list[dict] = []

    for chunk in sorted(chunks, key=lambda c: c.t_start):
        summary = summary_by_id.get(chunk.chunk_id, {})
        missing_fields = _check_fields(chunk)
        history = entity_history[chunk.entity]

        priority, conf, reason = _priority(summary, history)

        # Low-confidence flag for missing fields
        if missing_fields:
            priority = max(priority, "elevated")  # promote, never demote
            reason = f"missing fields: {missing_fields}"
            conf = min(conf, 0.5)

        record = {
            "chunk_id": chunk.chunk_id,
            "entity": chunk.entity,
            "strategy": chunk.strategy.value,
            "t_start": chunk.t_start,
            "t_end": chunk.t_end,
            "n_events": len(chunk),
            "priority": priority,
            "confidence": conf,
            "reason": reason,
            "missing_fields": missing_fields,
            "context": (
                f"{len(history)} prior chunk(s) from this entity in the last hour"
                if history else "first chunk seen from this entity"
            ),
            "point_a_text": summary.get("text", ""),
            "stats": summary.get("stats", {}),
            # Attach the DataFrame reference for Detection to score
            "_chunk_ref": chunk,
        }

        # Append to entity history for future context
        entity_history[chunk.entity].append({
            "chunk_id": chunk.chunk_id,
            "t_start": chunk.t_start,
            "priority": priority,
        })

        triaged.append(record)

    escalate = [r for r in triaged if r["priority"] in ("urgent", "elevated")]
    routine = [r for r in triaged if r["priority"] == "routine"]

    avg_conf = sum(r["confidence"] for r in triaged) / max(len(triaged), 1)

    return AgentResult(
        agent="investigation",
        status=AgentStatus.OK,
        confidence=round(avg_conf, 3),
        output={
            "incident_id": incident_id,
            "triaged": triaged,
            "escalate_count": len(escalate),
            "routine_count": len(routine),
            "total_chunks": len(triaged),
            "entities_seen": len(entity_history),
        },
        notes=[f"Triaged {len(triaged)} chunks; {len(escalate)} escalated to Detection."],
        ms=(time.perf_counter() - t0) * 1000,
    )
