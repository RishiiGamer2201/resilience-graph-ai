"""
src/agents/detection.py — Agent 2: Detection (Anomaly Scoring)

Sarthak's doc: "runs the anomaly model (Isolation Forest / autoencoder, per
existing Engine 1) on each chunk's feature vector, producing an anomaly score.
Because Investigation already attached short-term context, Detection can also
apply a lightweight context-aware threshold adjustment."

Wraps:  src/shared/detector.py  (autoencoder → IsolationForest fallback)
Input:  AgentResult from Investigation (triaged chunks)
Output: AgentResult with anomaly_score (0-100) and threshold breach flag per chunk.

Context-aware threshold rule:
  - Base threshold: 50
  - "urgent" chunk from Investigation: threshold lowered to 35
  - "elevated" chunk: threshold lowered to 42
  - "routine": base threshold 50

Usage:
    from src.agents.detection import run
    result = run(investigation_result)
"""
from __future__ import annotations

import time

import numpy as np
import pandas as pd

from src.agents import AgentResult, AgentStatus
from src.shared import detector as _det

# ─── Thresholds ────────────────────────────────────────────────────────────────
BASE_THRESHOLD = 50
THRESHOLD_BY_PRIORITY = {
    "urgent": 35,
    "elevated": 42,
    "routine": BASE_THRESHOLD,
}

# Feature columns expected by the LANL autoencoder (Engine 1).
# If a chunk's events don't have these, we fall back to a heuristic score.
LANL_FEATURES = [
    "is_fail",
    "new_dst_for_user",
    "new_src_for_user",
    "user_distinct_dst_sofar",
    "user_fail_rate_sofar",
    "dst_rarity",
    "is_ntlm",
]


def _heuristic_score(stats: dict, priority: str) -> int:
    """Fallback anomaly score when engineered features are unavailable."""
    score = 10  # baseline
    fail_rate = stats.get("failure_rate", 0.0)
    n_dst = stats.get("destination_host_unique", 1)
    n_events = stats.get("n_events", 1)

    score += int(fail_rate * 40)
    score += min(n_dst * 3, 30)
    score += min(n_events // 5, 20)

    # Priority bump from Investigation context
    if priority == "urgent":
        score += 20
    elif priority == "elevated":
        score += 10

    return min(score, 100)


def _score_chunk(chunk_ref, stats: dict, priority: str) -> tuple[int, str]:
    """Score one chunk. Returns (score_0_100, method)."""
    events = chunk_ref.events if chunk_ref is not None else pd.DataFrame()

    # Check if engineered LANL features are present
    has_features = not events.empty and all(f in events.columns for f in LANL_FEATURES)

    if has_features and _det.available():
        feat_mat = events[LANL_FEATURES].fillna(0).values.astype(float)
        ref = _det.anchors()
        if ref:
            scores = _det.scores_0_100(feat_mat, ref)
        else:
            raw = _det.raw_scores(feat_mat)
            # No calibration anchors: normalize linearly to 0-100
            r_min, r_max = float(raw.min()), float(raw.max())
            scores = ((raw - r_min) / max(r_max - r_min, 1e-9)) * 100
        score = int(float(scores.max()))
        method = "autoencoder"
    else:
        score = _heuristic_score(stats, priority)
        method = "heuristic"

    return score, method


def run(investigation_result: AgentResult) -> AgentResult:
    """Score all escalated chunks from Investigation with context-aware thresholds.

    Routine chunks receive heuristic baseline scores (not passed to autoencoder
    for efficiency); only urgent/elevated chunks use the full model.

    Returns AgentResult with:
        output["scored"]: list of chunk records with anomaly_score + flagged bool
        output["flagged_count"]: number of chunks above threshold
        output["max_score"]: highest anomaly score seen
    """
    t0 = time.perf_counter()

    triaged: list[dict] = investigation_result.output.get("triaged", [])
    if not triaged:
        return AgentResult(
            agent="detection",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            notes=["No triaged chunks received from Investigation."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    scored: list[dict] = []
    max_score = 0

    for record in triaged:
        priority = record.get("priority", "routine")
        stats = record.get("stats", {})
        chunk_ref = record.get("_chunk_ref")

        # Only run full model on non-routine chunks (efficiency)
        if priority in ("urgent", "elevated"):
            score, method = _score_chunk(chunk_ref, stats, priority)
        else:
            score = _heuristic_score(stats, "routine")
            method = "heuristic"

        threshold = THRESHOLD_BY_PRIORITY.get(priority, BASE_THRESHOLD)
        flagged = score >= threshold
        max_score = max(max_score, score)

        scored.append({
            "chunk_id": record["chunk_id"],
            "entity": record["entity"],
            "strategy": record["strategy"],
            "t_start": record["t_start"],
            "t_end": record["t_end"],
            "priority": priority,
            "anomaly_score": score,
            "threshold": threshold,
            "flagged": flagged,
            "score_method": method,
            "context": record.get("context", ""),
            "point_a_text": record.get("point_a_text", ""),
            "stats": stats,
            "_chunk_ref": chunk_ref,
        })

    flagged_chunks = [c for c in scored if c["flagged"]]
    overall_conf = min(1.0, max_score / 100) if max_score else 0.0

    return AgentResult(
        agent="detection",
        status=AgentStatus.OK if flagged_chunks else AgentStatus.DEGRADED,
        confidence=round(overall_conf, 3),
        output={
            "scored": scored,
            "flagged_count": len(flagged_chunks),
            "total_scored": len(scored),
            "max_score": max_score,
        },
        notes=[
            f"Scored {len(scored)} chunks; {len(flagged_chunks)} above threshold.",
            f"Max anomaly score: {max_score}/100.",
        ],
        ms=(time.perf_counter() - t0) * 1000,
    )
