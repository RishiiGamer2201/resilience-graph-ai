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
# The column the orchestrator attaches when it scores the whole log up front.
SCORE_COLUMN = "_event_anomaly_score"

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


def _heuristic_score(stats: dict, priority: str) -> tuple[int, dict]:
    """Arithmetic over chunk aggregates. NOT a detection, and never labelled one.

    Returns (score, terms) so the number can be shown with the sum that produced
    it. This runs only when the per-event model features are unavailable.

    The Investigation priority no longer adds to the score. It already LOWERS
    the threshold this score is compared against (50 -> 42 -> 35), so adding 10
    or 20 on top applied the same context twice: an urgent chunk was pushed up
    and the bar was pulled down for the same reason. A chunk scoring 30 on its
    own behaviour cleared a 35 threshold at 50 with the bump -- flagged on
    context alone, with the arithmetic hidden inside a single number.
    """
    fail_rate = float(stats.get("failure_rate", 0.0) or 0.0)
    n_dst = int(stats.get("destination_host_unique", 1) or 1)
    n_events = int(stats.get("n_events", 1) or 1)

    terms = {
        "baseline": 10,
        "failure_rate": int(fail_rate * 40),
        "destination_fan_out": min(n_dst * 3, 30),
        "volume": min(n_events // 5, 20),
    }
    score = min(sum(terms.values()), 100)
    return score, {**terms, "total": score,
                   "priority_applied_to": "threshold only, not the score"}


def _score_chunk(chunk_ref, stats: dict, priority: str
                 ) -> tuple[int, str, dict]:
    """Score one chunk. Returns (score_0_100, method, evidence).

    `evidence` is what the score is made of: for the model path, the top
    contributing events with their own scores and the features that produced
    them; for the heuristic path, the arithmetic terms. A chunk finding that
    cannot be traced back to events is an assertion, not evidence, and this lane
    is advisory precisely because its claims are supposed to be checkable.
    """
    events = chunk_ref.events if chunk_ref is not None else pd.DataFrame()

    # Preferred path: per-event scores already produced for the whole log by the
    # same calibrated function the workflow lane uses. The chunk score is the
    # max over its own events, so a chunk is as anomalous as its most anomalous
    # event and the two lanes cannot disagree about that event.
    if not events.empty and SCORE_COLUMN in events.columns:
        per_event = pd.to_numeric(events[SCORE_COLUMN], errors="coerce")
        usable = per_event.notna()
        if usable.any():
            score = int(round(float(per_event[usable].max())))
            order = per_event.fillna(-1).to_numpy().argsort()[::-1][:3]
            top = []
            for i in order:
                if not bool(usable.iloc[int(i)]):
                    continue
                row = events.iloc[int(i)]
                top.append({
                    "index": int(events.index[int(i)]),
                    "score": int(round(float(per_event.iloc[int(i)]))),
                    "user": str(row.get("user", "")),
                    "source_host": str(row.get("source_host", "")),
                    "destination_host": str(row.get("destination_host", "")),
                    "features": {f: float(row.get(f, 0) or 0)
                                 for f in LANL_FEATURES if f in events.columns},
                })
            return score, "autoencoder", {
                "method": "autoencoder",
                "calibration": ("whole-log, shared with the workflow lane "
                                "(src.shared.live_analyze._score)"),
                "events_scored": int(usable.sum()),
                "events_unscorable": int((~usable).sum()),
                "aggregation": "max over the chunk's per-event scores",
                "top_events": top,
            }

    has_features = not events.empty and all(f in events.columns for f in LANL_FEATURES)

    if has_features and _det.available():
        feat_mat = events[LANL_FEATURES].fillna(0).values.astype(float)
        finite = np.isfinite(feat_mat).all(axis=1)
        if not finite.any():
            score, terms = _heuristic_score(stats, priority)
            return score, "heuristic", {"method": "heuristic",
                                        "why": "no fully-scorable events in chunk",
                                        "terms": terms}
        ref = _det.anchors()
        if ref:
            scores = _det.scores_0_100(feat_mat, ref)
            calibration = "shipped anchors"
        else:
            raw = _det.raw_scores(feat_mat)
            r_min, r_max = float(raw.min()), float(raw.max())
            scores = ((raw - r_min) / max(r_max - r_min, 1e-9)) * 100
            # Named, because a within-chunk rescale is a RANKING and pins the
            # top event of every chunk at 100 whatever it contains.
            calibration = "within-chunk rescale (no anchors available)"
        scores = np.where(finite, scores, 0.0)
        score = int(float(scores.max()))
        order = np.argsort(scores)[::-1][:3]
        top = []
        for i in order:
            if not finite[i]:
                continue
            row = events.iloc[int(i)]
            top.append({
                "index": int(events.index[int(i)]),
                "score": int(round(float(scores[int(i)]))),
                "user": str(row.get("user", "")),
                "source_host": str(row.get("source_host", "")),
                "destination_host": str(row.get("destination_host", "")),
                "features": {f: float(row.get(f, 0) or 0) for f in LANL_FEATURES},
            })
        return score, "autoencoder", {
            "method": "autoencoder",
            "detector": _det.which() if hasattr(_det, "which") else "autoencoder",
            "calibration": calibration,
            "events_scored": int(finite.sum()),
            "events_unscorable": int((~finite).sum()),
            "aggregation": "max over the chunk's per-event scores",
            "top_events": top,
        }

    score, terms = _heuristic_score(stats, priority)
    return score, "heuristic", {
        "method": "heuristic",
        # Stated in full, because this is arithmetic over aggregates and must
        # never be reported as, or mistaken for, a learned detection.
        "why": ("the engineered per-event features were not available for this "
                "chunk, so no model scored it"),
        "not_a_model": True,
        "terms": terms,
    }


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

        # Every chunk goes to the model when the model can score it. The
        # "routine chunks skip the model for efficiency" rule meant the lane's
        # quietest chunks were judged by a different method than its loud ones,
        # so a routine chunk's score and an urgent chunk's score were not
        # comparable -- and they are ranked against each other downstream.
        score, method, contributors = _score_chunk(chunk_ref, stats, priority)

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
            # What the chunk score is made of. A chunk finding that cannot be
            # traced to the events under it is an assertion, not evidence.
            "score_evidence": contributors,
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
