"""
src/agents/chunker.py — Multi-strategy event log chunker.

Sarthak's doc: "Since your logs are structured events, not prose, you don't
chunk by 'similar words' the way a RAG system chunks a PDF. You chunk by time
and entity, so patterns become visible."

Three strategies:
  1. Time-Window:  Rolling fixed-width windows (default 5 min) per entity.
                   Exposes high-frequency bursts: "40 logins in 5 minutes".
  2. Session:      Groups all events in one auth session (gap > SESSION_GAP_SEC
                   starts a new session). Exposes full session lifecycle.
  3. Entity:       All events for a single host/user across the full range.
                   Exposes lateral movement sequences.

Usage:
    from src.agents.chunker import chunk_events, ChunkStrategy, EventChunk
    chunks = chunk_events(events_df, strategy=ChunkStrategy.TIME_WINDOW)
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator

import pandas as pd


# ─── Configuration ────────────────────────────────────────────────────────────
TIME_WINDOW_SEC: int = 300      # 5-minute rolling windows (doc example: 5–15 min)
SESSION_GAP_SEC: int = 3_600    # >1h silence → new session
MIN_CHUNK_EVENTS: int = 2       # drop singleton chunks (not a pattern)


class ChunkStrategy(str, Enum):
    TIME_WINDOW = "time_window"
    SESSION = "session"
    ENTITY = "entity"


# ─── Data model ───────────────────────────────────────────────────────────────
@dataclass
class EventChunk:
    """A group of related events, ready for Point-A summarization + anomaly scoring.

    Attributes:
        chunk_id:   stable SHA-256 fingerprint of (entity, t_start, strategy)
        strategy:   which chunking strategy produced this chunk
        entity:     primary grouping key (username or hostname)
        t_start:    epoch seconds of first event
        t_end:      epoch seconds of last event
        events:     slice of the normalized event DataFrame
        stats:      pre-aggregated feature statistics (used by Point-A summarizer)
    """
    chunk_id: str
    strategy: ChunkStrategy
    entity: str
    t_start: int
    t_end: int
    events: pd.DataFrame
    stats: dict = field(default_factory=dict)

    def duration_sec(self) -> int:
        return max(1, self.t_end - self.t_start)

    def __len__(self) -> int:
        return len(self.events)


# ─── Internal helpers ─────────────────────────────────────────────────────────
def _chunk_id(entity: str, t_start: int, strategy: ChunkStrategy) -> str:
    raw = f"{entity}:{t_start}:{strategy.value}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _compute_stats(df: pd.DataFrame) -> dict:
    """Aggregate numeric + categorical statistics used by the Point-A summarizer."""
    n = len(df)
    stats: dict = {"n_events": n}

    for col, agg in [
        ("destination_host", "nunique"),
        ("source_host", "nunique"),
        ("user", "nunique"),
        ("status", None),
        ("event_type", None),
        ("protocol", None),
        ("bytes_out", "sum"),
        ("port", "nunique"),
    ]:
        if col not in df.columns:
            continue
        series = df[col]
        if agg == "nunique":
            stats[f"{col}_unique"] = int(series.nunique())
        elif agg == "sum":
            stats[f"{col}_total"] = int(pd.to_numeric(series, errors="coerce").fillna(0).sum())
        else:  # None → value_counts
            vc = series.value_counts().head(3).to_dict()
            stats[f"{col}_top"] = {str(k): int(v) for k, v in vc.items()}

    # Failure rate. The canonical status vocabulary from src.shared.normalize is
    # "success" / "fail" -- this tested for "failure", which no source emits, so
    # failure_rate was 0.0 for every chunk ever produced. Detection scoring,
    # Investigation triage, the Point-A summary text and the T1110 brute-force
    # rule all read it, so all four were blind to 217 failed logins in the LANL
    # demo slice alone. Match any status that starts with "fail".
    if "status" in df.columns:
        st = df["status"].astype(str).str.lower()
        n_fail = int(st.str.startswith("fail").sum())
        stats["failure_rate"] = round(n_fail / max(n, 1), 3)
        stats["n_failures"] = n_fail
        stats["n_successes"] = n - n_fail

    # NTLM share. 100% of LANL red-team logins used NTLM against 30% of benign in
    # this slice, and the published ablation puts ROC at 0.992 with the signal
    # and 0.906 without it. The agent lane could not see it at all because
    # protocol was never aggregated, which is why it never reached the
    # ntlm_lateral_movement rule that already existed in the table.
    if "protocol" in df.columns:
        pr = df["protocol"].astype(str).str.upper()
        stats["ntlm_rate"] = round(int((pr == "NTLM").sum()) / max(n, 1), 3)

    # Avg bytes if present
    if "bytes_out" in df.columns:
        bvals = pd.to_numeric(df["bytes_out"], errors="coerce").dropna()
        stats["bytes_out_avg"] = int(bvals.mean()) if len(bvals) else 0

    return stats


# ─── Strategy implementations ─────────────────────────────────────────────────
def _time_window_chunks(
    df: pd.DataFrame,
    entity_col: str,
    window_sec: int,
) -> Iterator[EventChunk]:
    """Yield rolling fixed-width windows per entity.

    Example: entity='svc_admin', window=300s → chunk 'svc_admin 09:00–09:05'
    """
    if entity_col not in df.columns or df.empty:
        return

    for entity, grp in df.groupby(entity_col, sort=False):
        grp = grp.sort_values("timestamp").reset_index(drop=True)
        if grp.empty:
            continue
        t_min = int(grp["timestamp"].iloc[0])
        t_max = int(grp["timestamp"].iloc[-1])

        # Bucket by integer division instead of walking the time axis.
        #
        # The previous loop stepped `t` from t_min to t_max in window_sec
        # increments FOR EVERY ENTITY, running a full boolean mask over that
        # entity's rows at each step. Its cost scaled with the log's DURATION,
        # not its event count, so a campaign spanning weeks burned millions of
        # empty windows: 125 events chunked in 0.05 s while 2,732 events spanning
        # a longer period took 30 s. Same chunks out, one grouped pass in.
        buckets = (grp["timestamp"] - t_min) // window_sec
        for bucket, sub in grp.groupby(buckets, sort=True):
            t = t_min + int(bucket) * window_sec
            window_end = t + window_sec
            sub = sub.reset_index(drop=True)
            if len(sub) >= MIN_CHUNK_EVENTS:
                yield EventChunk(
                    chunk_id=_chunk_id(str(entity), t, ChunkStrategy.TIME_WINDOW),
                    strategy=ChunkStrategy.TIME_WINDOW,
                    entity=str(entity),
                    t_start=t,
                    t_end=min(int(sub["timestamp"].max()), window_end - 1),
                    events=sub,
                    stats=_compute_stats(sub),
                )
            t += window_sec


def _session_chunks(
    df: pd.DataFrame,
    entity_col: str,
    gap_sec: int,
) -> Iterator[EventChunk]:
    """Yield one chunk per auth session (gap > gap_sec starts a new session).

    Captures full lifecycle: auth → commands → logoff.
    """
    if entity_col not in df.columns or df.empty:
        return

    for entity, grp in df.groupby(entity_col, sort=False):
        grp = grp.sort_values("timestamp").reset_index(drop=True)
        if grp.empty:
            continue

        session_rows: list[int] = []
        prev_ts: int | None = None

        for idx, row in grp.iterrows():
            ts = int(row["timestamp"])
            if prev_ts is not None and (ts - prev_ts) > gap_sec:
                # flush current session
                if len(session_rows) >= MIN_CHUNK_EVENTS:
                    sub = grp.loc[session_rows].reset_index(drop=True)
                    yield EventChunk(
                        chunk_id=_chunk_id(str(entity), int(sub["timestamp"].iloc[0]), ChunkStrategy.SESSION),
                        strategy=ChunkStrategy.SESSION,
                        entity=str(entity),
                        t_start=int(sub["timestamp"].iloc[0]),
                        t_end=int(sub["timestamp"].iloc[-1]),
                        events=sub,
                        stats=_compute_stats(sub),
                    )
                session_rows = []
            session_rows.append(idx)
            prev_ts = ts

        # flush last session
        if len(session_rows) >= MIN_CHUNK_EVENTS:
            sub = grp.loc[session_rows].reset_index(drop=True)
            yield EventChunk(
                chunk_id=_chunk_id(str(entity), int(sub["timestamp"].iloc[0]), ChunkStrategy.SESSION),
                strategy=ChunkStrategy.SESSION,
                entity=str(entity),
                t_start=int(sub["timestamp"].iloc[0]),
                t_end=int(sub["timestamp"].iloc[-1]),
                events=sub,
                stats=_compute_stats(sub),
            )


def _entity_chunks(
    df: pd.DataFrame,
    entity_col: str,
) -> Iterator[EventChunk]:
    """Yield one chunk per entity spanning the entire time range.

    Exposes lateral movement: same user touching many hosts sequentially.
    """
    if entity_col not in df.columns or df.empty:
        return

    for entity, grp in df.groupby(entity_col, sort=False):
        grp = grp.sort_values("timestamp").reset_index(drop=True)
        if len(grp) < MIN_CHUNK_EVENTS:
            continue
        yield EventChunk(
            chunk_id=_chunk_id(str(entity), int(grp["timestamp"].iloc[0]), ChunkStrategy.ENTITY),
            strategy=ChunkStrategy.ENTITY,
            entity=str(entity),
            t_start=int(grp["timestamp"].iloc[0]),
            t_end=int(grp["timestamp"].iloc[-1]),
            events=grp,
            stats=_compute_stats(grp),
        )


# ─── Public API ───────────────────────────────────────────────────────────────
import logging

log = logging.getLogger("agents.chunker")


def chunk_events(
    events: pd.DataFrame,
    *,
    strategy: ChunkStrategy = ChunkStrategy.TIME_WINDOW,
    entity_col: str = "user",
    window_sec: int = TIME_WINDOW_SEC,
    gap_sec: int = SESSION_GAP_SEC,
) -> list[EventChunk]:
    """Chunk a normalized event DataFrame into EventChunk objects.

    Args:
        events:     Normalized DataFrame (src/schema.py columns).
        strategy:   ChunkStrategy.TIME_WINDOW | SESSION | ENTITY
        entity_col: Which column to group by ('user' or 'source_host').
        window_sec: Time-window width in seconds (TIME_WINDOW only).
        gap_sec:    Max intra-session gap in seconds (SESSION only).

    Returns:
        List of EventChunk, sorted by t_start ascending.
    """
    if "timestamp" not in events.columns:
        raise ValueError("events DataFrame must have a 'timestamp' column")

    t0 = time.perf_counter()

    if strategy == ChunkStrategy.TIME_WINDOW:
        chunks = list(_time_window_chunks(events, entity_col, window_sec))
    elif strategy == ChunkStrategy.SESSION:
        chunks = list(_session_chunks(events, entity_col, gap_sec))
    elif strategy == ChunkStrategy.ENTITY:
        chunks = list(_entity_chunks(events, entity_col))
    else:
        raise ValueError(f"Unknown strategy: {strategy!r}")

    chunks.sort(key=lambda c: c.t_start)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    # Log without importing logging to avoid side effects at import time
    log.debug(f"[chunker] strategy={strategy.value} entity_col={entity_col!r} "
          f"-> {len(chunks)} chunks in {elapsed_ms:.0f}ms")
    return chunks


def chunk_all_strategies(
    events: pd.DataFrame,
    *,
    entity_col: str = "user",
) -> dict[str, list[EventChunk]]:
    """Run all three strategies and return a dict keyed by strategy name.

    Useful for the Investigation Agent, which selects the best view per entity.
    """
    return {
        ChunkStrategy.TIME_WINDOW.value: chunk_events(events, strategy=ChunkStrategy.TIME_WINDOW, entity_col=entity_col),
        ChunkStrategy.SESSION.value: chunk_events(events, strategy=ChunkStrategy.SESSION, entity_col=entity_col),
        ChunkStrategy.ENTITY.value: chunk_events(events, strategy=ChunkStrategy.ENTITY, entity_col=entity_col),
    }
