"""
tests/test_chunker.py — Unit tests for src/agents/chunker.py

Tests all three chunking strategies against a minimal synthetic DataFrame that
covers the documented patterns: time-window bursts, session gaps, entity fan-out.
"""
from __future__ import annotations

import pandas as pd
import pytest

from src.agents.chunker import (
    ChunkStrategy,
    EventChunk,
    chunk_events,
    chunk_all_strategies,
    SESSION_GAP_SEC,
    TIME_WINDOW_SEC,
    MIN_CHUNK_EVENTS,
)


# ─── Fixture ──────────────────────────────────────────────────────────────────
@pytest.fixture
def auth_events() -> pd.DataFrame:
    """Minimal normalized event DataFrame covering 3 users."""
    rows = []
    base = 1_700_000_000  # arbitrary epoch

    # User A: burst of 10 events in 60 seconds (time-window + session)
    for i in range(10):
        rows.append({
            "timestamp": base + i * 6,
            "user": "U_A",
            "source_host": "PC-01",
            "destination_host": f"SRV-{i:02d}",
            "event_type": "auth",
            "status": "success",
            "bytes_out": 512,
        })

    # User A: second session after a 2-hour gap (session chunking must split here)
    gap = SESSION_GAP_SEC + 100
    for i in range(5):
        rows.append({
            "timestamp": base + gap + i * 10,
            "user": "U_A",
            "source_host": "PC-01",
            "destination_host": "DC-01",
            "event_type": "auth",
            "status": "failure",
            "bytes_out": 0,
        })

    # User B: lateral movement across 6 hosts over 30 minutes
    for i in range(6):
        rows.append({
            "timestamp": base + i * 300,
            "user": "U_B",
            "source_host": f"HOST-{i:02d}",
            "destination_host": f"HOST-{i+1:02d}",
            "event_type": "auth",
            "status": "success",
            "bytes_out": 1024,
        })

    # User C: singleton (should be filtered by MIN_CHUNK_EVENTS in entity mode)
    rows.append({
        "timestamp": base + 9999,
        "user": "U_C",
        "source_host": "PC-99",
        "destination_host": "SRV-99",
        "event_type": "auth",
        "status": "success",
        "bytes_out": 256,
    })

    return pd.DataFrame(rows)


# ─── Time-window tests ────────────────────────────────────────────────────────
def test_time_window_produces_chunks(auth_events):
    chunks = chunk_events(auth_events, strategy=ChunkStrategy.TIME_WINDOW,
                          entity_col="user", window_sec=TIME_WINDOW_SEC)
    assert len(chunks) >= 1, "Expected at least one time-window chunk"


def test_time_window_chunk_type(auth_events):
    chunks = chunk_events(auth_events, strategy=ChunkStrategy.TIME_WINDOW, entity_col="user")
    for c in chunks:
        assert isinstance(c, EventChunk)
        assert c.strategy == ChunkStrategy.TIME_WINDOW


def test_time_window_event_count(auth_events):
    chunks = chunk_events(auth_events, strategy=ChunkStrategy.TIME_WINDOW,
                          entity_col="user", window_sec=TIME_WINDOW_SEC)
    # User A's burst of 10 events in 60s should all land in 1 or 2 windows
    ua_chunks = [c for c in chunks if c.entity == "U_A" and c.t_end - c.t_start < TIME_WINDOW_SEC]
    total_ua_events = sum(len(c) for c in ua_chunks)
    assert total_ua_events >= 5, f"Expected ≥5 events from U_A burst, got {total_ua_events}"


def test_time_window_stats_populated(auth_events):
    chunks = chunk_events(auth_events, strategy=ChunkStrategy.TIME_WINDOW, entity_col="user")
    for c in chunks:
        assert "n_events" in c.stats
        assert c.stats["n_events"] == len(c)


# ─── Session tests ────────────────────────────────────────────────────────────
def test_session_splits_on_gap(auth_events):
    chunks = chunk_events(auth_events, strategy=ChunkStrategy.SESSION,
                          entity_col="user", gap_sec=SESSION_GAP_SEC)
    ua_chunks = [c for c in chunks if c.entity == "U_A"]
    # U_A has two sessions separated by >SESSION_GAP_SEC
    assert len(ua_chunks) >= 2, (
        f"Expected U_A to produce ≥2 session chunks (gap={SESSION_GAP_SEC}s), "
        f"got {len(ua_chunks)}"
    )


def test_session_chunks_non_overlapping(auth_events):
    chunks = chunk_events(auth_events, strategy=ChunkStrategy.SESSION, entity_col="user")
    by_entity: dict[str, list] = {}
    for c in chunks:
        by_entity.setdefault(c.entity, []).append(c)
    for entity, ecs in by_entity.items():
        ecs.sort(key=lambda x: x.t_start)
        for i in range(len(ecs) - 1):
            assert ecs[i].t_end < ecs[i + 1].t_start, (
                f"Overlapping session chunks for {entity}"
            )


# ─── Entity tests ─────────────────────────────────────────────────────────────
def test_entity_one_chunk_per_user(auth_events):
    chunks = chunk_events(auth_events, strategy=ChunkStrategy.ENTITY, entity_col="user")
    entities = [c.entity for c in chunks]
    # Each entity should appear at most once
    assert len(entities) == len(set(entities)), "Duplicate entity chunks found"


def test_entity_excludes_singletons(auth_events):
    chunks = chunk_events(auth_events, strategy=ChunkStrategy.ENTITY, entity_col="user")
    # U_C has only 1 event — should be filtered
    uc_chunks = [c for c in chunks if c.entity == "U_C"]
    assert len(uc_chunks) == 0, "Singleton entity U_C should be filtered"


def test_entity_chunk_covers_full_range(auth_events):
    chunks = chunk_events(auth_events, strategy=ChunkStrategy.ENTITY, entity_col="user")
    for c in chunks:
        assert c.t_end >= c.t_start


# ─── chunk_all_strategies ─────────────────────────────────────────────────────
def test_chunk_all_strategies_returns_three_keys(auth_events):
    result = chunk_all_strategies(auth_events, entity_col="user")
    assert set(result.keys()) == {"time_window", "session", "entity"}


def test_chunk_all_strategies_all_event_chunks(auth_events):
    result = chunk_all_strategies(auth_events, entity_col="user")
    for strategy, chunks in result.items():
        for c in chunks:
            assert isinstance(c, EventChunk), f"{strategy}: got non-EventChunk"


# ─── Edge cases ───────────────────────────────────────────────────────────────
def test_empty_dataframe_returns_no_chunks():
    empty = pd.DataFrame(columns=["timestamp", "user", "source_host",
                                   "destination_host", "event_type", "status", "bytes_out"])
    for strategy in ChunkStrategy:
        chunks = chunk_events(empty, strategy=strategy, entity_col="user")
        assert chunks == [], f"Expected [] for empty DataFrame with {strategy}"


def test_missing_timestamp_raises():
    df = pd.DataFrame({"user": ["A"], "event_type": ["auth"]})
    with pytest.raises(ValueError, match="timestamp"):
        chunk_events(df, strategy=ChunkStrategy.TIME_WINDOW)
