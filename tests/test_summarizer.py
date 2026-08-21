"""
tests/test_summarizer.py — Unit tests for src/agents/summarizer.py

Tests Point A (chunk template strings) and Point B (fallback narrative).
LLM path is not tested here — it requires a network key and is end-to-end
verified manually.
"""
from __future__ import annotations

import pandas as pd
import pytest

from src.agents.chunker import chunk_events, ChunkStrategy
from src.agents.summarizer import summarize_chunk, summarize_incident


# ─── Fixtures ─────────────────────────────────────────────────────────────────
@pytest.fixture
def single_chunk():
    """One EventChunk representing a lateral-movement burst."""
    base = 1_700_000_000
    rows = [
        {"timestamp": base + i * 6, "user": "svc_admin",
         "source_host": "PC-01", "destination_host": f"SRV-{i:02d}",
         "event_type": "auth", "status": "success", "bytes_out": 512}
        for i in range(40)
    ]
    df = pd.DataFrame(rows)
    chunks = chunk_events(df, strategy=ChunkStrategy.TIME_WINDOW,
                          entity_col="user", window_sec=300)
    assert chunks, "Expected at least one chunk from fixture"
    return chunks[0]


@pytest.fixture
def high_failure_chunk():
    """One EventChunk with a high failure rate."""
    base = 1_700_000_000
    rows = [
        {"timestamp": base + i * 10, "user": "attacker",
         "source_host": "EXT-IP-1", "destination_host": "DC-01",
         "event_type": "auth",
         "status": "failure" if i < 18 else "success",
         "bytes_out": 0}
        for i in range(20)
    ]
    df = pd.DataFrame(rows)
    chunks = chunk_events(df, strategy=ChunkStrategy.SESSION,
                          entity_col="user", gap_sec=3600)
    assert chunks
    return chunks[0]


# ─── Point A: summarize_chunk ─────────────────────────────────────────────────
def test_summarize_chunk_returns_dict(single_chunk):
    result = summarize_chunk(single_chunk)
    assert isinstance(result, dict)


def test_summarize_chunk_required_keys(single_chunk):
    result = summarize_chunk(single_chunk)
    for key in ("chunk_id", "entity", "strategy", "t_start", "t_end",
                "n_events", "duration_sec", "text", "stats"):
        assert key in result, f"Missing key: {key!r}"


def test_summarize_chunk_text_is_string(single_chunk):
    result = summarize_chunk(single_chunk)
    assert isinstance(result["text"], str)
    assert len(result["text"]) > 10, "Point-A text too short"


def test_summarize_chunk_entity_in_text(single_chunk):
    result = summarize_chunk(single_chunk)
    assert single_chunk.entity in result["text"], (
        f"Entity {single_chunk.entity!r} not mentioned in Point-A text"
    )


def test_summarize_chunk_n_events_matches(single_chunk):
    result = summarize_chunk(single_chunk)
    assert result["n_events"] == len(single_chunk)


def test_summarize_chunk_failure_rate_mentioned(high_failure_chunk):
    result = summarize_chunk(high_failure_chunk)
    # High failure rate should be mentioned in text
    text = result["text"].lower()
    assert "fail" in text or "failure" in text, (
        f"High failure rate not mentioned in text: {result['text']!r}"
    )


def test_summarize_chunk_fanout_label(single_chunk):
    result = summarize_chunk(single_chunk)
    # svc_admin burst across many destinations → should get fan-out label
    assert "fanout_label" in result


# ─── Point B: summarize_incident ─────────────────────────────────────────────
def test_summarize_incident_template_fallback(single_chunk, high_failure_chunk):
    summaries = [summarize_chunk(single_chunk), summarize_chunk(high_failure_chunk)]
    technique_chain = ["T1078", "T1021.001", "T1059"]

    result = summarize_incident(summaries, technique_chain, use_llm=False)
    assert isinstance(result, dict)


def test_summarize_incident_required_keys(single_chunk):
    summaries = [summarize_chunk(single_chunk)]
    result = summarize_incident(summaries, ["T1078"], use_llm=False)
    for key in ("narrative", "method", "authoritative", "technique_chain", "n_chunks"):
        assert key in result, f"Missing key: {key!r}"


def test_summarize_incident_never_authoritative(single_chunk):
    summaries = [summarize_chunk(single_chunk)]
    result = summarize_incident(summaries, [], use_llm=False)
    assert result["authoritative"] is False, "Point-B output must never be authoritative"


def test_summarize_incident_template_method(single_chunk):
    summaries = [summarize_chunk(single_chunk)]
    result = summarize_incident(summaries, ["T1078"], use_llm=False)
    assert result["method"] == "template"


def test_summarize_incident_narrative_nonempty(single_chunk):
    summaries = [summarize_chunk(single_chunk)]
    result = summarize_incident(summaries, ["T1078"], use_llm=False)
    assert len(result["narrative"]) > 10, "Narrative too short"


def test_summarize_incident_n_chunks(single_chunk, high_failure_chunk):
    summaries = [summarize_chunk(single_chunk), summarize_chunk(high_failure_chunk)]
    result = summarize_incident(summaries, [], use_llm=False)
    assert result["n_chunks"] == 2


def test_summarize_incident_empty_summaries():
    result = summarize_incident([], [], use_llm=False)
    assert "narrative" in result
    assert len(result["narrative"]) > 0, "Should produce fallback text for empty input"
