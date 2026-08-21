"""
tests/test_10_agents.py — Integration tests for the full 10-agent pipeline.

Tests:
  1. Individual agent contract compliance (AgentResult shape)
  2. Orchestrator hard gates (schema enforcement, consistency)
  3. Full pipeline end-to-end on synthetic data (no file I/O required)

These tests use synthetic event data only — no scenario parquets needed.
"""
from __future__ import annotations

import re

import pandas as pd
import pytest

from src.agents import AgentResult, AgentStatus

# ─── Shared synthetic fixture ─────────────────────────────────────────────────
@pytest.fixture
def synthetic_events() -> pd.DataFrame:
    """Synthetic auth events covering lateral movement and brute-force patterns."""
    base = 1_700_000_000
    rows = []

    # svc_admin: lateral movement burst (10 destinations in 60 seconds)
    for i in range(10):
        rows.append({
            "timestamp": base + i * 6,
            "user": "svc_admin",
            "source_host": "PC-01",
            "destination_host": f"SRV-{i:02d}",
            "event_type": "auth",
            "status": "success",
            "bytes_out": 1024,
            "protocol": "kerberos",
            "port": 445,
            "asset_criticality": "high" if i < 2 else "medium",
            "label": 1,
        })

    # attacker: brute-force (15 failures then 1 success)
    for i in range(16):
        rows.append({
            "timestamp": base + 300 + i * 3,
            "user": "attacker",
            "source_host": "EXT-192.168.99.1",
            "destination_host": "DC-01",
            "event_type": "auth",
            "status": "failure" if i < 15 else "success",
            "bytes_out": 0,
            "protocol": "ntlm",
            "port": 389,
            "asset_criticality": "critical",
            "label": 1,
        })

    # normal_user: benign, routine auth (not enough to be anomalous)
    for i in range(3):
        rows.append({
            "timestamp": base + 1000 + i * 60,
            "user": "normal_user",
            "source_host": "PC-10",
            "destination_host": "FILE-SRV-01",
            "event_type": "auth",
            "status": "success",
            "bytes_out": 256,
            "protocol": "kerberos",
            "port": 445,
            "asset_criticality": "low",
            "label": 0,
        })

    return pd.DataFrame(rows)


# ─── AgentResult contract tests ───────────────────────────────────────────────
def test_agent_result_as_dict():
    r = AgentResult(agent="test", status=AgentStatus.OK, confidence=0.8,
                    output={"foo": "bar"}, evidence_refs=["T1078"], ms=42.0)
    d = r.as_dict()
    assert d["agent"] == "test"
    assert d["status"] == "ok"
    assert d["confidence"] == 0.8
    assert "T1078" in d["evidence_refs"]


# ─── Agent 1: Investigation ───────────────────────────────────────────────────
def test_investigation_agent(synthetic_events):
    from src.agents.chunker import chunk_events, ChunkStrategy
    from src.agents.summarizer import summarize_chunk
    from src.agents import investigation

    chunks = chunk_events(synthetic_events, strategy=ChunkStrategy.TIME_WINDOW,
                          entity_col="user", window_sec=300)
    summaries = [summarize_chunk(c) for c in chunks]
    result = investigation.run(chunks, summaries)

    assert isinstance(result, AgentResult)
    assert result.agent == "investigation"
    assert result.status in (AgentStatus.OK, AgentStatus.DEGRADED)
    assert "triaged" in result.output
    assert "escalate_count" in result.output


def test_investigation_produces_priorities(synthetic_events):
    from src.agents.chunker import chunk_events, ChunkStrategy
    from src.agents.summarizer import summarize_chunk
    from src.agents import investigation

    chunks = chunk_events(synthetic_events, strategy=ChunkStrategy.TIME_WINDOW,
                          entity_col="user", window_sec=300)
    summaries = [summarize_chunk(c) for c in chunks]
    result = investigation.run(chunks, summaries)

    priorities = {r["priority"] for r in result.output["triaged"]}
    assert priorities <= {"routine", "elevated", "urgent"}, f"Unknown priority: {priorities}"


# ─── Agent 2: Detection ───────────────────────────────────────────────────────
def test_detection_agent(synthetic_events):
    from src.agents.chunker import chunk_events, ChunkStrategy
    from src.agents.summarizer import summarize_chunk
    from src.agents import investigation, detection

    chunks = chunk_events(synthetic_events, strategy=ChunkStrategy.TIME_WINDOW,
                          entity_col="user", window_sec=300)
    summaries = [summarize_chunk(c) for c in chunks]
    inv_res = investigation.run(chunks, summaries)
    det_res = detection.run(inv_res)

    assert isinstance(det_res, AgentResult)
    assert det_res.agent == "detection"
    assert "scored" in det_res.output
    for item in det_res.output["scored"]:
        assert 0 <= item["anomaly_score"] <= 100
        assert isinstance(item["flagged"], bool)


# ─── Agent 3: Intelligence ────────────────────────────────────────────────────
def test_intelligence_no_hallucinated_ids(synthetic_events):
    from src.agents.chunker import chunk_events, ChunkStrategy
    from src.agents.summarizer import summarize_chunk
    from src.agents import investigation, detection, intelligence

    chunks = chunk_events(synthetic_events, strategy=ChunkStrategy.TIME_WINDOW,
                          entity_col="user", window_sec=300)
    summaries = [summarize_chunk(c) for c in chunks]
    inv_res = investigation.run(chunks, summaries)
    det_res = detection.run(inv_res)
    int_res = intelligence.run(det_res)

    attack_id_re = re.compile(r"^T\d{4}(\.\d{3})?$")
    for m in int_res.output.get("mapped", []):
        tid = m.get("technique_id")
        if tid is not None:
            assert attack_id_re.match(str(tid)), (
                f"Hallucinated ATT&CK ID: {tid!r}"
            )


# ─── Full 10-Agent Pipeline (Orchestrator) ────────────────────────────────────
def test_full_pipeline_runs(synthetic_events):
    from src.agents.orchestrator import run_pipeline, PipelineResult

    result = run_pipeline(synthetic_events, scenario="test_synthetic",
                          incident_id="INC-TEST", use_llm=False)

    assert isinstance(result, PipelineResult)
    assert result.incident_id == "INC-TEST"
    assert result.scenario == "test_synthetic"


def test_pipeline_produces_10_agent_traces(synthetic_events):
    from src.agents.orchestrator import run_pipeline

    result = run_pipeline(synthetic_events, use_llm=False)
    agent_names = {t["agent"] for t in result.agent_traces}
    expected = {"investigation", "detection", "intelligence",
                "graph_observer", "kb_connector", "validator",
                "prioritizer", "reasoner", "prediction"}
    missing = expected - agent_names
    assert not missing, f"Missing agent traces: {missing}"


def test_pipeline_no_failed_agents(synthetic_events):
    from src.agents.orchestrator import run_pipeline

    result = run_pipeline(synthetic_events, use_llm=False)
    failed = [t for t in result.agent_traces if t["status"] == "failed"]
    assert not failed, f"Agents failed: {[f['agent'] for f in failed]}"


def test_pipeline_narrative_nonempty(synthetic_events):
    from src.agents.orchestrator import run_pipeline

    result = run_pipeline(synthetic_events, use_llm=False)
    assert isinstance(result.incident_narrative, str)
    assert len(result.incident_narrative) > 10


def test_pipeline_severity_valid(synthetic_events):
    from src.agents.orchestrator import run_pipeline

    result = run_pipeline(synthetic_events, use_llm=False)
    assert result.severity in ("critical", "high", "medium", "low")


def test_pipeline_no_invalid_attack_ids(synthetic_events):
    from src.agents.orchestrator import run_pipeline

    result = run_pipeline(synthetic_events, use_llm=False)
    attack_re = re.compile(r"^T\d{4}(\.\d{3})?$")
    for ref in result.evidence_refs:
        if ref.startswith("T"):
            assert attack_re.match(ref), f"Invalid ATT&CK ID in pipeline output: {ref!r}"


def test_pipeline_as_dict_serializable(synthetic_events):
    import json
    from src.agents.orchestrator import run_pipeline

    result = run_pipeline(synthetic_events, use_llm=False)
    d = result.as_dict()
    # Must be JSON-serializable (no DataFrames, no nx.Graph objects)
    json.dumps(d)  # raises if not serializable


def test_pipeline_status_valid(synthetic_events):
    from src.agents.orchestrator import run_pipeline

    result = run_pipeline(synthetic_events, use_llm=False)
    assert result.status in ("ok", "partial", "failed")
