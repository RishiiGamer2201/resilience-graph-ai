"""The two pipelines, and what their agreement is allowed to be worth.

Two analyses of the same log now exist. The rule this file enforces is that the
workflow governs, the agent lane is advisory, and agreement between them buys
LESS confidence than genuinely independent telemetry would — because they read
the same log through the same rule table.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.shared.crosscheck import MAX_CORROBORATION, as_evidence, crosscheck

ANALYST = {"X-Role": "analyst"}


def wf(severity: str, techniques: list[str]) -> dict:
    return {"signals": {"incident": {"severity": severity,
                                     "technique_ids": techniques}}}


def agent(severity: str, refs: list[str], degraded: list[str] | None = None) -> dict:
    return {"status": "ok", "severity": severity, "evidence_refs": refs,
            "agent_traces": [{"agent": a, "status": "degraded"}
                             for a in (degraded or [])]}


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# --------------------------------------------------------------------------- #
# verdicts                                                                     #
# --------------------------------------------------------------------------- #
def test_matching_severity_and_shared_technique_corroborates():
    cc = crosscheck(wf("high", ["T1078", "T1021"]), agent("high", ["T1021"]))
    assert cc["verdict"] == "corroborates"
    assert cc["corroboration_strength"] == MAX_CORROBORATION


def test_adjacent_severity_only_partially_corroborates():
    cc = crosscheck(wf("high", ["T1021"]), agent("medium", ["T1021"]))
    assert cc["verdict"] == "partially corroborates"
    assert 0 < cc["corroboration_strength"] < MAX_CORROBORATION


def test_a_two_step_severity_gap_is_a_contradiction():
    cc = crosscheck(wf("critical", ["T1021"]), agent("medium", ["T1021"]))
    assert cc["verdict"] == "contradicts"
    assert cc["corroboration_strength"] == 0.0


def test_a_contradiction_adds_no_confidence():
    cc = crosscheck(wf("high", ["T1021"]), agent("low", ["T1021"]))
    assert as_evidence(cc) is None, "a contradiction must not corroborate anything"


def test_no_shared_techniques_is_inconclusive_not_agreement():
    cc = crosscheck(wf("high", ["T1078"]), agent("high", []))
    assert cc["verdict"] in ("inconclusive", "partially corroborates")
    if cc["verdict"] == "inconclusive":
        assert cc["corroboration_strength"] == 0.0


def test_a_degraded_agent_lane_corroborates_less():
    healthy = crosscheck(wf("high", ["T1021"]), agent("high", ["T1021"]))
    broken = crosscheck(wf("high", ["T1021"]),
                        agent("high", ["T1021"], degraded=["intelligence"]))
    assert broken["corroboration_strength"] < healthy["corroboration_strength"]


def test_a_missing_agent_lane_degrades_rather_than_failing():
    cc = crosscheck(wf("high", ["T1021"]), None)
    assert cc["available"] is False
    assert cc["verdict"] == "not available"
    assert cc["authoritative"] == "workflow"


# --------------------------------------------------------------------------- #
# the honesty rules                                                            #
# --------------------------------------------------------------------------- #
def test_the_workflow_is_always_the_authority():
    for ag in (agent("critical", ["T1021"]), agent("low", ["T1021"]), None):
        assert crosscheck(wf("high", ["T1021"]), ag)["authoritative"] == "workflow"


def test_agreement_can_never_be_worth_a_second_sensor():
    """Same log, same rule table. Capped on purpose."""
    cc = crosscheck(wf("critical", ["T1021"]), agent("critical", ["T1021"]))
    assert cc["corroboration_strength"] <= MAX_CORROBORATION
    ev = as_evidence(cc)
    assert ev.support <= MAX_CORROBORATION


def test_the_partial_independence_is_stated_in_every_result():
    cc = crosscheck(wf("high", ["T1021"]), agent("high", ["T1021"]))
    ind = cc["partial_independence"]
    assert ind["shared_components"], "must name what the two lanes share"
    assert "second sensor" in ind["note"]


def test_the_two_lanes_are_one_independence_group():
    cc = crosscheck(wf("high", ["T1021"]), agent("high", ["T1021"]))
    assert as_evidence(cc).independence_group == "agent-lane"


def test_the_agent_narrative_is_never_authoritative():
    cc = crosscheck(wf("high", ["T1021"]),
                    {**agent("high", ["T1021"]), "incident_narrative": "n",
                     "point_b_method": "llm"})
    assert cc["narrative_authoritative"] is False


def test_both_severity_bases_are_explained():
    sev = crosscheck(wf("high", ["T1021"]), agent("medium", ["T1021"]))["severity"]
    assert "anomaly score" in sev["basis_workflow"]
    assert "risk band" in sev["basis_agent_lane"]


# --------------------------------------------------------------------------- #
# end to end                                                                   #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def result(client):
    r = client.post("/api/investigate", json={"scenario": "aiims_ransomware"},
                    headers=ANALYST)
    assert r.status_code == 200, r.text
    return r.json()


def test_the_investigation_carries_a_crosscheck(result):
    cc = result["crosscheck"]
    assert cc is not None and cc["available"] is True
    assert cc["verdict"] in ("corroborates", "partially corroborates",
                             "contradicts", "inconclusive")


def test_the_crosscheck_moves_evidence_confidence(result):
    ec = result["headline"]["evidence_confidence"]
    assert ec["crosscheck"] is not None
    assert ec["crosscheck"]["verdict"] == result["crosscheck"]["verdict"]


def test_a_failing_agent_lane_does_not_break_the_investigation(monkeypatch, client):
    """The cross-check is advisory. It must never take the investigation down."""
    import src.agents.orchestrator as orch
    monkeypatch.setattr(orch, "run_pipeline",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("lane down")))
    r = client.post("/api/investigate", json={"scenario": "aiims_ransomware"},
                    headers=ANALYST)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["crosscheck"]["available"] is False
    assert body["signals"]["incident"]["alert_count"] > 0


def test_the_ui_contract_for_the_crosscheck_panel(result):
    cc = result["crosscheck"]
    for key in ("available", "authoritative", "verdict", "corroboration_strength",
                "severity", "techniques", "narrative", "narrative_method",
                "narrative_authoritative", "partial_independence", "explanation",
                "agent_lane_degraded"):
        assert key in cc, key
    for key in ("workflow", "agent_lane", "agreement", "basis_workflow",
                "basis_agent_lane"):
        assert key in cc["severity"], key
    for key in ("workflow", "agent_lane", "shared", "workflow_only",
                "agent_lane_only", "overlap"):
        assert key in cc["techniques"], key


# --------------------------------------------------------------------------- #
# a contradiction must cost something                                          #
# --------------------------------------------------------------------------- #
def test_a_contradiction_actively_reduces_evidence_confidence():
    """Neutral treatment would let a real disagreement pass unnoticed. Two
    analyses of the same log two severity bands apart means at least one is
    wrong, and the result deserves less trust until that is resolved."""
    from src.shared.crosscheck import CONTRADICTION_DISCOUNT
    from src.shared.workflow import evidence_confidence

    claims = [{"actionable": True, "confidence": 0.8, "missing_evidence": []}]
    baseline = evidence_confidence(claims, 1, 1)["value"]
    conflicted = evidence_confidence(
        claims, 1, 1,
        {"available": True, "verdict": "contradicts", "corroboration_strength": 0.0},
    )
    assert conflicted["value"] < baseline, (conflicted["value"], baseline)
    assert conflicted["crosscheck"]["confidence_discount"] == CONTRADICTION_DISCOUNT
    assert abs(conflicted["value"] - baseline * (1 - CONTRADICTION_DISCOUNT)) < 0.2


def test_corroboration_raises_and_contradiction_lowers_from_the_same_baseline():
    from src.shared.workflow import evidence_confidence
    claims = [{"actionable": True, "confidence": 0.8, "missing_evidence": []}]
    base = evidence_confidence(claims, 1, 1)["value"]
    up = evidence_confidence(claims, 1, 1, {
        "available": True, "verdict": "corroborates",
        "corroboration_strength": 0.45, "independence_group": "agent-lane"})["value"]
    down = evidence_confidence(claims, 1, 1, {
        "available": True, "verdict": "contradicts",
        "corroboration_strength": 0.0})["value"]
    assert down < base < up, (down, base, up)


def test_an_unavailable_crosscheck_neither_helps_nor_hurts():
    from src.shared.workflow import evidence_confidence
    claims = [{"actionable": True, "confidence": 0.8, "missing_evidence": []}]
    base = evidence_confidence(claims, 1, 1)["value"]
    absent = evidence_confidence(claims, 1, 1,
                                 {"available": False, "verdict": "not available"})["value"]
    assert absent == base
