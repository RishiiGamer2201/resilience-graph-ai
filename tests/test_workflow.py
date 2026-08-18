"""The investigation workflow, its headline metrics, the explainability trace and
the PS7 scoreboard contract.

The properties worth locking in: the graph is bounded, a broken optional stage
degrades instead of erasing the investigation, the headline numbers are
reproducible arithmetic, and the scoreboard cannot quietly start overclaiming.
"""
from __future__ import annotations

import pytest

from src.shared import workflow as wf

CRIT = ["PATIENT-DB-01", "DC-AIIMS-01"]


@pytest.fixture(scope="module")
def result():
    return wf.investigate(scenario="aiims_ransomware", critical_assets=CRIT)


# --------------------------------------------------------------------------- #
# the graph                                                                    #
# --------------------------------------------------------------------------- #
def test_all_seven_stages_run_in_order(result):
    nodes = [n["node"] for n in result["trace"]["nodes"]]
    assert nodes[0] == "understand"
    assert nodes[-1] == "action"
    assert set(nodes) == set(wf.NODES)
    # the fixed spine must appear in order, ignoring the permitted evidence retry
    spine = [n for n in nodes if n != "evidence"]
    assert spine == ["understand", "plan", "signals", "replan", "replan", "impact", "action"] \
        or spine == ["understand", "plan", "signals", "replan", "impact", "action"], spine


def test_the_graph_is_bounded(result):
    nodes = [n["node"] for n in result["trace"]["nodes"]]
    assert nodes.count("evidence") <= 1 + wf.MAX_REPLANS
    assert nodes.count("replan") <= 1 + wf.MAX_REPLANS
    assert "at most 1 replan" in result["trace"]["bounded_by"]


def test_every_node_reports_a_status_and_a_time(result):
    for n in result["trace"]["nodes"]:
        assert n["status"] in ("ok", "degraded", "skipped", "failed"), n
        assert n["ms"] >= 0
        assert n["summary"]


def test_a_broken_optional_stage_degrades_rather_than_erasing_the_case(monkeypatch):
    """Losing the evidence retriever must not lose the detection."""
    import src.shared.evidence as ev
    monkeypatch.setattr(ev, "repository",
                        lambda: (_ for _ in ()).throw(RuntimeError("index corrupt")))
    r = wf.investigate(scenario="aiims_ransomware", critical_assets=CRIT)
    assert r["ok"] is True
    ev_node = next(n for n in r["trace"]["nodes"] if n["node"] == "evidence")
    assert ev_node["status"] == "degraded"
    assert "evidence" in r["trace"]["degraded"]
    assert r["signals"]["incident"]["alert_count"] > 0        # detection survived
    assert r["action"]["proposals"]                            # so did the response


def test_a_required_stage_failing_is_reported_not_faked():
    with pytest.raises(ValueError):
        wf.investigate(scenario="no-such-scenario")


def test_no_llm_is_in_the_path(result):
    assert result["llm"]["provider"] == "none"
    assert result["llm"]["used_for"] == []
    assert "deterministic" in result["llm"]["note"]


def test_the_same_input_gives_the_same_answer():
    a = wf.investigate(scenario="aiims_ransomware", critical_assets=CRIT)
    b = wf.investigate(scenario="aiims_ransomware", critical_assets=CRIT)
    for key in ("attack_progression_confidence", "crown_jewel_exposure"):
        assert a["headline"][key]["value"] == b["headline"][key]["value"]
    assert (a["signals"]["incident"]["technique_ids"]
            == b["signals"]["incident"]["technique_ids"])


# --------------------------------------------------------------------------- #
# headline metrics: the arithmetic must be checkable on screen                 #
# --------------------------------------------------------------------------- #
def test_exposure_decays_with_distance():
    one = wf.crown_jewel_exposure({"paths_to_critical": {"DB": ["A", "DB"]}}, ["DB"])
    three = wf.crown_jewel_exposure({"paths_to_critical": {"DB": ["A", "B", "C", "DB"]}}, ["DB"])
    assert one["value"] == 100.0
    assert three["value"] < one["value"]


def test_an_unreachable_crown_jewel_scores_zero_and_says_why():
    e = wf.crown_jewel_exposure({"paths_to_critical": {}}, ["DB"])
    assert e["value"] == 0.0
    assert e["terms"][0]["why"] == "no path from any attacker pivot"


def test_no_designated_crown_jewel_is_not_measured_rather_than_zero():
    e = wf.crown_jewel_exposure({"paths_to_critical": {}}, [])
    assert e["value"] is None
    assert e["state"] == "not measured"
    assert "no crown-jewel assets were designated" in e["reason"]


def test_progression_terms_reproduce_the_headline(result):
    c = result["headline"]["attack_progression_confidence"]
    recomputed = 100 * sum(t["weight"] * t["value"] for t in c["terms"])
    assert abs(recomputed - c["value"]) < 0.05, (recomputed, c["value"])
    assert abs(sum(t["weight"] for t in c["terms"]) - 1.0) < 1e-9


def test_exposure_terms_reproduce_the_headline(result):
    e = result["headline"]["crown_jewel_exposure"]
    recomputed = sum(t["score"] for t in e["terms"]) / len(e["terms"])
    assert abs(recomputed - e["value"]) < 0.05


# --------------------------------------------------------------------------- #
# action + RFI                                                                 #
# --------------------------------------------------------------------------- #
def test_nothing_is_ever_executed(result):
    assert result["action"]["executed"] == 0
    assert all(p["simulated"] for p in result["action"]["proposals"])
    assert "SIMULATION ONLY" in result["action"]["note"]


def test_a_crown_jewel_action_is_gated(result):
    gated = [p for p in result["action"]["proposals"] if p["policy"]["requires_approval"]]
    assert gated, "no action was gated in an incident that reaches a crown jewel"
    assert all(p["policy"]["reasons"] for p in gated)


def test_the_rfi_asks_for_the_things_a_model_cannot_know(result):
    rfi = result["action"]["rfi"]
    fields = {q["field"] for q in rfi["questions"]}
    assert {"asset_owner", "business_criticality", "maintenance_window",
            "identity_context", "edr_result", "patch_status"} <= fields
    assert "deterministic template" in rfi["generated_by"]


# --------------------------------------------------------------------------- #
# explainability                                                               #
# --------------------------------------------------------------------------- #
def test_explain_walks_the_whole_chain():
    import pandas as pd
    from src.engine1.lanl_detect import engineer
    from src.schema import coerce
    from src.shared.explain import explain_step
    from src.shared.live_analyze import _score, analyze_events

    raw = pd.read_csv("data/demo/scenarios/aiims_ransomware.csv")
    bundle = analyze_events(raw.copy(), critical_assets=set(CRIT))
    df = engineer(coerce(raw.copy()))
    df["anomaly_score"] = _score(df).round().astype(int)

    t = explain_step(df, bundle, 0)
    assert t["available"]
    stages = [s["stage"] for s in t["stages"]]
    assert len(stages) == 11
    assert stages[0].startswith("1 ") and stages[-1].startswith("11 ")
    assert all(s["produced_by"] for s in t["stages"])
    assert t["stages"][-1]["value"]["executed"] == 0


# --------------------------------------------------------------------------- #
# scoreboard contract                                                          #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def board():
    from src.shared.scoreboard import scoreboard
    return scoreboard()


def test_every_card_is_either_measured_or_explains_itself(board):
    for c in board["cards"]:
        if c["state"] == "measured":
            assert isinstance(c["value"], (int, float)), c["id"]
            assert c["definition"] and c["dataset"], c["id"]
        else:
            assert c["value"] is None, c["id"]
            assert c["why"], c["id"]


def test_no_card_reports_a_zero_where_it_means_unknown(board):
    for c in board["cards"]:
        if c["state"] == "not_measured":
            assert c["provenance"] == "NOT_MEASURED"


def test_the_two_metrics_we_cannot_measure_are_declared(board):
    unmeasured = {c["id"] for c in board["cards"] if c["state"] == "not_measured"}
    assert {"mttr", "technique_precision"} <= unmeasured
    mttr = next(c for c in board["cards"] if c["id"] == "mttr")
    assert "simulated" in mttr["why"].lower() or "no action is executed" in mttr["why"].lower()


def test_every_cited_report_exists_on_disk(board):
    assert board["summary"]["missing_reports"] == []


def test_the_board_refuses_the_claims_we_promised_not_to_make(board):
    assert "accuracy" in board["refused_claims"]
    for c in board["cards"]:
        name = c["name"].lower()
        assert "accuracy" not in name or "top-3" in name, c["name"]
        assert "100% attribution" not in name


def test_detection_headline_matches_the_canonical_metrics_store(board):
    """The scoreboard must not be able to drift from reports/metrics.json."""
    from src.shared.metrics_store import load
    m = load()
    card = next(c for c in board["cards"] if c["id"] == "tpr_at_1pct_fpr")
    assert card["value"] == round(100 * m["engine1"]["lanl"]["tpr_at_1pct_fpr"], 1)
    roc = next(c for c in board["cards"] if c["id"] == "lanl_roc")
    assert roc["value"] == m["engine1"]["lanl"]["roc_auc"]


def test_the_ui_scorecard_also_reads_the_store():
    from src.shared.metrics_store import load
    from src.shared.views import SCORECARD
    m = load()
    lanl = next(c for c in SCORECARD if c["name"].startswith("LANL"))
    assert lanl["value"] == m["engine1"]["lanl"]["roc_auc"], "SCORECARD drifted again"
