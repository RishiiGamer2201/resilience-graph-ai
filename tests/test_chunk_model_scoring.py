"""The agent lane scores chunks with the model, or says plainly that it did not.

Issue #39. `src/agents/detection.py` had an autoencoder path guarded by
`all(f in events.columns for f in LANL_FEATURES)`. Nothing on the agent lane
ever engineered those features -- the orchestrator handed raw events straight to
the chunker -- so the guard was False for every chunk in every scenario and the
whole "10-agent" lane was scored by:

    10 + failure_rate*40 + min(unique_dst*3, 30) + min(events//5, 20)

which is arithmetic over aggregates, not the detector this project publishes
ROC and TPR@1%FPR for.
"""
from __future__ import annotations

import pandas as pd
import pytest

from src.agents.chunker import chunk_all_strategies
from src.agents.detection import (BASE_THRESHOLD, LANL_FEATURES, SCORE_COLUMN,
                                  THRESHOLD_BY_PRIORITY, _heuristic_score,
                                  _score_chunk)
from src.agents.orchestrator import _engineer_for_scoring

SCENARIO = "data/demo/scenarios/aiims_ransomware.csv"


@pytest.fixture(scope="module")
def scored_events():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    path = root / SCENARIO
    if not path.exists():                        # pragma: no cover
        pytest.skip("demo scenario not exported")
    out, _ = _engineer_for_scoring(pd.read_csv(path))
    return out


# --------------------------------------------------------------------------- #
# the model actually runs                                                      #
# --------------------------------------------------------------------------- #
def test_the_lane_engineers_the_features_the_model_needs(scored_events):
    """Without this the autoencoder branch is unreachable, which is the bug."""
    missing = [f for f in LANL_FEATURES if f not in scored_events.columns]
    assert not missing, missing


def test_every_event_carries_a_calibrated_score(scored_events):
    assert SCORE_COLUMN in scored_events.columns
    assert pd.to_numeric(scored_events[SCORE_COLUMN], errors="coerce").notna().any()


def test_chunks_are_scored_by_the_model_not_the_heuristic(scored_events):
    chunks = chunk_all_strategies(scored_events)["time_window"]
    methods = set()
    for c in chunks:
        _, method, _ = _score_chunk(c, {}, "routine")
        methods.add(method)
    assert methods == {"autoencoder"}, methods


def test_routine_chunks_go_through_the_same_model_as_urgent_ones(scored_events):
    """Routine chunks used to skip the model "for efficiency", so the lane's
    quiet chunks and its loud ones were scored by different methods -- and then
    ranked against each other downstream."""
    chunks = chunk_all_strategies(scored_events)["time_window"]
    c = chunks[0]
    routine, m_routine, _ = _score_chunk(c, {}, "routine")
    urgent, m_urgent, _ = _score_chunk(c, {}, "urgent")
    assert m_routine == m_urgent == "autoencoder"
    assert routine == urgent, "priority changed the model score"


# --------------------------------------------------------------------------- #
# findings link back to events                                                 #
# --------------------------------------------------------------------------- #
def test_a_chunk_score_names_the_events_that_produced_it(scored_events):
    """A chunk finding that cannot be traced to events is an assertion. This
    lane is advisory precisely because its claims are meant to be checkable."""
    chunks = chunk_all_strategies(scored_events)["time_window"]
    score, method, evidence = _score_chunk(chunks[0], {}, "routine")
    assert method == "autoencoder"
    assert evidence["aggregation"] == "max over the chunk's per-event scores"
    assert evidence["top_events"], "no contributing events recorded"
    top = evidence["top_events"][0]
    assert top["score"] == score, "the chunk score is not its top event's score"
    assert set(top["features"]) <= set(LANL_FEATURES)
    assert {"user", "source_host", "destination_host"} <= set(top)


# --------------------------------------------------------------------------- #
# the fallback is explicit and never dressed up                                #
# --------------------------------------------------------------------------- #
def test_the_heuristic_says_it_is_not_a_model():
    chunk = type("C", (), {"events": pd.DataFrame()})()
    score, method, evidence = _score_chunk(chunk, {"failure_rate": 0.5,
                                                   "destination_host_unique": 4,
                                                   "n_events": 50}, "urgent")
    assert method == "heuristic"
    assert evidence["not_a_model"] is True
    assert "no model scored it" in evidence["why"]
    assert evidence["terms"]["total"] == score


def test_the_orchestrator_label_follows_what_actually_ran(scored_events):
    from src.agents.orchestrator import _scoring_method
    assert _scoring_method([{"score_method": "autoencoder"}]) == "autoencoder"
    assert _scoring_method([{"score_method": "heuristic"}]) == "behavioural heuristic"
    mixed = _scoring_method([{"score_method": "autoencoder"},
                             {"score_method": "heuristic"}])
    assert "autoencoder" in mixed and "heuristic" in mixed


# --------------------------------------------------------------------------- #
# priority is applied once                                                     #
# --------------------------------------------------------------------------- #
def test_priority_lowers_the_threshold_and_no_longer_also_raises_the_score():
    """It did both: an urgent chunk was pushed up 20 points AND its bar pulled
    down from 50 to 35, for the same reason, inside one number. A chunk scoring
    30 on its own behaviour cleared a 35 threshold at 50."""
    stats = {"failure_rate": 0.2, "destination_host_unique": 3, "n_events": 20}
    routine, terms = _heuristic_score(stats, "routine")
    urgent, _ = _heuristic_score(stats, "urgent")
    assert routine == urgent, "priority still contributes to the score"
    assert terms["priority_applied_to"] == "threshold only, not the score"
    assert THRESHOLD_BY_PRIORITY["urgent"] < THRESHOLD_BY_PRIORITY["routine"] == BASE_THRESHOLD


# --------------------------------------------------------------------------- #
# calibration is a property of the log, not of a five-minute window            #
# --------------------------------------------------------------------------- #
def test_scoring_is_whole_log_not_per_chunk(scored_events):
    """Rescaling inside each chunk pins its top event at 100 whatever it holds,
    which turned a ranking into a severity and flagged 36 of 36 chunks."""
    chunks = chunk_all_strategies(scored_events)["time_window"]
    tops = []
    for c in chunks:
        _, method, ev = _score_chunk(c, {}, "routine")
        assert method == "autoencoder"
        assert "whole-log" in ev["calibration"]
        tops.append(ev["top_events"][0]["score"] if ev["top_events"] else 0)
    assert len({t for t in tops}) > 1, "every chunk's top event scored the same"
    flagged = sum(1 for c in chunks
                  if _score_chunk(c, {}, "routine")[0] >= BASE_THRESHOLD)
    assert flagged < len(chunks), "every chunk is above threshold"
