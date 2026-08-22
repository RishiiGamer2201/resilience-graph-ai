"""Forward simulation: the properties that keep a forecast honest.

A K-step rollout is the easiest place in this product to produce impressive
nonsense. These pin the arithmetic that stops it.
"""
from __future__ import annotations

import pytest

from src.shared.rollout import (MAX_HORIZON, RELIABLE_CONFIDENCE, STEP_DECAY,
                                simulate_progression)

CHAIN = ["T1078", "T1021"]
GRAPH = {"critical_assets_at_risk": ["DB"],
         "paths_to_critical": {"DB": ["PC", "JUMP", "DB"]}}


@pytest.fixture(scope="module")
def sim():
    return simulate_progression(CHAIN, GRAPH, k_steps=6, crown_jewels=["DB", "DC"])


# --------------------------------------------------------------------------- #
# arithmetic that must hold                                                    #
# --------------------------------------------------------------------------- #
def test_cumulative_probability_never_decreases(sim):
    """P(reached impact BY step k) cannot fall as k grows. It did, because the
    curve was being multiplied by a decaying confidence — conflating a
    probability with how much the probability is worth."""
    cum = sim["infiltration_probability"]
    assert cum == sorted(cum), cum


def test_probability_and_confidence_are_separate_series(sim):
    assert len(sim["infiltration_probability"]) == len(sim["horizon_confidence"])
    assert sim["horizon_confidence"] != sim["infiltration_probability"]


def test_horizon_confidence_decays_monotonically(sim):
    conf = sim["horizon_confidence"]
    assert conf == sorted(conf, reverse=True)
    assert conf[0] == 1.0
    assert conf[-1] < conf[0]


def test_confidence_follows_the_declared_decay(sim):
    for i, c in enumerate(sim["horizon_confidence"]):
        # stored rounded to 4dp, so the tolerance has to allow for that
        assert abs(c - STEP_DECAY ** i) < 1e-4, (i, c)


def test_probabilities_stay_within_bounds(sim):
    for p in sim["infiltration_probability"]:
        assert 0.0 <= p <= 100.0
    for step in sim["steps"]:
        total = sum(pr["probability"] for pr in step["predictions"])
        assert total <= 1.0001, f"step distribution exceeds 1: {total}"


# --------------------------------------------------------------------------- #
# the headline must not be the least reliable number                          #
# --------------------------------------------------------------------------- #
def test_the_headline_is_quoted_at_a_confident_horizon(sim):
    """Cumulative probability always peaks at the LAST step, where confidence is
    lowest. Leading with the peak means leading with the worst estimate."""
    assert sim["headline_confidence"] >= RELIABLE_CONFIDENCE
    assert sim["reliable_horizon"] < len(sim["steps"]) or len(sim["steps"]) == 1


def test_the_headline_never_exceeds_the_peak(sim):
    assert sim["headline_probability"] <= sim["peak_infiltration_probability"]


def test_the_headline_states_its_own_confidence(sim):
    assert str(sim["headline_confidence"]) in sim["headline"]
    assert "confidence" in sim["headline"].lower()


def test_steps_beyond_the_horizon_are_disclaimed(sim):
    assert "not quoted" in sim["beyond_horizon_note"]


# --------------------------------------------------------------------------- #
# grounding                                                                    #
# --------------------------------------------------------------------------- #
def test_every_predicted_technique_is_a_real_attack_id(sim):
    import pickle

    from src.shared.rollout import LOOKUPS
    with LOOKUPS.open("rb") as f:
        valid = set(pickle.load(f)["technique_to_name"])
    for step in sim["steps"]:
        for pr in step["predictions"]:
            assert pr["technique_id"] in valid, pr["technique_id"]
            assert pr["stage"], pr


def test_the_forecast_does_not_invent_topology(sim):
    """A predicted technique must not conjure hosts the attacker never touched."""
    ex = sim["reachable_crown_jewels"]
    assert ex["already_reachable"] == ["DB"]
    assert ex["not_yet_reachable"] == ["DC"]
    assert "do not invent" in ex["note"]


def test_it_is_deterministic():
    a = simulate_progression(CHAIN, GRAPH, k_steps=4)
    b = simulate_progression(CHAIN, GRAPH, k_steps=4)
    assert a == b


def test_nothing_observed_means_nothing_forecast():
    out = simulate_progression([], GRAPH, k_steps=4)
    assert out["available"] is False
    assert "nothing to roll forward" in out["reason"]


def test_the_horizon_is_bounded():
    out = simulate_progression(CHAIN, GRAPH, k_steps=999)
    assert out["k_steps"] == MAX_HORIZON
    assert len(out["steps"]) <= MAX_HORIZON


def test_a_missing_graph_degrades_rather_than_failing():
    out = simulate_progression(CHAIN, None, k_steps=3)
    assert out["available"] is True
    assert out["reachable_crown_jewels"]["available"] is False


def test_the_method_is_declared(sim):
    m = sim["method"]
    assert "Markov" in m["model"]
    assert "beam" in m["search"]
    assert m["deterministic"] is True
    assert "not a simulation of an attacker's intent" in sim["honesty"]


# --------------------------------------------------------------------------- #
# wired into the investigation                                                 #
# --------------------------------------------------------------------------- #
def test_the_investigation_carries_a_forecast():
    from fastapi.testclient import TestClient

    from api.main import app
    r = TestClient(app).post("/api/investigate",
                             json={"scenario": "aiims_ransomware"},
                             headers={"X-Role": "analyst"})
    assert r.status_code == 200
    f = r.json()["impact"]["progression_forecast"]
    assert f["available"] is True
    assert f["steps"] and f["headline"]
    assert f["infiltration_probability"] == sorted(f["infiltration_probability"])
