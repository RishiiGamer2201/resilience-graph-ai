"""Regression tests for interpolation mass in the ATT&CK association ranker."""
from __future__ import annotations

import pytest

from src.shared import predictor


@pytest.fixture()
def synthetic_model(monkeypatch):
    """A tiny model with contexts for every runtime source mode."""
    model = {
        "version": 4,
        "order2": {("P", "L"): [["A", 3], ["B", 1]]},
        "order1": {"L": [["A", 1], ["C", 1]]},
        "unigram": [["A", 1], ["B", 1], ["C", 2]],
        "lambdas": [0.2, 0.3, 0.5],
        "_uni_total": 4,
        "_fallback": ["A", "B", "C"],
    }
    monkeypatch.setitem(predictor._state, "m", model)
    return model


@pytest.mark.parametrize(
    ("history", "expected_source"),
    [
        ([], "profile-frequency-fallback"),
        (["UNKNOWN"], "profile-frequency-fallback"),
        (["L"], "profile-association-order1"),
        (["P", "L"], "profile-association-order2"),
    ],
)
def test_complete_candidate_mass_is_one_for_every_source_mode(
    synthetic_model,
    history,
    expected_source,
):
    ranked, source = predictor.rank_associations(history, k=None)

    assert source == expected_source
    assert {technique for technique, _ in ranked} == {"A", "B", "C"}
    assert sum(weight for _, weight in ranked) == pytest.approx(1.0, abs=1e-9)


def test_unavailable_weights_are_redistributed_over_available_components(synthetic_model):
    fallback, _ = predictor.rank_associations([], k=None)
    first_order, _ = predictor.rank_associations(["L"], k=None)
    second_order, _ = predictor.rank_associations(["P", "L"], k=None)

    # Unigram-only: its stored 0.5 lambda becomes 1.0.
    assert dict(fallback) == pytest.approx({"A": 0.25, "B": 0.25, "C": 0.5})
    # First-order: 0.3 and 0.5 become 0.375 and 0.625.
    assert dict(first_order) == pytest.approx({"A": 0.34375, "B": 0.15625, "C": 0.5})
    # Full context keeps the original 0.2/0.3/0.5 mixture.
    assert dict(second_order) == pytest.approx({"A": 0.425, "B": 0.175, "C": 0.4})


def test_top_k_is_a_ranked_slice_not_a_claim_that_visible_mass_sums_to_one(synthetic_model):
    complete, source = predictor.rank_associations(["L"], k=None)
    visible, visible_source = predictor.rank_associations(["L"], k=2)

    assert visible_source == source
    assert visible == complete[:2]
    assert sum(weight for _, weight in visible) < 1.0


def test_narrative_does_not_present_model_weight_as_empirical_frequency(synthetic_model):
    narrative = predictor.generate_prediction_narrative([("A", 0.5)], ["L"])

    assert "normalized model weight 50%" in narrative
    assert "not observed frequencies" in narrative
    assert "calibrated confidence" in narrative
    assert "future probabilities" in narrative


def test_legacy_zero_unigram_lambda_still_falls_back_to_a_distribution(monkeypatch):
    legacy = {
        "version": 1,
        "order2": {},
        "order1": {"KNOWN": [["A", 1]]},
        "unigram": [["A", 1], ["B", 3]],
        "lambdas": [0.0, 1.0, 0.0],
        "_uni_total": 4,
        "_fallback": ["B", "A"],
    }
    monkeypatch.setitem(predictor._state, "m", legacy)

    ranked, source = predictor.rank_associations(["UNKNOWN"], k=None)

    assert source == "profile-frequency-fallback"
    assert dict(ranked) == pytest.approx({"A": 0.25, "B": 0.75})
    assert sum(weight for _, weight in ranked) == pytest.approx(1.0, abs=1e-9)
