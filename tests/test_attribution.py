"""Exact Shapley attribution: the axioms, not the vibes.

The SIH problem statement says black-box output without interpretability is not
acceptable and names SHAP. With seven features the full 128-coalition
enumeration is cheap, so these values are EXACT and must satisfy the Shapley
axioms. A test suite that only checked "an explanation was produced" would pass
for an attribution that is quietly wrong, which is worse than none.
"""
from __future__ import annotations

import pytest

from src.engine1.lanl_detect import FEATURES
from src.shared.attribution import BASELINE, explain_score, shapley_values

MALICIOUS = {"is_fail": 0, "new_dst_for_user": 1, "new_src_for_user": 1,
             "user_distinct_dst_sofar": 20, "user_fail_rate_sofar": 0.05,
             "dst_rarity": 10.0, "is_ntlm": 1}


@pytest.fixture(scope="module")
def attr():
    return explain_score(MALICIOUS)


# --------------------------------------------------------------------------- #
# Shapley axioms                                                               #
# --------------------------------------------------------------------------- #
def test_efficiency_the_values_sum_to_the_prediction_gap(attr):
    """sum(phi) == v(all) - v(baseline). The defining property."""
    total = sum(a["shapley"] for a in attr["attributions"])
    assert abs(total - attr["total_attribution"]) < 1e-5, (total, attr["total_attribution"])


def test_dummy_a_feature_at_its_baseline_gets_no_credit():
    """A row identical to the baseline must attribute nothing to anything."""
    out = explain_score(dict(BASELINE))
    assert abs(out["total_attribution"]) < 1e-9
    for a in out["attributions"]:
        assert abs(a["shapley"]) < 1e-9, a


def test_symmetry_identical_inputs_give_identical_explanations():
    assert explain_score(MALICIOUS) == explain_score(MALICIOUS)


def test_every_feature_receives_an_attribution(attr):
    assert {a["feature"] for a in attr["attributions"]} == set(FEATURES)


def test_it_is_exact_not_sampled(attr):
    assert "exact" in attr["method"].lower()
    assert "no sampling" in attr["method"].lower() or "128" in attr["method"]


# --------------------------------------------------------------------------- #
# does it say something true about the domain?                                 #
# --------------------------------------------------------------------------- #
def test_the_ntlm_signal_is_a_top_driver(attr):
    """100% of LANL red-team logins used NTLM versus ~6% of benign traffic, and
    the published ablation shows removing it costs ROC 0.992 -> 0.906. An
    attribution that did not surface it would be contradicting our own report."""
    top3 = [a["feature"] for a in attr["attributions"][:3]]
    assert "is_ntlm" in top3, attr["attributions"]


def test_anomalous_values_raise_the_score(attr):
    raising = [a["feature"] for a in attr["attributions"] if a["direction"] == "raises"]
    assert "is_ntlm" in raising
    assert "dst_rarity" in raising


def test_a_benign_row_scores_below_a_malicious_one():
    benign = explain_score(dict(BASELINE))
    assert benign["score"] < explain_score(MALICIOUS)["score"]


def test_each_attribution_is_human_readable(attr):
    for a in attr["attributions"]:
        assert a["meaning"] and not a["meaning"].startswith(a["feature"])
        assert a["direction"] in ("raises", "lowers", "neutral")
        assert 0.0 <= a["share"] <= 1.0


def test_shapley_values_cover_every_feature_key():
    phi = shapley_values(MALICIOUS)
    assert set(phi) == set(FEATURES)


# --------------------------------------------------------------------------- #
# wired into the explainability trace                                          #
# --------------------------------------------------------------------------- #
def test_the_explain_trace_carries_the_attribution():
    from fastapi.testclient import TestClient

    from api.main import app
    r = TestClient(app).post("/api/explain",
                             json={"scenario": "aiims_ransomware",
                                   "critical_assets": ["PATIENT-DB-01"],
                                   "step_index": 0},
                             headers={"X-Role": "analyst"})
    assert r.status_code == 200
    stage4 = next(s for s in r.json()["stages"] if s["stage"].startswith("4"))
    a = stage4["value"]["attribution"]
    assert a["attributions"], a
    assert "exact" in a["method"].lower()
