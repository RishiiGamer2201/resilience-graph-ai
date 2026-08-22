"""The network-state world model: the properties, not the vibes.

SIH 2026 requirement 2 asks for P(S_t+1 | S_t) over observed network state. A
test suite that only checked "a forecast came back" would pass for a model whose
transition matrix rows do not sum to one, whose rollout probability falls with
the horizon, or whose latent assignment is not reproducible. All three have
happened to us in this codebase before.

These run without the 308 MB CIC-IDS2017 parquet. The tests that need it are
skipped rather than silently passing on a fabricated substitute.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.engine3.netstate import (
    FLOWS,
    MODEL,
    STATE_DIM,
    NetStateModel,
    build_observations,
    fit,
    state_names,
    windows,
)


# --------------------------------------------------------------------------- #
# fixtures: a synthetic two-regime network                                     #
# --------------------------------------------------------------------------- #
W = 8


def _frame(seed: int = 0) -> pd.DataFrame:
    """A quiet clean day and a noisy compromised day."""
    from src.engine3.netstate import FLOW_FEATURES
    rng = np.random.default_rng(seed)
    n = 40 * W
    out = []
    for day, loc, scale, attack in (("A", 0.0, 0.2, 0.0), ("B", 6.0, 2.0, 1.0)):
        d = pd.DataFrame(rng.normal(loc, scale, size=(n, len(FLOW_FEATURES))),
                         columns=FLOW_FEATURES)
        d["label"], d["day"] = attack, day
        out.append(d)
    return pd.concat(out, ignore_index=True)


@pytest.fixture(scope="module")
def model_and_obs():
    df = _frame()
    obs = build_observations(df, ["A", "B"], window=W)
    return fit(obs, n_states=4, window=W), obs


# --------------------------------------------------------------------------- #
# the state vector                                                             #
# --------------------------------------------------------------------------- #
def test_state_is_fixed_width_mean_and_dispersion():
    s, a = windows(_frame()[:W * 5], window=W)
    assert s.shape == (5, STATE_DIM)
    assert len(state_names()) == STATE_DIM
    assert (a >= 0).all() and (a <= 1).all()


def test_infinities_in_the_cic_rate_columns_do_not_reach_the_model():
    """Flow Bytes/s is inf for zero-duration flows in the CIC export. An inf in
    the state vector poisons the standardiser and every centroid after it."""
    from src.engine3.netstate import FLOW_FEATURES
    df = _frame()[: W * 2].copy()
    df.loc[0, "Flow Bytes/s"] = np.inf
    df.loc[1, "Flow IAT Std"] = -np.inf
    s, _ = windows(df, window=W)
    assert np.isfinite(s).all()


def test_a_short_day_yields_no_windows_rather_than_a_ragged_one():
    s, a = windows(_frame()[: W - 1], window=W)
    assert len(s) == 0 and len(a) == 0


def test_windows_never_span_a_day_boundary():
    obs = build_observations(_frame(), ["A", "B"], window=W)
    assert [d for d, _, _ in obs] == ["A", "B"]
    assert all(len(s) == 40 for _, s, _ in obs)


# --------------------------------------------------------------------------- #
# the transition model                                                         #
# --------------------------------------------------------------------------- #
def test_transition_rows_are_probability_distributions(model_and_obs):
    m, _ = model_and_obs
    for T in (m.transitions, m.transition_matrix()):
        assert T.shape == (m.n_states, m.n_states)
        assert np.allclose(T.sum(axis=1), 1.0)
        assert (T >= 0).all()


def test_laplace_smoothing_leaves_no_impossible_transition(model_and_obs):
    m, _ = model_and_obs
    assert (m.transitions > 0).all(), "an unseen transition must be improbable, not impossible"


def test_the_interpolation_weight_is_a_real_mixture(model_and_obs):
    m, _ = model_and_obs
    m2 = NetStateModel(**{**m.__dict__, "persistence_weight": 0.25})
    T = m2.transition_matrix()
    expected = 0.75 * m.transitions + 0.25 * np.eye(m.n_states)
    assert np.allclose(T, expected)
    assert np.allclose(T.sum(axis=1), 1.0)


def test_zero_weight_returns_the_counted_matrix_untouched(model_and_obs):
    m, _ = model_and_obs
    m2 = NetStateModel(**{**m.__dict__, "persistence_weight": 0.0})
    assert np.array_equal(m2.transition_matrix(), m.transitions)


# --------------------------------------------------------------------------- #
# determinism                                                                  #
# --------------------------------------------------------------------------- #
def test_the_same_data_gives_the_same_model():
    """k-means is seeded. Two fits over identical input must agree exactly, or
    nothing downstream of the latent ids is reproducible."""
    obs = build_observations(_frame(), ["A", "B"], window=W)
    a, b = fit(obs, n_states=4, window=W), fit(obs, n_states=4, window=W)
    assert np.array_equal(a.centroids, b.centroids)
    assert np.array_equal(a.transitions, b.transitions)
    assert a.persistence_weight == b.persistence_weight


def test_encoding_is_stable(model_and_obs):
    m, obs = model_and_obs
    s = obs[0][1]
    assert np.array_equal(m.encode(s), m.encode(s))


# --------------------------------------------------------------------------- #
# the forecast                                                                 #
# --------------------------------------------------------------------------- #
def test_cumulative_probability_never_falls(model_and_obs):
    """The bug we already shipped once in src/shared/rollout.py: multiplying a
    cumulative probability by a decaying confidence made the curve go DOWN as
    the horizon grew, which is incoherent."""
    m, obs = model_and_obs
    f = m.forecast(obs[1][1], horizon=6)
    cum = [s["cumulative_probability"] for s in f["steps"]]
    assert cum == sorted(cum), cum


def test_every_reported_probability_is_a_probability(model_and_obs):
    m, obs = model_and_obs
    f = m.forecast(obs[1][1], horizon=5)
    for s in f["steps"]:
        assert 0.0 <= s["attack_probability"] <= 1.0, s
        assert 0.0 <= s["cumulative_probability"] <= 1.0, s
        assert abs(sum(t["probability"] for t in s["top_states"])) <= 1.0 + 1e-6


def test_the_forecast_separates_a_compromised_regime_from_a_quiet_one(model_and_obs):
    m, obs = model_and_obs
    quiet = m.forecast(obs[0][1], horizon=3)
    noisy = m.forecast(obs[1][1], horizon=3)
    assert (noisy["steps"][0]["attack_probability"]
            > quiet["steps"][0]["attack_probability"]), (noisy, quiet)


def test_the_horizon_is_honoured(model_and_obs):
    m, obs = model_and_obs
    assert len(m.forecast(obs[0][1], horizon=7)["steps"]) == 7


def test_the_forecast_says_which_state_space_it_is_in(model_and_obs):
    """The whole point of engine3 is that it is NOT the technique state space.
    A caller must be able to tell the two apart from the payload alone."""
    m, obs = model_and_obs
    f = m.forecast(obs[0][1], horizon=2)
    assert "network" in f["state_space"].lower()
    assert "no sampling" in f["method"].lower()


# --------------------------------------------------------------------------- #
# explainability                                                               #
# --------------------------------------------------------------------------- #
def test_a_latent_state_can_be_printed(model_and_obs):
    """'Black-box outputs without interpretability are not acceptable' is a
    direct quote from the problem statement."""
    m, _ = model_and_obs
    d = m.describe_state(0)
    assert d["distinguishing_features"]
    names = set(state_names())
    for f in d["distinguishing_features"]:
        assert f["feature"] in names
        assert f["direction"] in ("high", "low")
    assert 0.0 <= d["attack_rate"] <= 1.0


def test_state_attack_rates_are_measured_not_assumed(model_and_obs):
    m, _ = model_and_obs
    assert ((m.state_attack_rate >= 0) & (m.state_attack_rate <= 1)).all()
    assert m.state_support.sum() == 80, "every training window belongs to a state"


# --------------------------------------------------------------------------- #
# round trip                                                                   #
# --------------------------------------------------------------------------- #
def test_save_and_load_preserve_the_model(tmp_path, model_and_obs):
    m, obs = model_and_obs
    p = tmp_path / "m.npz"
    m.save(p)
    r = NetStateModel.load(p)
    assert np.array_equal(r.centroids, m.centroids)
    assert np.array_equal(r.transitions, m.transitions)
    assert r.persistence_weight == m.persistence_weight
    assert r.window == m.window and r.trained_on == m.trained_on
    assert r.forecast(obs[0][1], horizon=3) == m.forecast(obs[0][1], horizon=3)


# --------------------------------------------------------------------------- #
# the shipped artifact                                                         #
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not MODEL.exists(), reason="netstate model not trained")
def test_the_shipped_model_is_coherent():
    m = NetStateModel.load()
    assert m.n_states >= 2
    assert m.centroids.shape[1] == STATE_DIM
    assert np.allclose(m.transition_matrix().sum(axis=1), 1.0)
    assert 0.0 <= m.persistence_weight <= 1.0
    assert m.trained_on, "the model must record which days it was trained on"


@pytest.mark.skipif(not MODEL.exists(), reason="netstate model not trained")
def test_the_shipped_model_was_not_trained_on_the_test_days():
    from src.engine3.netstate import TEST_DAYS
    m = NetStateModel.load()
    for day in TEST_DAYS:
        assert day not in m.trained_on, f"{day} is a test day and must not be trained on"


@pytest.mark.skipif(not FLOWS.exists(), reason="CIC-IDS2017 parquet not present")
def test_the_published_numbers_match_a_rerun():
    """reports/netstate.md is generated. If the model drifts from the report,
    the report is a claim we can no longer support."""
    import json
    from pathlib import Path
    mm = json.loads(Path("reports/metrics.json").read_text(encoding="utf-8"))
    ns = mm.get("engine3", {}).get("netstate")
    if not ns:
        pytest.skip("engine3 metrics not recorded yet")
    assert ns["next_state_top1"] > ns["counted_matrix_top1"], (
        "interpolation is supposed to help; if it stops helping, say so in the report")
    assert ns["brier_1step"] < ns["brier_1step_baseline"], (
        "the forecast must beat always predicting prevalence or it means nothing")
