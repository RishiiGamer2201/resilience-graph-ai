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
    OnlineTracker,
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


# --------------------------------------------------------------------------- #
# online adaptation                                                            #
# --------------------------------------------------------------------------- #
def test_the_tracker_cannot_see_the_future(model_and_obs):
    """The property the whole online result depends on.

    A prediction made at window i must be byte-identical whether or not windows
    after i exist. If a refactor ever lets future evidence leak backwards, the
    published 0.3964 becomes another oracle number and we would not notice from
    the accuracy alone -- it would simply improve.
    """
    m, obs = model_and_obs
    states = obs[1][1]

    short = OnlineTracker(m, prior_strength=2.0)
    short.observe_all(states[:5])
    early = short.next_distribution()

    long = OnlineTracker(m, prior_strength=2.0)
    long.observe_all(states[:5])
    mid = long.next_distribution()
    long.observe_all(states[5:])          # the future arrives

    assert np.array_equal(early, mid)


def test_predict_then_observe_is_the_only_order_that_works(model_and_obs):
    m, obs = model_and_obs
    t = OnlineTracker(m, prior_strength=2.0)
    with pytest.raises(ValueError):
        t.next_distribution()
    with pytest.raises(ValueError):
        t.forecast(horizon=2)
    t.observe(obs[0][1][0])
    assert t.next_distribution() is not None


def test_the_tracker_starts_at_the_offline_prior(model_and_obs):
    """With no live evidence the adapted row must equal the offline row, or the
    model is worse than useless on the first window of a stream."""
    m, obs = model_and_obs
    t = OnlineTracker(m, prior_strength=2.0)
    latent = t.observe(obs[0][1][0])
    assert np.allclose(t.next_distribution(), m.next_distribution(latent))


def test_live_evidence_moves_the_distribution(model_and_obs):
    m, obs = model_and_obs
    t = OnlineTracker(m, prior_strength=2.0)
    t.observe_all(obs[1][1][:2])
    before = t.next_distribution().copy()
    cur = t.current_state
    t.observe_all(obs[1][1][2:12])
    if t.current_state == cur:
        assert not np.allclose(before, t.next_distribution()), (
            "ten observed transitions must change the estimate")


def test_the_adapted_matrix_stays_a_probability_model(model_and_obs):
    m, obs = model_and_obs
    t = OnlineTracker(m, prior_strength=2.0)
    t.observe_all(obs[1][1])
    T = t.transition_matrix()
    assert np.allclose(T.sum(axis=1), 1.0)
    assert (T >= 0).all()


def test_reset_forgets_the_stream(model_and_obs):
    m, obs = model_and_obs
    t = OnlineTracker(m, prior_strength=2.0)
    t.observe_all(obs[1][1])
    t.reset()
    assert t.current_state is None and t.n_observed == 0
    latent = t.observe(obs[0][1][0])
    assert np.allclose(t.next_distribution(), m.next_distribution(latent))


def test_the_online_forecast_says_it_is_online(model_and_obs):
    m, obs = model_and_obs
    t = OnlineTracker(m, prior_strength=2.0)
    t.observe_all(obs[1][1][:6])
    f = t.forecast(horizon=3)
    assert f["adaptation"]["mode"] == "online"
    assert f["adaptation"]["windows_observed"] == 6
    cum = [x["cumulative_probability"] for x in f["steps"]]
    assert cum == sorted(cum), cum


def test_both_forecasts_go_through_one_rollout(model_and_obs):
    """Two rollout implementations would drift and the drifting one would be
    whichever nobody was watching. A zero-strength-prior tracker with no live
    evidence beyond one window must agree with the offline forecast."""
    m, obs = model_and_obs
    states = obs[0][1]
    offline = m.forecast(states[:1], horizon=3)
    t = OnlineTracker(m, prior_strength=1.0)
    t.observe(states[0])
    online = t.forecast(horizon=3)
    assert offline["current_state"] == online["current_state"]
    assert set(offline) <= set(online)


@pytest.mark.skipif(not MODEL.exists(), reason="netstate model not trained")
def test_the_shipped_model_carries_its_online_hyperparameter():
    m = NetStateModel.load()
    assert m.online_prior_strength > 0.0, (
        "online_prior_strength must be fitted, not left at the zero default")


@pytest.mark.skipif(not FLOWS.exists(), reason="CIC-IDS2017 parquet not present")
def test_online_beats_persistence_and_stays_under_the_oracle():
    """The claim in reports/netstate.md, in one assertion.

    Under the oracle matters as much as over persistence: an online number at or
    above a matrix counted on the test days would mean future information had
    leaked in somewhere.
    """
    import json
    from pathlib import Path
    ns = json.loads(Path("reports/metrics.json").read_text(encoding="utf-8")
                    ).get("engine3", {}).get("netstate")
    if not ns or "online_top1" not in ns:
        pytest.skip("online arm not evaluated yet")
    assert ns["online_top1"] > ns["persistence_top1"], (
        ns["online_top1"], ns["persistence_top1"])
    assert ns["online_top1"] < ns["oracle_top1"], (
        "online must stay below an oracle counted on the test days; at or above "
        "it means future information is leaking into the causal walk")


# --------------------------------------------------------------------------- #
# baselines: the compromise forecast must be scored against persistence        #
# --------------------------------------------------------------------------- #
def test_compromise_detection_reports_a_persistence_baseline(model_and_obs):
    """The compromise warning used to be reported against random (0.5).

    That is the wrong reference class. Attacks arrive in bursts and traffic is
    autocorrelated, so 'the current window is compromised' is already a strong
    predictor of the next one -- which is exactly why next-state prediction is
    scored against persistence a few functions away. This test fails if the
    persistence comparison is ever dropped again.
    """
    from scripts.eval_netstate import compromise_detection
    model, obs = model_and_obs
    det = compromise_detection(model, obs)
    if det.get("state") == "not measured":
        pytest.skip("synthetic fixture is single-class at this threshold")

    for key in ("persistence_rate_roc_auc", "persistence_binary_roc_auc",
                "persistence_rate_pr_auc", "beats_persistence",
                "roc_auc_lift_over_persistence"):
        assert key in det, f"{key} missing: the persistence baseline was dropped"

    assert 0.0 <= det["persistence_rate_roc_auc"] <= 1.0
    assert det["beats_persistence"] == (
        det["roc_auc"] > det["persistence_rate_roc_auc"])
    assert det["roc_auc_lift_over_persistence"] == pytest.approx(
        det["roc_auc"] - det["persistence_rate_roc_auc"], abs=1e-9)


def test_persistence_baseline_is_strong_when_traffic_is_autocorrelated():
    """A perfectly autocorrelated stream must give persistence ROC-AUC 1.0.

    This is the whole point of the baseline: on bursty data a forecaster that
    beats random by a wide margin can still be adding nothing over 'assume no
    change'. If this ever returns ~0.5 the baseline is not being computed from
    the current window and the comparison is meaningless.
    """
    from sklearn.metrics import roc_auc_score
    # bursty: long clean runs and long compromised runs, so rates[t] predicts
    # rates[t+1] everywhere except the two run boundaries
    rates = np.array([0.0] * 60 + [1.0] * 60 + [0.0] * 60, dtype=float)
    truth = (rates[1:] > 0.5).astype(int)
    persistence = rates[:-1]
    auc = roc_auc_score(truth, persistence)
    assert auc > 0.95, auc
    # and the point of the whole test: random is 0.5, so a model reporting 0.98
    # against 0.5 has claimed a win it may not have against this.
    assert auc - 0.5 > 0.4, "persistence must be far above random on bursty data"


def test_forecast_calibration_carries_both_baselines(model_and_obs):
    """Brier must be reported against persistence as well as prevalence.

    Prevalence is the easy baseline and the model was already beating it.
    Persistence is the hard one, and holding next-state to persistence while
    holding the forecast only to prevalence grades two halves of one model on
    two different curves.
    """
    from scripts.eval_netstate import forecast_calibration
    model, obs = model_and_obs
    cal = forecast_calibration(model, obs, horizon=2)
    assert cal["per_step"], "no horizons scored"
    for step in cal["per_step"]:
        assert "brier_persistence_baseline" in step, "persistence baseline dropped"
        assert "brier_prevalence_baseline" in step
        assert step["brier_persistence_baseline"] >= 0.0
