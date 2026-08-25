"""Forward simulation: the properties that keep a forecast honest.

A K-step rollout is the easiest place in this product to produce impressive
nonsense. These pin the arithmetic that stops it.
"""
from __future__ import annotations

import pytest

from src.shared import predictor
from src.shared.rollout import (MAX_HORIZON, RELIABLE_CONFIDENCE, STEP_DECAY,
                                simulate_progression)

CHAIN = ["T1078", "T1021"]
GRAPH = {"critical_assets_at_risk": ["DB"],
         "paths_to_critical": {"DB": ["PC", "JUMP", "DB"]}}
ARTIFACT_TEMPORAL_STATUS = predictor.temporal_prediction_status()


@pytest.fixture(autouse=True)
def validated_temporal_model(monkeypatch):
    """Keep testing rollout arithmetic behind an explicitly open gate."""
    monkeypatch.setattr(
        predictor,
        "temporal_prediction_status",
        lambda: {"enabled": True, "mode": "chronological-next-move"},
    )


@pytest.fixture()
def sim():
    return simulate_progression(CHAIN, GRAPH, k_steps=6, crown_jewels=["DB", "DC"])


# --------------------------------------------------------------------------- #
# arithmetic that must hold                                                    #
# --------------------------------------------------------------------------- #
def test_cumulative_probability_never_decreases(sim):
    """P(reached impact BY step k) cannot fall as k grows. It did, because the
    curve was being multiplied by a decaying confidence -- conflating a
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


# --------------------------------------------------------------------------- #
# the constant must trace to a RECOMPUTED measurement, not to prose            #
# --------------------------------------------------------------------------- #
# The measured top-3 hit counts per horizon, over the fixed population of 544
# held-out prefixes. These integers -- not any number parsed out of the markdown
# -- are what the cheap tests below refit STEP_DECAY from.
# `test_the_whole_measurement_reproduces_from_the_corpus` re-derives these counts
# from the corpus itself, so they cannot quietly rot into magic numbers.
MEASURED_HITS = [245, 163, 122, 78, 82, 65, 55, 54]
MEASURED_PREFIXES = 544
MEASURED_SEQUENCES = 29
REGRESSION_POINTS = 8          # one accuracy per horizon; NOT the prefix count


def _eval_script():
    """Import scripts/eval_rollout_decay.py (not a package, so path it in)."""
    import sys

    from src.shared.rollout import ROOT
    sys.path.insert(0, str(ROOT / "scripts"))
    import eval_rollout_decay
    return eval_rollout_decay


def _measured_accuracy():
    return [100 * h / MEASURED_PREFIXES for h in MEASURED_HITS]


def _report_text():
    from src.shared.rollout import ROOT
    report = ROOT / "reports" / "rollout_decay.md"
    assert report.exists(), "STEP_DECAY has no measurement report behind it"
    return report.read_text(encoding="utf-8")


def _rollout_source():
    import pathlib

    import src.shared.rollout as rollout
    return pathlib.Path(rollout.__file__).read_text(encoding="utf-8")


def test_the_decay_constant_is_what_the_fit_recomputes():
    """STEP_DECAY must be the number the fit produces, RECOMPUTED here.

    This used to regex the value out of the committed markdown and compare it to
    the constant, which meant editing one number in the .md made any constant
    pass. The report is prose; it cannot be the authority for the thing it
    describes. So the fit is re-run from the measured hit counts instead.
    """
    d, r2, r2_anchored = _eval_script().fit_decay(_measured_accuracy())

    assert round(d, 2) == STEP_DECAY, (
        f"code ships STEP_DECAY = {STEP_DECAY}, the fit recomputes {d:.4f}")
    assert abs(d - 0.7744) < 5e-5, d
    assert abs(r2 - 0.719) < 5e-4, r2
    assert abs(r2_anchored - 0.862) < 5e-4, r2_anchored


def test_the_reported_r2_is_the_one_that_explains_the_decay():
    """R^2 must not be inflated by the r(1) = 1 anchor.

    `fit_decay` enumerates from 0, so step 1 enters as
    `(0, log(acc[0]/acc[0])) = (0, 0.0)`. That point is the definition of the
    ratio, not an observation: it sits exactly on the line so it adds nothing to
    ss_res, while adding its full squared deviation to ss_tot. Counting it took
    R^2 from 0.719 to 0.862 without the curve explaining anything more.
    """
    fit_decay = _eval_script().fit_decay
    acc = _measured_accuracy()
    d, r2, r2_anchored = fit_decay(acc)

    assert r2 < r2_anchored, "the anchor is supposed to inflate R^2; it did not"
    assert r2_anchored - r2 > 0.1, (r2, r2_anchored)

    # the anchor cannot move the slope -- dropping it must leave d untouched
    import math
    pts = [(h, math.log(a / acc[0])) for h, a in enumerate(acc)]
    slope_all = sum(h * y for h, y in pts) / sum(h * h for h, _ in pts)
    slope_no_anchor = (sum(h * y for h, y in pts[1:])
                       / sum(h * h for h, _ in pts[1:]))
    assert abs(slope_all - slope_no_anchor) < 1e-12, "the anchor moved the slope"

    # and the report must lead with the honest one
    text = _report_text()
    import re
    headline = re.search(r"R² = \*\*([0-9.]+)\*\*", text)
    assert headline, "fit quality (R²) is not reported"
    assert abs(float(headline.group(1)) - r2) < 5e-4, (
        f"report leads with R² {headline.group(1)}, the decay R² is {r2:.3f}")
    assert f"{r2_anchored:.3f}" in text, (
        "the inflated R² should still be disclosed, labelled as inflated")


def test_the_report_does_not_call_the_prefix_count_the_regressions_n():
    """544 is the population behind the accuracies, not the fit's sample size.

    `fit_decay` takes ONE argument: a list of 8 accuracies. The least squares has
    8 data points and 1 free parameter. 544 never enters it. The report used to
    print "n = 544 held-out prefixes" in the slot where a regression's n belongs.
    """
    text = _report_text()
    assert "n = 544 held-out prefixes" not in text, (
        "544 is being presented as the regression's n again")

    # both numbers must appear, distinctly labelled
    assert f"{REGRESSION_POINTS} data points" in text
    assert str(MEASURED_PREFIXES) in text and str(MEASURED_SEQUENCES) in text
    assert "never a row in the fit" in text


def test_the_prefixes_are_not_claimed_to_be_independent():
    """544 overlapping prefixes from 29 sequences are not 544 observations."""
    text = _report_text()
    assert "effective sample size" in text
    assert "bootstrap" in text.lower(), "no interval on d is reported"
    # the interval has to be sequence-level, and it has to be stated
    import re
    ci = re.search(r"sequence bootstrap, 95%.*?\*\*\[([0-9.]+), ([0-9.]+)\]\*\*", text)
    assert ci, "the sequence bootstrap interval is not reported"
    lo, hi = float(ci.group(1)), float(ci.group(2))
    assert lo < STEP_DECAY < hi, (lo, hi)
    assert hi - lo > 0.05, "a sequence-level interval this narrow is suspicious"


def test_the_reliable_horizon_margin_is_disclosed_next_to_the_claim():
    """"The horizon moved from 3 to 5" survives on 0.00084. Say so, or drop it.

    Step 5 clears RELIABLE_CONFIDENCE only when d^4 >= 0.35, i.e.
    d >= 0.35 ** 0.25 = 0.769161. Shipped 0.77 clears by 0.00084 -- far inside
    the band of d values the fit cannot tell apart. A report that simultaneously
    says the fit "does not support four significant figures" and asserts step 5
    unqualified is claiming both sides of the same digit.
    """
    d_min = RELIABLE_CONFIDENCE ** 0.25
    margin = STEP_DECAY - d_min
    assert 0 < margin < 0.001, (
        f"margin is now {margin:.5f}; the disclosures below assume it is tiny")

    # the 5% SSE band straddles the flip point, so the flip is unresolvable
    band = _eval_script().sse_band(_measured_accuracy())
    assert band[0] < d_min < band[1], (
        f"flip point {d_min:.6f} no longer sits inside the SSE band {band}")

    for name, text in (("report", _report_text()),
                       ("rollout.py", _rollout_source())):
        assert f"{margin:.5f}" in text, (
            f"{name} does not state the {margin:.5f} margin the step-5 claim rests on")
        assert "0.769161" in text, f"{name} does not state the flip threshold"


def test_the_alternative_fit_is_disclosed():
    """A linear-space fit on the same ratios fits them better and gives 0.7420.

    Not mentioning it would make log space look like the only option rather than
    a choice -- and the choice moves d by more than the bootstrap's resolution.
    """
    ev = _eval_script()
    acc = _measured_accuracy()
    d = ev.fit_decay(acc)[0]
    d_lin, r2_lin, r2_lin_of_d_log = ev.fit_decay_linear(acc, d)

    assert abs(d_lin - 0.7420) < 5e-4, d_lin
    assert r2_lin > r2_lin_of_d_log, "linear space was supposed to fit better"

    text = _report_text()
    assert f"{d_lin:.4f}" in text, "the linear-space alternative is not reported"
    assert f"{r2_lin:.3f}" in text and f"{r2_lin_of_d_log:.3f}" in text
    assert "Log space is a CHOICE" in _rollout_source()


def test_the_shipped_method_string_labels_its_sample_sizes(sim):
    """The API payload carried "over 544 held-out prefixes, R^2 0.870" -- both
    mislabelled. Whatever ships to a caller has to be the honest version."""
    decay = sim["method"]["decay"]
    assert "reports/rollout_decay.md" in decay
    assert "fitted" in decay
    assert "544 held-out prefixes from 29" in decay, (
        "the payload must say what the 544 are and how many clusters they form")
    assert "8 points in the regression" in decay or "points in the regression" in decay
    assert "0.719" in decay, "the payload still quotes an R^2 it did not earn"
    assert "R^2 0.862" not in decay


def test_the_whole_measurement_reproduces_from_the_corpus():
    """Re-run the experiment end to end and check every pinned number.

    Slowest test in the file (~10s): it rolls 544 prefixes forward 8 steps each.
    Worth it -- this is what stops MEASURED_HITS above from rotting into a second
    set of magic numbers, and the only check that would catch the model itself
    changing underneath the constant. The cheap tests above cover the fit
    arithmetic and the disclosures; this one covers the corpus.
    """
    R = _eval_script().measure(quiet=True)

    assert R["n"] == MEASURED_PREFIXES
    assert R["n_seqs"] == MEASURED_SEQUENCES
    assert R["n_points"] == REGRESSION_POINTS
    assert [round(a * MEASURED_PREFIXES / 100) for a in R["acc"]] == MEASURED_HITS
    assert round(R["d"], 2) == STEP_DECAY
    assert abs(R["r2"] - 0.719) < 5e-4
    assert R["horizon"] == 5


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
    assert "not detections or a simulation of attacker intent" in sim["honesty"]


# --------------------------------------------------------------------------- #
# wired into the investigation                                                 #
# --------------------------------------------------------------------------- #
def test_the_investigation_disables_unvalidated_chronology(monkeypatch):
    monkeypatch.setattr(predictor, "temporal_prediction_status",
                        lambda: ARTIFACT_TEMPORAL_STATUS)
    from fastapi.testclient import TestClient

    from api.main import app
    r = TestClient(app).post("/api/investigate",
                             json={"scenario": "aiims_ransomware"},
                             headers={"X-Role": "analyst"})
    assert r.status_code == 200
    f = r.json()["impact"]["progression_forecast"]
    assert f["available"] is False
    assert f["mode"] == "association-only"
    assert f["associations"]
    assert "timeline benchmark" in f["reason"]
    assert "steps" not in f


def test_current_artifact_fails_closed_on_temporal_claims(monkeypatch):
    assert ARTIFACT_TEMPORAL_STATUS["enabled"] is False
    assert ARTIFACT_TEMPORAL_STATUS["data_basis"]["observed_timeline"] is False
    assert ARTIFACT_TEMPORAL_STATUS["benchmark"]["sequences"] == 4
    lo, hi = ARTIFACT_TEMPORAL_STATUS["benchmark"]["gain_sequence_bootstrap_95"]
    assert lo <= 0 <= hi
    monkeypatch.setattr(predictor, "temporal_prediction_status",
                        lambda: ARTIFACT_TEMPORAL_STATUS)
    out = simulate_progression(CHAIN, GRAPH, k_steps=4)
    assert out["available"] is False
    assert out["mode"] == "association-only"
    assert out["associations"]
    assert "steps" not in out


def test_a_saturated_headline_says_so_instead_of_quoting_a_precise_figure():
    """99.7% is a property of noisy-OR, not evidence of near-certain compromise.

    The cumulative curve combines per-step probabilities across rollout branches,
    so it climbs past 95 whenever a few steps carry real probability and then
    stays flat. On AIIMS it runs 44.9, 91.2, 99.0, 99.5, 99.7. Leading with
    "99.7% chance of compromise" would be the same overclaim this module already
    refuses to make about steps past the reliable horizon.
    """
    from src.shared.rollout import SATURATION, simulate_progression
    out = simulate_progression(["T1078", "T1021", "T1550.002"], None, k_steps=8)
    if out["headline_probability"] < SATURATION:
        pytest.skip("this chain does not saturate; nothing to assert")
    assert out["headline_saturated"] is True
    assert "saturated" in out["headline"], out["headline"]
    assert "near-certain" in out["headline"]
    # the figure is still reported, just not presented as precision
    assert str(out["headline_probability"]) in out["headline"]


def test_the_forecast_horizon_rolls_past_the_reliable_one():
    """Otherwise `_headline` has nothing to hold back and stops guarding.

    The guard leads with the furthest step still worth quoting rather than the
    peak, and the peak is always the last step. Asking for exactly as many steps
    as the reliable horizon makes those the same step. This pins the invariant so
    a future change to STEP_DECAY cannot silently close the gap again.
    """
    from src.shared.rollout import (FORECAST_HORIZON, RELIABLE_CONFIDENCE,
                                    STEP_DECAY)
    reliable = 1
    while STEP_DECAY ** reliable >= RELIABLE_CONFIDENCE:
        reliable += 1
    assert FORECAST_HORIZON > reliable, (
        f"horizon {FORECAST_HORIZON} must exceed the reliable horizon {reliable}")
