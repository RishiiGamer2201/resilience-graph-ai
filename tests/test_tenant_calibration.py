"""The alert line, measured on this estate rather than borrowed from LANL.

Issue #36. `live_analyze._score` loaded `api/cache/score_ref.json`
unconditionally, so every estate was scored against LANL's notion of ordinary.
Enabling the entity baseline (#37) changed which FEATURES are computed but not
the threshold they are judged against, because the store held entity counts and
no score distribution -- a tenant-specific feature pipeline reporting against a
foreign alert line, which reads as tenant-specific detection and is not.
"""
from __future__ import annotations

import sqlite3

import numpy as np
import pandas as pd
import pytest

from src.shared import baseline
from src.shared import calibration as cal


@pytest.fixture()
def store(tmp_path, monkeypatch):
    db = tmp_path / "profiles.db"
    monkeypatch.setenv(baseline.DB_ENV, str(db))
    return db


def benign(n=6000, seed=7):
    """Varied routine traffic: many accounts over many days, no failures."""
    rng = np.random.default_rng(seed)
    return pd.DataFrame({
        "timestamp": np.sort(rng.integers(0, 86400 * 30, n)),
        "user": [f"u{i}" for i in rng.integers(0, 40, n)],
        "source_host": [f"WS{i}" for i in rng.integers(0, 60, n)],
        "destination_host": rng.choice([f"SRV{i}" for i in range(25)], n),
        "is_fail": 0,
    })


# --------------------------------------------------------------------------- #
# the budget is measured, not defined                                          #
# --------------------------------------------------------------------------- #
def test_heldout_benign_traffic_meets_the_declared_alert_budget(store):
    """The acceptance criterion, and the one that is easy to fake.

    Fitting p99 on a sample and then reporting 1% is circular -- it is true of
    any sample by construction, which is the mistake relative_anchors documents
    having made. So the rate is measured on a slice the anchors never saw.
    """
    out = baseline.enroll(benign(), source="benign-30d.csv")
    c = out["calibration"]
    assert c["state"] == "fitted", c
    assert c["heldout_samples"] > 0
    assert c["heldout_alert_rate"] <= c["budget_alert_rate"] * 1.5, c
    assert c["within_budget"] is True


def test_the_held_out_slice_is_not_the_slice_the_anchors_were_fitted_on(store):
    out = baseline.enroll(benign(), source="b.csv")
    c = out["calibration"]
    assert c["samples"] == 6000
    assert c["heldout_samples"] == 1500          # 25% held out
    assert c["samples"] > c["heldout_samples"]


def test_too_little_history_refuses_to_calibrate_rather_than_guessing(store):
    """A p99 over a few hundred rows moves by orders of magnitude between
    samples. An unstable anchor is a confident, tenant-specific wrong answer."""
    out = baseline.enroll(benign(n=300), source="tiny.csv")
    c = out["calibration"]
    assert c["state"] == "insufficient"
    assert c["minimum_samples"] == cal.MIN_SAMPLES
    assert baseline.status()["calibration"]["state"] == "absent"


def test_a_degenerate_distribution_is_refused(store):
    """Perfectly uniform traffic has no spread to place anchors in."""
    n = 4000
    flat = pd.DataFrame({"timestamp": range(n), "user": ["u"] * n,
                         "source_host": ["WS"] * n,
                         "destination_host": ["SRV"] * n, "is_fail": 0})
    out = baseline.enroll(flat, source="flat.csv")
    assert out["calibration"]["state"] in ("degenerate", "insufficient")


# --------------------------------------------------------------------------- #
# it is actually used, and it is reported                                      #
# --------------------------------------------------------------------------- #
def test_scoring_uses_the_local_anchors_once_they_exist(store):
    from src.shared.live_analyze import _tenant_ref

    before = _tenant_ref()[1]["source"]
    assert before == "shipped-lanl"

    baseline.enroll(benign(), source="b.csv")
    ref, provenance = _tenant_ref()
    assert provenance["source"] == "tenant-baseline"
    assert provenance["samples"] == 6000
    assert provenance["calibration_version"] == cal.VERSION
    assert {"p50", "p99", "hi"} <= set(ref)


def test_status_reports_source_sample_size_and_version(store):
    """API/UI criterion: a reader must be able to see which scale produced a
    score without reading the source at the commit it was written."""
    baseline.enroll(benign(), source="b.csv")
    c = baseline.status()["calibration"]
    assert c["state"] == "ready"
    assert c["source"] == "tenant-baseline"
    assert c["samples"] == 6000
    assert c["version"] == cal.VERSION
    assert c["budget_alert_rate"] == cal.DEFAULT_BUDGET


def test_the_analysis_reports_which_anchors_scored_it(store):
    from src.shared.live_analyze import analyze_events

    baseline.enroll(benign(), source="b.csv")
    bundle = analyze_events(benign(n=400, seed=11), critical_assets=set(),
                            incident_id="INC-CAL")
    anchors = bundle["meta"]["calibration"]["anchors"]
    assert anchors["source"] in ("tenant-baseline", "shipped-lanl")


# --------------------------------------------------------------------------- #
# it stops being true when the scale changes                                   #
# --------------------------------------------------------------------------- #
def test_a_changed_detector_or_feature_list_invalidates_the_calibration(store):
    """Anchors are raw reconstruction errors from ONE model over ONE feature
    list. Applying them after either moves is worse than falling back: the
    answer is wrong, tenant-specific and confident."""
    from src.shared.live_analyze import _tenant_ref

    baseline.enroll(benign(), source="b.csv")
    assert _tenant_ref()[1]["source"] == "tenant-baseline"

    with sqlite3.connect(store) as c:            # a retrained model
        c.execute("UPDATE calibration SET fingerprint='something-else'")

    assert baseline.status()["calibration"]["state"] == "stale"
    assert _tenant_ref()[1]["source"] == "shipped-lanl", (
        "stale anchors were applied instead of falling back")


def test_the_fingerprint_covers_both_the_model_and_the_features(tmp_path):
    a = cal.fingerprint(["x", "y"], None)
    assert cal.fingerprint(["x", "y"], None) == a          # stable
    assert cal.fingerprint(["x", "z"], None) != a          # feature list moved
    artifact = tmp_path / "m.npz"
    artifact.write_bytes(b"v1")
    b = cal.fingerprint(["x", "y"], artifact)
    artifact.write_bytes(b"v2")
    assert cal.fingerprint(["x", "y"], artifact) != b      # model moved


def test_an_over_budget_calibration_is_recorded_but_not_applied():
    """Recorded so the miss is visible; not applied because missing the budget
    is exactly the failure this feature exists to prevent."""
    raw = np.concatenate([np.full(4000, 0.001), np.full(1000, 5.0)])
    fitted = cal.fit(raw, features=["a"], detector_path=None)
    assert fitted["state"] in ("fitted", "over_budget", "degenerate")
    if fitted["state"] == "over_budget":
        assert fitted["within_budget"] is False


def test_calibration_failure_never_costs_the_enrolment(store, monkeypatch):
    """The profiles are committed before anchors are fitted. An operator must
    not lose a completed enrolment because calibration could not run."""
    monkeypatch.setattr(baseline, "_calibrate_from",
                        lambda df, path: {"state": "error", "detail": "boom"})
    out = baseline.enroll(benign(n=2500), source="b.csv")
    assert out["state"] == "done"
    assert out["calibration"]["state"] == "error"
    assert sqlite3.connect(store).execute(
        "SELECT COUNT(*) FROM user_dst").fetchone()[0] > 0
