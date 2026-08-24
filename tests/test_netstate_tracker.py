"""The causal tracker, persisted per tenant, reported as evidence and only that.

Issue #42. `OnlineTracker` is the stronger of the two estimators and it is
measured -- top-1 0.3964 against a persistence baseline of 0.3620 on held-out
days -- and it had no caller. `/api/netstate/analyze` loads the OFFLINE model on
every request and forecasts from scratch, so the adaptation the measurement is
about never happens: each request starts from the prior and is thrown away.
"""
from __future__ import annotations

import sqlite3

import numpy as np
import pytest

from src.engine3.netstate import MODEL, STATE_DIM
from src.shared import baseline
from src.shared import netstate_tracker as nt

pytestmark = pytest.mark.skipif(
    not MODEL.exists(),
    reason="world model artifact not built (python -m scripts.eval_netstate)")


@pytest.fixture()
def store(tmp_path, monkeypatch):
    db = tmp_path / "profiles.db"
    monkeypatch.setenv(baseline.DB_ENV, str(db))
    return db


def windows(n=8, seed=3):
    return np.random.default_rng(seed).normal(size=(n, STATE_DIM))


# --------------------------------------------------------------------------- #
# state persists per tenant                                                    #
# --------------------------------------------------------------------------- #
def test_adaptation_survives_the_request(store):
    """Without persistence an "online" tracker is an offline one with extra
    steps: it starts from the prior every call."""
    first = nt.observe(windows(), tenant="acme")
    assert first["support"]["windows_observed"] == 8
    second = nt.observe(windows(seed=5), tenant="acme")
    assert second["restored"]["state"] == "restored"
    assert second["support"]["windows_observed"] == 16


def test_tenants_do_not_share_counts(store):
    nt.observe(windows(), tenant="acme")
    other = nt.observe(windows(seed=9), tenant="globex")
    assert other["support"]["windows_observed"] == 8


def test_counts_are_refused_when_the_model_changes(store):
    """A live count is an index into THIS model's latent states. Restored onto a
    retrained model, state 3 means something else -- and the numbers still add
    up, which is what makes it dangerous."""
    nt.observe(windows(), tenant="acme")
    with sqlite3.connect(store) as c:
        c.execute("UPDATE netstate_tracker SET model_fingerprint='other'")
    tracker, restored = nt.load("acme")
    assert restored["state"] == "reset"
    assert tracker.n_observed == 0


def test_without_a_store_it_says_the_adaptation_is_ephemeral(monkeypatch):
    monkeypatch.delenv(baseline.DB_ENV, raising=False)
    out = nt.observe(windows(), tenant="acme")
    assert out["restored"]["state"] == "ephemeral"
    assert "one request" in out["restored"]["detail"]


# --------------------------------------------------------------------------- #
# causal by construction                                                       #
# --------------------------------------------------------------------------- #
def test_a_window_is_forecast_before_it_is_observed(store):
    """Observing first would make every prediction look excellent and mean
    nothing. The tracker's own API is predict-then-observe for this reason."""
    out = nt.observe(windows(), tenant="acme", horizon=3)
    per = out["per_window"]
    assert per[0]["forecast_made_before_this_window"] is None, (
        "the first window cannot have been forecast; there was no state yet")
    assert per[3]["forecast_made_before_this_window"] is not None
    steps = per[3]["forecast_made_before_this_window"]["steps"]
    assert len(steps) == 3


def test_the_forecast_reports_what_it_rests_on(store):
    """A forecast from four observed windows and one from four hundred are
    different claims."""
    out = nt.observe(windows(n=4), tenant="acme")
    assert out["support"]["windows_observed"] == 4
    assert out["confidence"] in ("live", "prior-dominated", "prior")
    assert 0.0 <= out["support"]["live_share"] <= 1.0


def test_evidence_carries_state_horizon_and_provenance(store):
    out = nt.observe(windows(), tenant="acme", horizon=4)
    assert isinstance(out["latent_state"], int)
    assert out["horizon"] == 4
    assert out["provenance"]["evaluated_for"] == "next-window prediction"
    assert out["provenance"]["not_evaluated_for"] == "raising alerts"
    assert "0.3964" in out["provenance"]["measured"]


# --------------------------------------------------------------------------- #
# evidence, and never a severity                                               #
# --------------------------------------------------------------------------- #
def test_the_forecast_is_never_authoritative_and_never_moves_severity(store):
    """The line this feature must not cross. The model was evaluated on
    next-window prediction; its usefulness as an alert has not been measured, so
    turning a prediction into one would be an unmeasured claim wearing a
    measured one's clothes."""
    out = nt.observe(windows(), tenant="acme")
    assert out["authoritative"] is False
    assert out["affects_severity"] is False


def test_no_severity_or_alert_field_leaks_into_the_evidence(store):
    out = nt.observe(windows(), tenant="acme")
    forbidden = {"severity", "alert", "score", "band", "flagged"}
    assert not (forbidden & set(out)), forbidden & set(out)


def test_the_tracker_is_not_wired_into_incident_scoring():
    """Greps for the wiring rather than trusting the flag. If a later change
    imports the tracker into the scoring path, this fails and someone has to
    justify it."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for rel in ("src/shared/live_analyze.py", "src/shared/correlate.py",
                "src/shared/claims.py"):
        text = (root / rel).read_text()
        assert "netstate_tracker" not in text, (
            f"{rel} imports the causal tracker; its forecast is evidence and "
            f"has not been evaluated as an alert")


# --------------------------------------------------------------------------- #
# the offline surface is untouched                                             #
# --------------------------------------------------------------------------- #
def test_the_offline_endpoint_still_exists_and_is_still_labelled():
    import api.main as main

    paths = {r.path for r in main.app.routes if hasattr(r, "path")}
    assert "/api/netstate/analyze" in paths, "the offline surface was removed"
    assert "/api/netstate/track" in paths


def test_packet_shaped_windows_are_refused_by_name(store):
    """#41's contract guard, reached through the tracker."""
    out = nt.observe(np.zeros((3, 60)), tenant="acme")
    assert out["state"] == "feature_mismatch"
    assert "48" in out["detail"] and "60" in out["detail"]
