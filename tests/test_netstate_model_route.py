"""The world model, described over HTTP.

Engine 3 feeds no alert, so it has no place in the analysis flow — and for a
while that meant it had no surface at all, which reads as an unfinished feature
rather than a deliberate boundary. This route exists so the boundary can be
shown: the model is a quantised state space, and the point of quantising rather
than fitting a black box is that a state can be printed.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.engine3.netstate import MODEL

client = TestClient(app)

pytestmark = pytest.mark.skipif(
    not MODEL.exists(),
    reason="world model artifact not built (python -m scripts.eval_netstate)")


def test_the_model_describes_every_state_it_has():
    r = client.get("/api/netstate/model")
    assert r.status_code == 200
    d = r.json()
    assert d["ready"] is True
    assert len(d["states"]) == d["n_states"]
    assert {s["state"] for s in d["states"]} == set(range(d["n_states"]))


def test_each_state_is_printable():
    """The whole reason for quantising. A state that cannot be described is a
    black box with extra steps."""
    d = client.get("/api/netstate/model").json()
    for s in d["states"]:
        assert s["distinguishing_features"], f"state {s['state']} describes nothing"
        for f in s["distinguishing_features"]:
            assert f["feature"] in d["feature_names"]
            assert f["direction"] in ("high", "low")
            assert isinstance(f["z_score"], (int, float))
        assert 0.0 <= s["attack_rate"] <= 1.0
        assert s["training_windows"] >= 0


def test_the_transition_matrix_is_square_and_normalised():
    d = client.get("/api/netstate/model").json()
    t = d["transitions"]
    n = d["n_states"]
    assert len(t) == n and all(len(row) == n for row in t)
    for i, row in enumerate(t):
        assert abs(sum(row) - 1.0) < 0.01, f"row {i} sums to {sum(row)}"


def test_it_reports_the_evaluation_rather_than_restating_it():
    """The screen renders these numbers; they must come from the metrics store,
    so a re-run of the evaluation moves the UI and nothing has to be retyped."""
    d = client.get("/api/netstate/model").json()
    m = d["evaluation"]["netstate"]
    assert m["persistence_top1"] > m["next_state_top1"], (
        "the persistence baseline is supposed to beat the offline model here; "
        "if that changed, the screen's copy needs rewriting too")
    assert m["online_top1"] > m["persistence_top1"]
    assert m["oracle_top1"] > m["online_top1"]


def test_the_route_says_it_is_not_wired_to_anything():
    """A research surface that does not say so reads as an unfinished feature."""
    d = client.get("/api/netstate/model").json()
    assert "no screen" in d["surface"]
    assert "does not feed any alert" in d["claim"]


def test_it_needs_no_input_and_no_role():
    """It describes a shipped artifact, not a log, so it takes neither."""
    assert client.get("/api/netstate/model").status_code == 200
