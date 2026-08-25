"""Engine 3 on the performance screen, ranked once on the server.

The world model page and the performance page both show the same estimator
comparison. If each sorted the rows and decided for itself which of our models a
baseline beat, the two screens could disagree -- and the one nobody reopened
would keep asserting a verdict the evaluation had already moved past.

So /api/metrics attaches the ranking rather than leaving it to the browser, and
these tests pin the property that matters: the two routes rank identically, and
the ranking follows the measured values rather than a remembered order.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app, _netstate_comparison

client = TestClient(app)


def _engine3() -> dict:
    r = client.get("/api/metrics")
    assert r.status_code == 200
    return r.json().get("engine3") or {}


def test_the_performance_payload_carries_the_ranking():
    e3 = _engine3()
    if not e3.get("netstate"):
        pytest.skip("engine3 not in this metrics cache")
    rows = e3["comparison"]["rows"]
    assert rows, "the screen has nothing to render"
    assert {r["key"] for r in rows} <= set(e3["netstate"]), (
        "a ranked row names a metric the evaluation never wrote")


def test_the_measured_numbers_are_still_there_untouched():
    """Attaching the ranking must not replace the raw block; the calibration and
    model-shape cards read it directly."""
    e3 = _engine3()
    if not e3.get("netstate"):
        pytest.skip("engine3 not in this metrics cache")
    from src.shared.metrics_store import load
    assert e3["netstate"] == (load().get("engine3") or {}).get("netstate")


def test_rows_are_ordered_by_measured_value():
    e3 = _engine3()
    if not e3.get("netstate"):
        pytest.skip("engine3 not in this metrics cache")
    values = [r["value"] for r in e3["comparison"]["rows"]]
    assert values == sorted(values), "the screen would draw a ranking out of order"


def test_a_loss_is_derived_not_asserted():
    """The flag must follow the numbers. Feed the same function a run where our
    offline model wins and nothing may still be marked as beaten."""
    won = _netstate_comparison({
        "marginal_top1": 0.10, "persistence_top1": 0.20,
        "next_state_top1": 0.90, "online_top1": 0.95, "oracle_top1": 0.99,
    })
    assert won["beaten"] == [], "a win is still being reported as a loss"
    assert not any(r["beaten_by_baseline"] for r in won["rows"])

    lost = _netstate_comparison({
        "marginal_top1": 0.10, "persistence_top1": 0.80,
        "next_state_top1": 0.30, "online_top1": 0.40, "oracle_top1": 0.99,
    })
    assert set(lost["beaten"]) == {"next_state_top1", "online_top1"}


def test_both_screens_are_handed_the_same_ranking():
    """The whole reason the ranking lives on the server."""
    from src.engine3.netstate import MODEL
    if not MODEL.exists():
        pytest.skip("world model artifact not built")
    e3 = _engine3()
    if not e3.get("netstate"):
        pytest.skip("engine3 not in this metrics cache")
    world = client.get("/api/netstate/model").json()["comparison"]
    assert world == e3["comparison"], (
        "the performance page and the world model page would show different "
        "orderings of the same evaluation")


def test_a_metrics_cache_without_engine3_still_serves():
    """The section renders an empty state; it must not take the page down."""
    assert client.get("/api/metrics").status_code == 200
    assert _netstate_comparison({}) == {"rows": [], "summary": "", "beaten": []}
