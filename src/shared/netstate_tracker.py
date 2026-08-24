"""The causal tracker, kept per tenant and attached to incidents as evidence.

WHAT WAS ALREADY TRUE. `src/engine3/netstate.py::OnlineTracker` is the stronger
of the two estimators and it is measured: top-1 0.3964 against a persistence
baseline of 0.3620 on held-out days, with its hyperparameters fitted
leave-one-day-out rather than read off the test set. It had no caller. The only
product surface, `/api/netstate/analyze`, loads the OFFLINE model on every
request and forecasts from scratch, so the adaptation the measurement is about
never happens: each request starts from the prior, observes the window it was
given, and is then thrown away.

WHAT THIS ADDS.

  * STATE THAT SURVIVES THE REQUEST. The live transition counts are stored per
    tenant in the same sqlite store the baselines and the ingest checkpoint use,
    so the tracker keeps adapting across calls and restarts. Without persistence
    an "online" tracker is an offline one with extra steps.
  * CAUSALITY THAT IS STRUCTURAL, NOT DOCUMENTED. `observe()` is the only way
    counts enter, and this module always forecasts BEFORE observing a window.
    The forecast returned for a window is the one made without it.
  * EVIDENCE, NOT SEVERITY. The forecast is attached to an incident as evidence
    and is deliberately not wired to any score, band, alert or gate. This model
    was evaluated on next-window prediction; its alert utility has not been
    measured, so turning a prediction into an alert would be a claim nobody has
    checked. `authoritative` is False and `affects_severity` is False, and there
    is a test that fails if either changes.

  * SUPPORT TRAVELS WITH THE NUMBER. A forecast from four observed windows and
    one from four hundred are different claims. `support` is the count the
    adapted row rests on and `confidence` says plainly which of the prior and
    the live counts is doing the work.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

import numpy as np

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS netstate_tracker (
    tenant TEXT PRIMARY KEY,
    n_states INTEGER NOT NULL,
    current_state INTEGER,
    windows_observed INTEGER NOT NULL DEFAULT 0,
    live_counts TEXT NOT NULL DEFAULT '[]',
    model_fingerprint TEXT NOT NULL DEFAULT '',
    updated REAL NOT NULL DEFAULT 0);
"""

DEFAULT_TENANT = "default"


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.executescript(_SCHEMA)
    return c


def _fingerprint(model) -> str:
    """Ties stored counts to the artifact they were counted under.

    A live count is an index into THIS model's latent states. Restore it onto a
    retrained model and state 3 means something else -- the numbers still add
    up, which is what makes it dangerous.
    """
    import hashlib

    h = hashlib.sha256()
    h.update(np.asarray(model.centroids, dtype="float64").tobytes())
    h.update(str(model.n_states).encode())
    return h.hexdigest()[:16]


def _store_path(path: Path | None) -> Path | None:
    if path is not None:
        return path
    from src.shared import baseline
    return baseline.db_path()


def load(tenant: str = DEFAULT_TENANT, *, path: Path | None = None):
    """Restore this tenant's tracker, or a fresh one when there is nothing usable."""
    from src.engine3.netstate import MODEL, NetStateModel, OnlineTracker

    if not MODEL.exists():
        return None, {"state": "unavailable",
                      "detail": ("world model artifact is not built; run "
                                 "python -m scripts.eval_netstate")}
    model = NetStateModel.load()
    tracker = OnlineTracker(model)
    store = _store_path(path)
    if store is None or not store.exists():
        return tracker, {"state": "ephemeral",
                         "detail": ("no store configured, so adaptation lasts "
                                    "one request; set NEXTATTACK_BASELINE_DB "
                                    "to keep it")}
    want = _fingerprint(model)
    with _lock, _connect(store) as c:
        row = c.execute(
            "SELECT current_state,windows_observed,live_counts,model_fingerprint "
            "FROM netstate_tracker WHERE tenant=?", (tenant,)).fetchone()
    if row is None:
        return tracker, {"state": "new", "detail": "no observations yet"}
    if row[3] != want:
        # Refused, not migrated. See _fingerprint.
        return tracker, {"state": "reset",
                         "detail": ("the world model changed since these counts "
                                    "were taken, so they index latent states "
                                    "that no longer mean the same thing")}
    live = np.asarray(json.loads(row[2]), dtype="float64")
    if live.shape != (model.n_states, model.n_states):
        return tracker, {"state": "reset", "detail": "stored counts have the wrong shape"}
    tracker._live = live
    tracker._current = None if row[0] is None else int(row[0])
    tracker.n_observed = int(row[1])
    return tracker, {"state": "restored", "windows_observed": tracker.n_observed}


def save(tracker, tenant: str = DEFAULT_TENANT, *, path: Path | None = None) -> None:
    store = _store_path(path)
    if store is None:
        return
    with _lock, _connect(store) as c:
        c.execute(
            "INSERT INTO netstate_tracker(tenant,n_states,current_state,"
            "windows_observed,live_counts,model_fingerprint,updated) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant) DO UPDATE SET "
            "current_state=excluded.current_state, "
            "windows_observed=excluded.windows_observed, "
            "live_counts=excluded.live_counts, "
            "model_fingerprint=excluded.model_fingerprint, "
            "updated=excluded.updated",
            (tenant, tracker.model.n_states,
             None if tracker.current_state is None else int(tracker.current_state),
             int(tracker.n_observed),
             json.dumps(np.asarray(tracker._live).tolist()),
             _fingerprint(tracker.model), time.time()))


def observe(states, tenant: str = DEFAULT_TENANT, *, horizon: int = 5,
            path: Path | None = None) -> dict:
    """Forecast, THEN observe, for each window in order. Returns the evidence.

    The forecast reported for a window is the one made before that window was
    counted. Doing it the other way round would make every prediction look
    excellent and mean nothing, which is the failure the tracker's own docstring
    warns about and the reason its API is predict-then-observe.
    """
    from src.engine3.netstate import FeatureContractError

    tracker, restored = load(tenant, path=path)
    if tracker is None:
        return restored

    windows = np.atleast_2d(np.asarray(states, dtype="float64"))
    predictions: list[dict] = []
    try:
        for window in windows:
            before = None
            if tracker.current_state is not None:
                before = tracker.forecast(horizon=horizon)
            latent = tracker.observe(window)
            predictions.append({
                "latent_state": int(latent),
                "forecast_made_before_this_window": before,
            })
    except FeatureContractError as e:
        return {"state": "feature_mismatch", "detail": str(e)}
    except ValueError as e:
        return {"state": "error", "detail": str(e)}

    save(tracker, tenant, path=path)
    return {**evidence(tracker, horizon=horizon),
            "restored": restored,
            "windows_ingested": int(len(windows)),
            "per_window": predictions}


def evidence(tracker, *, horizon: int = 5) -> dict:
    """What an incident screen shows: state, horizon, support, provenance.

    Never a severity. This model was evaluated on next-window prediction; its
    usefulness as an alert has not been measured, so a forecast here is
    something a responder may read, not something the product acts on.
    """
    if tracker is None or tracker.current_state is None:
        return {"state": "no_observations",
                "authoritative": False, "affects_severity": False,
                "detail": "no window has been observed for this tenant yet"}

    latent = int(tracker.current_state)
    live_row = float(np.asarray(tracker._live)[latent].sum())
    prior_row = float(np.asarray(tracker._prior)[latent].sum())
    total = live_row + prior_row
    share = (live_row / total) if total else 0.0
    forecast = tracker.forecast(horizon=horizon)

    return {
        "state": "ready",
        "latent_state": latent,
        "description": tracker.model.describe_state(latent),
        "horizon": horizon,
        "forecast": forecast,
        "support": {
            "windows_observed": int(tracker.n_observed),
            "live_transitions_from_this_state": live_row,
            "prior_weight_on_this_state": round(prior_row, 3),
            "live_share": round(share, 3),
        },
        "confidence": ("live" if share >= 0.5 else
                       "prior-dominated" if share > 0.05 else "prior"),
        "provenance": {
            "model": "src/engine3/netstate.py::OnlineTracker",
            "trained_on": tracker.model.trained_on,
            "measured": ("top-1 0.3964 against a persistence baseline of 0.3620 "
                         "on held-out days; hyperparameters fitted "
                         "leave-one-day-out, not on the test days"),
            "evaluated_for": "next-window prediction",
            "not_evaluated_for": "raising alerts",
        },
        # Both asserted in tests. A forecast that started moving a severity
        # would be an unmeasured claim wearing a measured one's clothes.
        "authoritative": False,
        "affects_severity": False,
    }


def status(tenant: str = DEFAULT_TENANT, *, path: Path | None = None) -> dict:
    tracker, restored = load(tenant, path=path)
    if tracker is None:
        return restored
    return {"tenant": tenant, "restore": restored,
            **evidence(tracker, horizon=5)}


__all__ = ["observe", "evidence", "status", "load", "save", "DEFAULT_TENANT"]
