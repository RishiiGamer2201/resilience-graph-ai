"""Where the alert line sits for THIS estate, measured on its own benign history.

THE DEFECT. `api/cache/score_ref.json` holds the anchors every score is mapped
through: benign p50 -> 0, benign p99 -> 50 (the 1% false-positive alert line),
attack range -> 100. They were measured on LANL. `src/shared/live_analyze._score`
loads them unconditionally, so every estate is scored against LANL's notion of
ordinary.

Turning the entity baseline on (#37) changed which FEATURES are computed --
"new for this account" starts meaning new rather than first-in-this-file -- but
it did not move the threshold those features are judged against, because the
store held entity counts and no score distribution at all. The result is a
tenant-specific feature pipeline reporting against a foreign alert line, which
reads as tenant-specific detection and is not: on the clean-log corpus up to
48.2% of events alert (reports/clean_log.md).

WHAT THIS DOES. Enrolment already collects known-good history. Scoring it gives
a benign distribution for this estate; its p50 and p99 are this estate's anchors.
Because calibrate() maps p99 -> 50 and 50 is the alert line, fitting p99 on
benign traffic IS the alert budget: 1% of benign scores land at or above it by
construction.

WHY THE HELD-OUT SPLIT IS NOT OPTIONAL. Fitting p99 on a sample and then quoting
1% is circular -- it is true of any sample by definition, which is the same
mistake `relative_anchors` documents having made. So the anchors are fitted on
one part of the history and the alert rate is MEASURED on a part they never saw.
That number is what gets stored and reported, and it can miss.

WHEN IT STOPS BEING TRUE. Anchors are raw reconstruction errors from one model
over one feature list. Change the detector artifact or the feature set and they
describe a scale that no longer exists, so every calibration carries a
fingerprint of both and is refused when it stops matching. A stale calibration
silently applied is worse than none: it is wrong, tenant-specific, and confident.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

import numpy as np

VERSION = "1.0.0"

# The share of benign traffic allowed to reach the alert line. 1% because that
# is the point the shipped scale is built around -- calibrate() maps p99 to 50,
# and 50 is ALERT_SCORE. Asking for a different budget here would move the alert
# line without moving the number that names it.
DEFAULT_BUDGET = 0.01

# Below this there is no distribution to speak of. A p99 taken over a few
# hundred rows moves by whole orders of magnitude between samples, and an anchor
# that unstable produces a confident, tenant-specific, wrong answer.
MIN_SAMPLES = 2_000
HELDOUT_FRACTION = 0.25


def fingerprint(features: list[str], detector_path: Path | None = None) -> str:
    """Identifies the scale these anchors describe: model artifact + feature list.

    Both, because either one moving invalidates them. A retrained autoencoder
    produces different raw errors for identical input; a reordered or extended
    feature list produces different input for an identical model.
    """
    h = hashlib.sha256()
    h.update("|".join(features).encode())
    if detector_path is not None and detector_path.exists():
        h.update(hashlib.sha256(detector_path.read_bytes()).digest())
    else:                                        # pragma: no cover - unbuilt tree
        h.update(b"no-detector-artifact")
    return h.hexdigest()[:16]


def fit(raw_scores: np.ndarray, *, features: list[str],
        detector_path: Path | None = None, budget: float = DEFAULT_BUDGET,
        heldout_fraction: float = HELDOUT_FRACTION) -> dict:
    """Fit anchors on benign scores and MEASURE the alert rate on held-out ones.

    Returns a dict that is either a usable calibration or a refusal that says
    why. It never raises on too little data: an operator enrolling a small first
    batch should be told the calibration is not ready, not handed a traceback.
    """
    raw = np.asarray(raw_scores, dtype="float64")
    raw = raw[np.isfinite(raw)]
    n = int(raw.size)
    if n < MIN_SAMPLES:
        return {"state": "insufficient", "samples": n,
                "minimum_samples": MIN_SAMPLES,
                "detail": (f"{n} benign scores; {MIN_SAMPLES} needed before an "
                           f"anchor is stable enough to move the alert line")}

    # Deterministic split. A shuffled one would make the reported alert rate
    # move between runs on identical input, and this number is quoted.
    rng = np.random.default_rng(20260824)
    order = rng.permutation(n)
    cut = int(n * (1.0 - heldout_fraction))
    train, heldout = raw[order[:cut]], raw[order[cut:]]

    p50 = float(np.percentile(train, 50))
    p99 = float(np.percentile(train, 100 * (1.0 - budget)))
    # The top of the scale. The shipped ref uses the attack range; there are no
    # attacks in benign history, so the largest benign error is the honest top
    # and anything above it saturates at 100.
    hi = float(train.max())
    if not (p50 < p99 < hi):
        return {"state": "degenerate", "samples": n,
                "detail": ("benign scores are too concentrated to place anchors "
                           f"(p50={p50:.3g}, p99={p99:.3g}, max={hi:.3g}); this "
                           "estate's history does not vary enough to calibrate")}

    # The measurement that makes the budget a claim rather than a definition:
    # what share of scores the anchors never saw land at or above the line.
    heldout_rate = float((heldout >= p99).mean()) if heldout.size else 0.0
    # Allowed to overshoot by half again before it is called a miss; the split
    # is finite and an exact match would be a suspicious claim.
    within = heldout_rate <= budget * 1.5

    return {
        "state": "fitted" if within else "over_budget",
        "p50": p50, "p99": p99, "hi": hi,
        "samples": n, "heldout_samples": int(heldout.size),
        "budget_alert_rate": budget,
        "heldout_alert_rate": round(heldout_rate, 5),
        "within_budget": bool(within),
        "fingerprint": fingerprint(features, detector_path),
        "version": VERSION,
        "created": time.time(),
        "detail": (
            f"fitted on {cut} benign scores; {heldout.size} held-out scores "
            f"alerted at {heldout_rate:.2%} against a {budget:.0%} budget"
            + ("" if within else " -- OVER BUDGET, not applied")),
    }


def store(c: sqlite3.Connection, fitted: dict) -> None:
    """Persist a fitted calibration. Only ever one row: the current scale."""
    c.execute(
        "INSERT INTO calibration(id,p50,p99,hi,samples,heldout_samples,"
        "budget_alert_rate,heldout_alert_rate,within_budget,fingerprint,"
        "version,created) VALUES(1,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET p50=excluded.p50, p99=excluded.p99, "
        "hi=excluded.hi, samples=excluded.samples, "
        "heldout_samples=excluded.heldout_samples, "
        "budget_alert_rate=excluded.budget_alert_rate, "
        "heldout_alert_rate=excluded.heldout_alert_rate, "
        "within_budget=excluded.within_budget, fingerprint=excluded.fingerprint, "
        "version=excluded.version, created=excluded.created",
        (fitted["p50"], fitted["p99"], fitted["hi"], fitted["samples"],
         fitted["heldout_samples"], fitted["budget_alert_rate"],
         fitted["heldout_alert_rate"], int(fitted["within_budget"]),
         fitted["fingerprint"], fitted["version"], fitted["created"]))


def load(c: sqlite3.Connection, *, features: list[str],
         detector_path: Path | None = None) -> dict | None:
    """The stored calibration, or None when there is none that still applies.

    Refuses on a fingerprint mismatch rather than degrading: anchors from a
    previous model describe a scale that no longer exists, and applying them
    produces a confident tenant-specific wrong answer, which is the one outcome
    worse than falling back to the shipped scale and saying so.
    """
    row = c.execute(
        "SELECT p50,p99,hi,samples,heldout_samples,budget_alert_rate,"
        "heldout_alert_rate,within_budget,fingerprint,version,created "
        "FROM calibration WHERE id=1").fetchone()
    if row is None:
        return None
    keys = ("p50", "p99", "hi", "samples", "heldout_samples",
            "budget_alert_rate", "heldout_alert_rate", "within_budget",
            "fingerprint", "version", "created")
    out = dict(zip(keys, row))
    out["within_budget"] = bool(out["within_budget"])
    want = fingerprint(features, detector_path)
    if out["fingerprint"] != want:
        return {**out, "state": "stale", "expected_fingerprint": want,
                "detail": ("the detector artifact or the feature list changed "
                           "since these anchors were fitted; they describe a "
                           "scale that no longer exists")}
    if not out["within_budget"]:
        return {**out, "state": "over_budget",
                "detail": ("held-out benign traffic exceeded the declared alert "
                           "budget, so these anchors are recorded but not used")}
    return {**out, "state": "ready"}


def as_ref(cal: dict) -> dict:
    """A calibration in the shape `detector.calibrate()` already accepts."""
    return {"p50": cal["p50"], "p99": cal["p99"], "hi": cal["hi"],
            "basis": ("piecewise-log on THIS estate's enrolled benign history: "
                      "p50->0, p99->50 (declared alert budget), max benign->100"),
            "source": "tenant-baseline",
            "samples": cal.get("samples"),
            "heldout_alert_rate": cal.get("heldout_alert_rate"),
            "budget_alert_rate": cal.get("budget_alert_rate"),
            "calibration_version": cal.get("version")}


def shipped_ref_source(ref: dict) -> dict:
    """The provenance block for the shipped anchors, so both paths report the
    same fields and a screen never has to guess which it is looking at."""
    return {**ref, "source": "shipped-lanl",
            "samples": None, "heldout_alert_rate": None,
            "budget_alert_rate": None,
            "calibration_version": None,
            "note": ("measured on LANL, not on this estate; enrol known-good "
                     "history to calibrate the alert line locally")}


def summary(path: Path | None, *, features: list[str],
            detector_path: Path | None = None) -> dict:
    """What /api/baseline/status and the analysis meta report about the scale."""
    if path is None or not Path(path).exists():
        return {"state": "off", "source": "shipped-lanl", "version": VERSION,
                "detail": "no baseline store; scores use the shipped LANL anchors"}
    with sqlite3.connect(path) as c:
        try:
            cal = load(c, features=features, detector_path=detector_path)
        except sqlite3.OperationalError:         # store predates this table
            return {"state": "absent", "source": "shipped-lanl", "version": VERSION,
                    "detail": "this store was created before local calibration"}
    if cal is None:
        return {"state": "absent", "source": "shipped-lanl", "version": VERSION,
                "detail": ("no local calibration yet; enrol benign history to "
                           "move the alert line onto this estate")}
    return {"state": cal["state"], "source": ("tenant-baseline"
                                              if cal["state"] == "ready"
                                              else "shipped-lanl"),
            "samples": cal["samples"], "heldout_samples": cal["heldout_samples"],
            "budget_alert_rate": cal["budget_alert_rate"],
            "heldout_alert_rate": cal["heldout_alert_rate"],
            "within_budget": cal["within_budget"],
            "fingerprint": cal["fingerprint"], "version": cal["version"],
            "detail": cal.get("detail", "local anchors in use")}


__all__ = ["VERSION", "DEFAULT_BUDGET", "MIN_SAMPLES", "fingerprint", "fit",
           "store", "load", "as_ref", "shipped_ref_source", "summary"]
