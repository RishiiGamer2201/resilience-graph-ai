"""Runtime anomaly scorer — the shipped Engine 1 detector, in pure NumPy.

The detector is a benign-trained autoencoder. It is TRAINED offline with PyTorch
(`src/engine1/lanl_detect.py`) and exported to `models/ae_lanl.npz` as plain
weight matrices, so the deployed image runs inference with NumPy alone and needs
no deep-learning framework. That is what keeps `requirements-deploy.txt` slim
and the container GPU-free.

Why the autoencoder replaced IsolationForest (measured, see
`reports/model_experiments.md` and `reports/lanl_redteam_detection.md`): at the
strict 1% false-positive operating point an analyst actually runs at, the
autoencoder catches far more of the 702 real red-team events. ROC-AUC barely
moves; the operating point is where the win is.

If the exported autoencoder is missing, scoring falls back to the IsolationForest
so the app still runs from a clone that has not rebuilt the model.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
AE_PATH = ROOT / "models" / "ae_lanl.npz"
IFOREST_PATH = ROOT / "models" / "iforest_lanl.joblib"

_state: dict = {}


def available() -> bool:
    return AE_PATH.exists()


def _load():
    """Load weights once. Returns (layers, mean, scale) or None if unavailable."""
    if "ae" not in _state:
        if not AE_PATH.exists():
            _state["ae"] = None
        else:
            z = np.load(AE_PATH)
            n = int(z["n_layers"])
            _state["ae"] = (
                [(z[f"W{i}"].astype("float64"), z[f"b{i}"].astype("float64"))
                 for i in range(n)],
                z["mean"].astype("float64"),
                z["scale"].astype("float64"),
            )
    return _state["ae"]


def anchors() -> dict | None:
    """The three calibration anchors stored with the weights:
    benign p50 (-> 0), benign p99 (-> 50, the 1% FPR line), hi (-> 100).
    None if unavailable (old artifact or no autoencoder)."""
    if not AE_PATH.exists():
        return None
    z = np.load(AE_PATH)
    if "benign_p99" not in z:
        return None
    p50, p99 = float(z["benign_p50"]), float(z["benign_p99"])
    hi = float(z["hi_anchor"]) if "hi_anchor" in z else p99 * 4
    if not (p99 > p50 and hi > p99):
        return None
    return {"p50": p50, "p99": p99, "hi": hi}


def calibrate(raw, ref: dict) -> np.ndarray:
    """Map raw reconstruction error to 0-100 with a PIECEWISE-LOG scale.

    benign p50 -> 0, benign p99 -> 50 (the 1% false-positive alert threshold),
    hi -> 100. Log within each segment because the error is heavy-tailed, so a
    real attack spreads across 50-100 by severity instead of pegging at 100.

    Accepts either the 3-anchor ref {p50,p99,hi} or a legacy {lo,hi} linear ref
    (older score_ref.json), so an out-of-date cache still scores sanely.
    """
    raw = np.asarray(raw, dtype="float64")
    if "p99" in ref:                             # piecewise-log (current)
        p50, p99, hi = ref["p50"], ref["p99"], ref["hi"]
        lr, l50, l99, lhi = np.log1p(raw), np.log1p(p50), np.log1p(p99), np.log1p(hi)
        lo_seg = 50.0 * np.clip((lr - l50) / (l99 - l50 + 1e-12), 0, 1)
        hi_seg = 50.0 + 50.0 * np.clip((lr - l99) / (lhi - l99 + 1e-12), 0, 1)
        return np.where(raw <= p99, lo_seg, hi_seg)
    lo, hi = ref["lo"], ref["hi"]                # legacy linear
    return np.clip((raw - lo) / (hi - lo + 1e-9), 0, 1) * 100


def _iforest():
    if "if" not in _state:
        import joblib
        _state["if"] = joblib.load(IFOREST_PATH) if IFOREST_PATH.exists() else None
    return _state["if"]


def raw_scores(X: np.ndarray) -> np.ndarray:
    """Anomaly score per row, higher = more anomalous.

    Autoencoder: mean squared reconstruction error on standardised features.
    A benign-trained autoencoder reconstructs normal behaviour well and unusual
    behaviour badly, so the error itself is the anomaly signal.
    """
    X = np.asarray(X, dtype="float64")
    ae = _load()
    if ae is None:                                   # fallback: shipped IsolationForest
        b = _iforest()
        if b is None:
            raise FileNotFoundError(
                f"no detector found: expected {AE_PATH.name} or {IFOREST_PATH.name}")
        return -b["model"].score_samples(b["scaler"].transform(X))

    layers, mean, scale = ae
    h = (X - mean) / scale
    a = h
    for i, (W, bias) in enumerate(layers):
        a = a @ W.T + bias
        if i < len(layers) - 1:
            a = np.maximum(a, 0.0)                   # ReLU on hidden layers only
    return ((a - h) ** 2).mean(axis=1)


RARITY_IDX = 5              # dst_rarity in FEATURES order, kept as a diagnostic
CONCENTRATION_LIMIT = 0.30  # share of auth going to ONE destination; see below
MIN_SAMPLE = 30             # below this, no corpus statistic means anything
RELIABLE_SAMPLE = 300       # below this, the corpus statistic is noisy, not absent


def out_of_distribution(X, dst_counts=None) -> tuple[bool, float]:
    """Is this log's CORPUS unlike the one the anchors were measured on?

    Returns (is_ood, top1_share).

    The shipped anchors come from LANL: benign p50 -> 0, benign p99 -> 50, the 1%
    false-positive line. They only mean anything for logs shaped like that
    corpus, and the synthetic India scenarios are not: every one of their 125
    events alerted, because a benign-trained autoencoder reconstructs what it saw
    in training and nothing else.

    TWO probes were rejected before this one, and both failures are instructive.

    Median reconstruction error above the benign p99 -- rejected because it fires
    on lanl_redteam_u66, real LANL data whose median is high because the log is
    mostly red team. A score-based test cannot separate "not LANL-shaped" from
    "largely compromised", and treating the second as the first suppressed 208
    real alerts to 5.

    Standardised shift of mean `dst_rarity` -- rejected because it is a LOG-SIZE
    test wearing a distribution test's clothes. dst_rarity is
    -log(count / len(df)) = log(N) - log(count), so its mean carries log(N)
    directly. Measured on truncations of one unchanged real corpus:

        lanl_campaign_all  2732 rows   shift -0.09   in-distribution
        lanl head(600)      600 rows   shift -0.68   in-distribution
        lanl head(200)      200 rows   shift -0.98   in-distribution, by 0.02
        lanl head(60)        60 rows   shift -1.04   OUT of distribution

    Same data, same hosts, same everything. A 26-row log tested out and a 27-row
    log tested in, and the flip cost recall 0.696 -> 0.206 because the triage
    budget then applied to a log that is mostly attack.

    THIS probe is the share of authentications going to the single most common
    destination. It is a property of the host population's shape and is
    completely invariant to row count:

        log                       top-1 share
        lanl_campaign_all               0.064
        lanl head(600/200/60)     0.115 / 0.130 / 0.100   <- stable under truncation
        lanl_redteam_u66                0.051
        aiims_ransomware                0.408
        cbse_exam_breach                0.386
        synthetic benign, 5000 rows / 1500 hosts, zipf   0.126
        synthetic benign, 2000 rows /  800 hosts, zipf   0.233

    Real enterprise authentication has a long destination tail; these synthetic
    scenarios were built on a handful of hosts where a pivot or the DC takes four
    events in ten. That is a difference a sentence can explain, and unlike the
    rarity shift it does not move when you truncate the file.

    The threshold sits in an EMPTY BAND. Every log measured falls below 0.24 or
    above 0.38, so any cut in (0.24, 0.38) classifies all of them identically;
    0.30 is the middle of that gap rather than a fitted value, and this docstring
    is the evidence for the band rather than an argument for the number.
    """
    if dst_counts is None:
        return False, 0.0
    c = np.asarray([v for v in dst_counts if v > 0], dtype="float64")
    total = c.sum()
    if c.size == 0 or total <= 0:
        # No destinations at all. Reporting a top-1 share of a set with no
        # members would be inventing the number that justifies the verdict.
        return True, None
    top1 = float(c.max() / total)
    if total < MIN_SAMPLE:
        return True, round(top1, 3)
    return bool(top1 > CONCENTRATION_LIMIT), round(top1, 3)


def sample_confidence(n_events: int) -> str:
    """How much weight the corpus test can carry at this many events.

    MIN_SAMPLE used to be a hard gate that flipped the verdict AND switched the
    user-facing caveat off, so 29 events and 30 events of the same file gave 21%
    alerts with an explanation and 73% with none. One benign row should not buy
    that much confidence, and the caveat is the part that has to degrade
    smoothly even where the calibration cannot.

    A top-1 share is a ratio over a small denominator: at 30 events one busy host
    moves it several points, at 300 it barely moves. So the statistic is reported
    with how far it can be trusted, rather than being trusted absolutely one row
    after it was not trusted at all.
    """
    if n_events < MIN_SAMPLE:
        return "insufficient"
    if n_events < RELIABLE_SAMPLE:
        return "low"
    return "ok"


def rarity_shift(X) -> float:
    """Standardised shift of mean dst_rarity. DIAGNOSTIC ONLY.

    Kept because it is informative next to the concentration figure, and
    explicitly not used as the verdict: see out_of_distribution for why it is a
    log-size test rather than a distribution test.
    """
    X = np.asarray(X, dtype="float64")
    ae = _load()
    if ae is None or X.size == 0 or X.shape[1] <= RARITY_IDX:
        return 0.0
    _, mean, scale = ae
    col = X[:, RARITY_IDX]
    col = col[np.isfinite(col)]
    if col.size == 0:
        return 0.0
    shift = float((col.mean() - mean[RARITY_IDX]) / scale[RARITY_IDX])
    return round(shift, 3) if np.isfinite(shift) else 0.0


TRIAGE_PERCENTILE = 80      # see relative_anchors


def relative_anchors(raw, percentile: float | None = None) -> dict:
    """Anchors from a log's OWN distribution, for OOD inputs. A ranking, not a rate.

    Deliberately a fallback, never the default. Fixed anchors are what make a
    score mean the same thing across two uploads, and this project moved from
    batch min/max to fixed anchors precisely to get that. But an anchor measured
    on a corpus the input does not resemble is not comparable either -- it is
    wrong in a stable direction.

    WHAT THIS CANNOT DO. On an OOD log the prevalence is unknown, so no threshold
    here is a calibrated false-positive rate and none is claimed. The first
    version of this function mapped the log's own p99 to 50, which pins the alert
    rate at 1% of any input by construction -- exactly as circular as the 100% it
    replaced, just in the other direction. On the AIIMS scenario that was 2 alerts
    against 35 real attack events: recall 5.7%.

    WHAT IT CAN DO. The model's RANKING survives the distribution shift, measured
    against the labels the synthetic scenarios carry:

        aiims_ransomware   ROC 0.987   PR 0.972
        cbse_exam_breach   ROC 0.988   PR 0.975

    So rank the events and surface the top slice for triage. At the 80th
    percentile that is recall 71.4% / precision 100% on AIIMS and 70.3% / 100% on
    CBSE. The percentile is an OPERATIONAL choice -- "show an analyst the top
    fifth of this log" -- not an estimate of how much of it is malicious, and
    callers must present it that way.

    Both of those figures are precision@k and recall@k, and should never be
    quoted without the cut beside them: a fixed budget means precision cannot
    fall until the ranking puts a benign event above the line, and recall is
    capped by the budget rather than by the detector.

    The cut is not fitted, and `reports/triage_cut.md` is the evidence rather than
    the assertion. It sweeps every cut THROUGH THIS SAME PATH -- calibrate, round,
    threshold at 50, rather than thresholding raw error, which is a distinction
    worth 3 percentage points of recall -- and shows the default is CONSERVATIVE:
    precision holds at 100% to top 22% on both logs, so 20% leaves 2 and 3 true
    positives unreported at no precision cost. A cut chosen to flatter the demo
    would sit at the other end of that range, and a test fails if it moves there.
    """
    raw = np.asarray(raw, dtype="float64")
    p50 = float(np.percentile(raw, 50))
    pct = TRIAGE_PERCENTILE if percentile is None else percentile
    cut = float(np.percentile(raw, pct))
    hi = float(raw.max())

    # THE SCALE CAN COLLAPSE, and when it does it must say so rather than nudge
    # itself back to plausible. If the median and the triage cut coincide there
    # is no distribution left to rank against: every event lands on 0 or 100 and
    # nothing between is reachable. That is what a perfectly uniform log does --
    # a password spray at one target, a scripted beacon, an automated loop --
    # and the old code padded p50 by 1e-9 and carried on, so 1,000 identical
    # events produced one confident 100 and a critical incident.
    #
    # The padding stays, because a caller still needs numbers. The FLAG is the
    # fix: it travels with the anchors, into the calibration block, and caps the
    # severity a collapsed scale is allowed to assert.
    collapsed = bool(
        (not (cut > p50)) or np.isclose(cut, p50, rtol=1e-9, atol=1e-12)
    )
    if collapsed:
        cut = p50 + 1e-9
    if not (hi > cut):
        hi = cut * 4 + 1e-9
    # reuses the piecewise-log map: p50 -> 0, cut -> 50 (the display alert line), hi -> 100
    return {"p50": p50, "p99": cut, "hi": hi,
            "basis": (f"ranked-within-this-log (top {100 - pct:.0f}% surfaced)"
                      if not collapsed else
                      "COLLAPSED: this log has no score distribution to rank within"),
            "collapsed": collapsed,
            "triage_percentile": pct}


def scores_0_100(X: np.ndarray, ref: dict) -> np.ndarray:
    """Calibrate raw scores to 0-100 with the fixed anchors in `ref`, so a score
    means the same thing across uploads and matches the single-event endpoint."""
    return calibrate(raw_scores(X), ref)


def demo() -> None:
    """Self-check: unusual behaviour scores above routine, and the calibrated
    scale keeps benign low, the alert line near 50, and attacks high."""
    benign = [0, 0, 0, 50, 0.001, 4.0, 0]     # seen host, low fails, common dst
    mal = [0, 1, 1, 20, 0.05, 10.0, 1]        # new host + new source, NTLM, rare dst
    r = raw_scores(np.array([benign, mal], dtype="float64"))
    assert r[1] > r[0], f"malicious vector must score higher: {r}"
    ref = anchors()
    if ref:
        s = calibrate(r, ref)
        assert 0 <= s[0] < 50 <= s[1] <= 100, f"calibration off: {s}"
        print(f"detector ok (ae={available()}): benign score {s[0]:.0f} < malicious {s[1]:.0f} "
              f"| anchors p50={ref['p50']:.4f} p99={ref['p99']:.4f} hi={ref['hi']:.3f}")
    else:
        print(f"detector ok (ae={available()}): benign {r[0]:.5f} < malicious {r[1]:.5f}")


if __name__ == "__main__":
    demo()
