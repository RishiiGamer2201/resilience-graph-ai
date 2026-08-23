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


RARITY_IDX = 5              # dst_rarity in FEATURES order
RARITY_SHIFT_SIGMA = 1.0    # training sigmas; see below


def out_of_distribution(X) -> tuple[bool, float]:
    """Is this log's CORPUS too unlike the training corpus for the anchors to hold?

    Returns (is_ood, shift_in_training_sigmas).

    The shipped anchors come from LANL: benign p50 -> 0, benign p99 -> 50, the 1%
    false-positive line. They only mean anything for logs shaped like the corpus
    they were measured on, and the synthetic India scenarios are not: every one of
    their 125 events alerted, because a benign-trained autoencoder reconstructs
    what it saw in training and nothing else.

    The obvious test -- "median reconstruction error above the benign p99" -- is
    WRONG, and measuring it is how that was established. It fires on
    lanl_redteam_u66, which is real LANL data and one of the cleanest inputs we
    have. Its median error is high because the log is *mostly red team*. A
    score-based test cannot separate "this log is not LANL-shaped" from "this log
    is largely compromised"; both look identical downstream, and treating the
    second as the first suppressed 208 real alerts down to 5.

    So test the INPUT, not the output, and test only the feature that is
    corpus-relative. `dst_rarity` is -log(count / corpus_size): it is a property
    of the log's own host population, not of any attacker. The other six features
    are per-user behaviour and are *supposed* to shift under attack -- measured as
    standardised shift from the training mean stored in the model artifact:

        feature            lanl_campaign  lanl_u66   aiims   cbse
        is_fail                   +1.94     +3.44    +0.36   +0.35
        new_dst_for_user          +1.70     +4.09    +2.00   +2.08
        is_ntlm                   +1.82     +4.03    +0.95   +1.00
        dst_rarity                -0.09     -0.13    -1.88   -1.83   <-- the tell

    Both LANL logs sit on the training mean for rarity while shifting hard on the
    attack-driven features. The synthetic logs do the opposite. One threshold on
    one feature separates them for a reason that can be stated in a sentence.
    """
    X = np.asarray(X, dtype="float64")
    ae = _load()
    if ae is None or X.size == 0 or X.shape[1] <= RARITY_IDX:
        return False, 0.0
    _, mean, scale = ae
    col = X[:, RARITY_IDX]
    col = col[np.isfinite(col)]
    if col.size == 0:
        return False, 0.0
    shift = float((col.mean() - mean[RARITY_IDX]) / scale[RARITY_IDX])
    if not np.isfinite(shift):
        # NaN never satisfies `abs(shift) > threshold`, so an unguarded NaN was
        # silently reported as in-distribution AND travelled into the response as
        # `rarity_shift_sigma: nan`, which Starlette refuses to serialise
        # (allow_nan=False) -- a 500 on the public upload endpoint from one blank
        # destination_host cell. Comparing NaN is always the bug; say so instead.
        return False, 0.0
    return bool(abs(shift) > RARITY_SHIFT_SIGMA), round(shift, 3)


TRIAGE_PERCENTILE = 80      # see relative_anchors


def relative_anchors(raw) -> dict:
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
    percentile that is recall 71% / precision 100% on AIIMS and 70% / 100% on
    CBSE. The percentile is an OPERATIONAL choice -- "show an analyst the top fifth
    of this log" -- not an estimate of how much of it is malicious, and callers
    must present it that way.
    """
    raw = np.asarray(raw, dtype="float64")
    p50 = float(np.percentile(raw, 50))
    cut = float(np.percentile(raw, TRIAGE_PERCENTILE))
    hi = float(raw.max())
    if not (cut > p50):
        cut = p50 + 1e-9
    if not (hi > cut):
        hi = cut * 4 + 1e-9
    # reuses the piecewise-log map: p50 -> 0, cut -> 50 (the display alert line), hi -> 100
    return {"p50": p50, "p99": cut, "hi": hi,
            "basis": f"ranked-within-this-log (top {100 - TRIAGE_PERCENTILE}% surfaced)",
            "triage_percentile": TRIAGE_PERCENTILE}


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
