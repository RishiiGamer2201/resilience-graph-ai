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
