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


def benign_band() -> tuple[float, float] | None:
    """(median, 99th percentile) of the BENIGN score distribution, measured at
    training time and stored with the weights. Used to anchor the 0-100 scale to
    a real operating point. None if unavailable (old artifact or no autoencoder).
    """
    if not AE_PATH.exists():
        return None
    z = np.load(AE_PATH)
    if "benign_p99" not in z:
        return None
    p50, p99 = float(z["benign_p50"]), float(z["benign_p99"])
    return (p50, p99) if p99 > p50 else None


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


def scores_0_100(X: np.ndarray, lo: float, hi: float) -> np.ndarray:
    """Calibrate raw scores to 0-100 with FIXED anchors, so a score means the
    same thing across uploads and matches the single-event endpoint exactly."""
    raw = raw_scores(X)
    return np.clip((raw - lo) / (hi - lo + 1e-9), 0, 1) * 100


def demo() -> None:
    """Self-check: unusual behaviour must score above routine behaviour."""
    benign = [0, 0, 0, 50, 0.001, 4.0, 0]     # seen host, low fails, common dst
    mal = [0, 1, 1, 20, 0.05, 10.0, 1]        # new host + new source, NTLM, rare dst
    r = raw_scores(np.array([benign, mal], dtype="float64"))
    assert r[1] > r[0], f"malicious vector must score higher: {r}"
    print(f"detector ok (ae={available()}): benign {r[0]:.5f} < malicious {r[1]:.5f}")


if __name__ == "__main__":
    demo()
