"""Runtime next-technique predictor — the shipped Engine 2 transition model.

Shipped model: **interpolated Markov**. It blends three estimates of
P(next | history) with weights tuned on the validation split:

    P = l2 * P(next | prev, last)  +  l1 * P(next | last)  +  l0 * P(next)

Deleted interpolation matters here because the training set is small (140
sequences). A pure second-order model is sharper when it has seen the exact
bigram and useless when it has not; interpolation keeps the higher-order signal
without collapsing to zero on unseen context. Measured on 780 held-out
prediction points it beats the previous first-order model, and a paired
bootstrap keeps it ahead in 96% of resamples (`reports/model_experiments.md`).

Artifact: `models/next_technique_markov.pkl`.
  v2 (current) {"version": 2, "order2": {(a,b): [[t,n],..]}, "order1": {...},
                "unigram": [[t,n],..], "lambdas": [l2, l1, l0]}
  v1 (legacy)  {last: [[t, n], ...]}  -- read as order1-only so an old artifact
               still serves predictions instead of crashing.
"""
from __future__ import annotations

import pickle
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MARKOV_PATH = ROOT / "models" / "next_technique_markov.pkl"

_state: dict = {}


def _load() -> dict:
    if "m" not in _state:
        with MARKOV_PATH.open("rb") as f:
            raw = pickle.load(f)
        if isinstance(raw, dict) and raw.get("version") == 2:
            m = raw
        else:                                    # legacy first-order table
            from collections import Counter
            uni: Counter = Counter()
            for succ in (raw or {}).values():
                for t, n in succ:
                    uni[t] += n
            m = {"version": 1, "order2": {}, "order1": raw or {},
                 "unigram": [[t, int(n)] for t, n in uni.most_common()],
                 "lambdas": [0.0, 1.0, 0.0]}
        m["_uni_total"] = sum(n for _, n in m["unigram"]) or 1
        m["_fallback"] = [t for t, _ in m["unigram"]]
        _state["m"] = m
    return _state["m"]


def _dist(pairs) -> tuple[dict, int]:
    d = {t: n for t, n in (pairs or [])}
    return d, (sum(d.values()) or 1)


def rank_next(technique_ids: list[str], k: int = 5) -> tuple[list[tuple[str, float]], str]:
    """Return [(technique_id, probability), ...] and the source label.

    Probabilities are real interpolated transition probabilities. When no
    context has ever been observed the model falls back to global frequency,
    and those suggestions are reported honestly with their unigram probability.
    """
    m = _load()
    l2, l1, l0 = m["lambdas"]
    last = technique_ids[-1] if technique_ids else None
    prev = technique_ids[-2] if len(technique_ids) >= 2 else None

    d2, n2 = _dist(m["order2"].get((prev, last))) if prev and last else ({}, 1)
    d1, n1 = _dist(m["order1"].get(last)) if last else ({}, 1)
    duni, nuni = _dist(m["unigram"])

    cands = set(d2) | set(d1) | set(duni)
    scored = []
    for t in cands:
        p = l0 * (duni.get(t, 0) / nuni)
        if d1:
            p += l1 * (d1.get(t, 0) / n1)
        if d2:
            p += l2 * (d2.get(t, 0) / n2)
        if p > 0:
            scored.append((t, p))
    scored.sort(key=lambda x: (-x[1], x[0]))

    source = ("markov-interpolated-order2" if d2 else
              "markov-interpolated-order1" if d1 else "frequency-fallback")
    return scored[: max(1, k)], source


def top_ids(technique_ids: list[str], k: int = 3) -> list[str]:
    return [t for t, _ in rank_next(technique_ids, k)[0]]


def demo() -> None:
    """Self-check: predictions are ranked, probabilities are sane."""
    m = _load()
    any_last = next(iter(m["order1"]), None)
    preds, src = rank_next([any_last] if any_last else [], 5)
    assert preds, "expected at least one prediction"
    assert all(0.0 <= p <= 1.0 for _, p in preds), f"probabilities out of range: {preds}"
    assert preds == sorted(preds, key=lambda x: (-x[1], x[0])), "not ranked"
    print(f"predictor ok (v{m['version']}, lambdas={m['lambdas']}, src={src}): "
          f"{[(t, round(p, 3)) for t, p in preds[:3]]}")


if __name__ == "__main__":
    demo()
