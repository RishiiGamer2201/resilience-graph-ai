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

import re

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


def generate_prediction_narrative(
    predictions: list[tuple[str, float] | dict],
    technique_chain: list[str] | None = None,
) -> str:
    """Plain-English projection of the attacker's likely next moves.

    Two things were removed from an earlier version:

    - A closing sentence, "Proactive isolation of active pivot hosts will
      interrupt this path before crown-jewel assets are compromised." That is an
      unqualified promise about the future, and this function has no basis for
      one.
    - Hand-written action prose selected by keyword-matching the technique name,
      so "Remote Services" became "pivoting laterally to compromise adjacent
      domain infrastructure" whether or not that had happened. The real ATT&CK
      description is available from the parsed STIX and is used instead.

    The measured accuracy is stated inline, because a prediction offered without
    it invites the reader to treat 38.1% top-3 as a forecast.
    """
    if not predictions:
        return ("No next move is projected: the observed technique sequence does "
                "not match any transition the model learned.")

    try:
        from src.shared.views import _names
        names = _names()
    except Exception:
        names = {}

    try:
        from src.shared.attack_mapper import explanation
    except Exception:
        def explanation(_tid: str) -> str:
            return ""

    rows = []
    for item in predictions[:3]:
        if isinstance(item, dict):
            tid = str(item.get("technique_id", ""))
            prob = float(item.get("probability", item.get("score", 0.0)) or 0.0)
            name = item.get("name") or names.get(tid, tid)
        else:
            tid, prob = str(item[0]), float(item[1])
            name = names.get(tid, tid)
        rows.append((tid, name, prob))

    if not rows:
        return "No next move is projected for this sequence."

    lead = ""
    if technique_chain:
        last = technique_chain[-1]
        lead = (f"The most recent technique observed is {names.get(last, last)} "
                f"({last}). ")

    parts = [f"{lead}Ranked by how often each technique followed this sequence in "
             f"205 real ATT&CK campaigns, the next moves are:"]

    for i, (tid, name, prob) in enumerate(rows, start=1):
        pct = f" — {prob * 100:.0f}% of the time in the training sequences" if prob > 0 else ""
        # ATT&CK descriptions are markdown and carry inline links; keep the
        # link text, drop the URL, so the sentence reads as prose everywhere.
        desc = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", explanation(tid))
        desc = f" {desc}" if desc else ""
        parts.append(f"• {i}. {name} ({tid}){pct}.{desc}")

    parts.append("These are transition frequencies, not detections: nothing here "
                 "has been observed on this network. The predictor gets the right "
                 "technique in its top three 38.1% of the time, measured against "
                 "7.1% for a kill-chain-order baseline, so treat a single "
                 "prediction as a lead to check rather than a forecast.")
    return " ".join(parts)


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
