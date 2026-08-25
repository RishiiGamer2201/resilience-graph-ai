"""Runtime ATT&CK technique-association ranker.

Shipped model: **interpolated Markov**. It blends three estimates of
P(next | history) with weights tuned on the validation split:

    P = l2 * P(next | prev, last)  +  l1 * P(next | last)  +  l0 * P(next)

Deleted interpolation matters here because the training set is small (140
sequences). A pure second-order model is sharper when it has seen the exact
bigram and useless when it has not; interpolation keeps the higher-order signal
without collapsing to zero on unseen context. Most training rows are ATT&CK
group/campaign technique profiles sorted by a tactic heuristic, not observed
timelines. The scores are therefore association scores, not next-move
probabilities. Measured on held-out profile positions it beats the previous first-order model, and a paired
bootstrap keeps it ahead in 96% of resamples (`reports/model_experiments.md`).

Artifact: `models/next_technique_markov.pkl`.
  v3 (current) v2 fields plus data-basis and temporal-validation metadata.
  v2           {"version": 2, "order2": {(a,b): [[t,n],..]}, "order1": {...},
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

SAFE_TEMPORAL_DEFAULT = {
    "enabled": False,
    "mode": "association-only",
    "reason": (
        "Chronological next-move prediction is disabled: the shipped model was "
        "trained on tactic-ordered ATT&CK profiles and has no qualifying "
        "independent temporal benchmark."
    ),
    "data_basis": {
        "kind": "ATT&CK group/campaign technique profiles",
        "ordering": "heuristic MITRE ATT&CK tactic order",
        "observed_timeline": False,
    },
}


def _load() -> dict:
    if "m" not in _state:
        with MARKOV_PATH.open("rb") as f:
            raw = pickle.load(f)
        if isinstance(raw, dict) and raw.get("version") in {2, 3}:
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


def temporal_prediction_status() -> dict:
    """Return the artifact's fail-closed chronological-prediction gate.

    Old artifacts carry no validation metadata and therefore cannot silently
    regain next-move language. A future artifact must explicitly record a
    qualifying independent chronological benchmark before this becomes true.
    """
    status = _load().get("temporal_validation")
    if not isinstance(status, dict) or status.get("enabled") is not True:
        merged = {**SAFE_TEMPORAL_DEFAULT, **(status or {})}
        merged["enabled"] = False
        merged["mode"] = "association-only"
        return merged
    return status


def _dist(pairs) -> tuple[dict, int]:
    d = {t: n for t, n in (pairs or [])}
    return d, (sum(d.values()) or 1)


def rank_associations(technique_ids: list[str], k: int = 5) -> tuple[list[tuple[str, float]], str]:
    """Return profile-association scores and the source label.

    The values are normalized frequencies learned from tactic-sorted profiles.
    They are useful for ranking ATT&CK techniques to investigate, but they are
    not probabilities that a technique will happen next.
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

    source = ("profile-association-order2" if d2 else
              "profile-association-order1" if d1 else "profile-frequency-fallback")
    return scored[: max(1, k)], source


def rank_next(technique_ids: list[str], k: int = 5) -> tuple[list[tuple[str, float]], str]:
    """Compatibility alias for callers that consume a ranked association list.

    The historical name is retained for the API/artifact transition. Callers
    must not describe the returned values as chronological next-move evidence.
    """
    return rank_associations(technique_ids, k)


def top_ids(technique_ids: list[str], k: int = 3) -> list[str]:
    return [t for t, _ in rank_associations(technique_ids, k)[0]]


def generate_prediction_narrative(
    predictions: list[tuple[str, float] | dict],
    technique_chain: list[str] | None = None,
) -> str:
    """Plain-English explanation of associated ATT&CK techniques.

    Two things were removed from an earlier version:

    - A closing sentence, "Proactive isolation of active pivot hosts will
      interrupt this path before crown-jewel assets are compromised." That is an
      unqualified promise about the future, and this function has no basis for
      one.
    - Hand-written action prose selected by keyword-matching the technique name,
      so "Remote Services" became "pivoting laterally to compromise adjacent
      domain infrastructure" whether or not that had happened. The real ATT&CK
      description is available from the parsed STIX and is used instead.

    The data basis is stated inline so a profile-position score cannot be
    mistaken for evidence about chronological attacker behaviour.
    """
    if not predictions:
        return ("No associated technique could be ranked: the observed technique "
                "set does not match a profile association learned by the model.")

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
            prob = float(item.get("association_score",
                                  item.get("score", item.get("probability", 0.0))) or 0.0)
            name = item.get("name") or names.get(tid, tid)
        else:
            tid, prob = str(item[0]), float(item[1])
            name = names.get(tid, tid)
        rows.append((tid, name, prob))

    if not rows:
        return "No associated technique could be ranked for this profile."

    lead = ""
    if technique_chain:
        last = technique_chain[-1]
        lead = (f"The most recent technique observed is {names.get(last, last)} "
                f"({last}). ")

    parts = [f"{lead}Ranked by co-occurrence position in ATT&CK group and campaign "
             f"profiles sorted with a tactic heuristic, techniques to investigate are:"]

    for i, (tid, name, prob) in enumerate(rows, start=1):
        pct = f" — association score {prob * 100:.0f}%" if prob > 0 else ""
        # ATT&CK descriptions are markdown and carry inline links; keep the
        # link text, drop the URL, so the sentence reads as prose everywhere.
        desc = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", explanation(tid))
        desc = f" {desc}" if desc else ""
        parts.append(f"• {i}. {name} ({tid}){pct}.{desc}")

    status = temporal_prediction_status()
    parts.append("These are profile associations, not detections or a chronological "
                 "forecast: nothing here has been observed on this network. "
                 f"{status['reason']} Treat the list only as investigation leads.")
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
