"""Exact Shapley attribution for the anomaly detector.

"Which features drove this score?" — answered exactly, not approximated.

The SIH world-models problem statement says black-box outputs without
interpretability are not acceptable and names SHAP values or attention weights.
Our detector has **seven** features, so the full Shapley computation is
2^7 = 128 coalitions per row: cheap enough to do exactly, in NumPy, with no new
dependency and no sampling error. KernelSHAP exists to approximate this when the
feature count makes exhaustive enumeration impossible. It does not here.

    phi_i = sum over subsets S of F\\{i} of
              |S|!(n-|S|-1)!/n! * [ v(S union {i}) - v(S) ]

`v(S)` is the detector's reconstruction error with the features outside S
replaced by a benign baseline, so a Shapley value reads as "how much this
feature's actual value moved the score away from normal behaviour".

Because it is exact, the values satisfy the efficiency axiom: they sum to
`v(all features) - v(baseline)`. `explain_score` asserts that, so a broken
implementation fails loudly instead of producing plausible nonsense.

    from src.shared.attribution import explain_score
    attr = explain_score({"is_fail": 0, "new_dst_for_user": 1, ...})
    attr["attributions"][0]     # the feature that drove the score most
"""
from __future__ import annotations

from itertools import combinations
from math import factorial

import numpy as np

from src.engine1.lanl_detect import FEATURES

# A "normal" reference point. Shapley values are always relative to a baseline;
# this one is the behaviour the detector was trained to reconstruct well, so an
# attribution reads as departure from routine activity.
BASELINE = {
    "is_fail": 0.0,
    "new_dst_for_user": 0.0,
    "new_src_for_user": 0.0,
    "user_distinct_dst_sofar": 40.0,
    "user_fail_rate_sofar": 0.001,
    "dst_rarity": 4.0,
    "is_ntlm": 0.0,
}

HUMAN = {
    "is_fail": "the authentication failed",
    "new_dst_for_user": "first time this account reached this host",
    "new_src_for_user": "first time this account came from this source",
    "user_distinct_dst_sofar": "how many hosts this account has touched",
    "user_fail_rate_sofar": "this account's running failure rate",
    "dst_rarity": "how rarely the estate authenticates to this destination",
    "is_ntlm": "NTLM used instead of Kerberos",
}


def _vector(row: dict, present: set[str]) -> list[float]:
    """Feature vector with everything outside `present` set to the baseline."""
    return [float(row.get(f, BASELINE[f])) if f in present else float(BASELINE[f])
            for f in FEATURES]


def shapley_values(row: dict) -> dict[str, float]:
    """Exact Shapley value per feature for this row's anomaly score."""
    from src.shared import detector

    n = len(FEATURES)
    others = {f: [g for g in FEATURES if g != f] for f in FEATURES}

    # every coalition's value, computed in ONE batched forward pass
    subsets: list[frozenset] = []
    for size in range(n + 1):
        for combo in combinations(FEATURES, size):
            subsets.append(frozenset(combo))
    matrix = np.array([_vector(row, set(s)) for s in subsets], dtype="float64")
    scores = detector.raw_scores(matrix)
    value = {s: float(v) for s, v in zip(subsets, scores)}

    phi: dict[str, float] = {}
    for f in FEATURES:
        total = 0.0
        for size in range(n):
            weight = factorial(size) * factorial(n - size - 1) / factorial(n)
            for combo in combinations(others[f], size):
                s = frozenset(combo)
                total += weight * (value[s | {f}] - value[s])
        phi[f] = total
    return phi


def explain_score(row: dict, *, top_k: int = 7) -> dict:
    """Rank the features by how much they drove this row's anomaly score."""
    from src.shared import detector

    phi = shapley_values(row)
    full = float(detector.raw_scores([_vector(row, set(FEATURES))])[0])
    base = float(detector.raw_scores([_vector(row, set())])[0])

    # Efficiency axiom: exact Shapley values sum to the full prediction minus the
    # baseline. If this ever fails the attribution is wrong, and a wrong
    # explanation is worse than none.
    drift = abs(sum(phi.values()) - (full - base))
    assert drift < 1e-6 * max(1.0, abs(full - base)) + 1e-9, (
        f"Shapley values violate efficiency by {drift}: sum={sum(phi.values())}, "
        f"full-base={full - base}")

    ranked = sorted(phi.items(), key=lambda kv: -abs(kv[1]))[:top_k]
    span = max((abs(v) for v in phi.values()), default=0.0) or 1.0
    return {
        "method": "exact Shapley values (2^7 = 128 coalitions, no sampling)",
        "baseline": BASELINE,
        "baseline_score": round(base, 6),
        "score": round(full, 6),
        "total_attribution": round(full - base, 6),
        "attributions": [{
            "feature": f,
            "meaning": HUMAN[f],
            "value": float(row.get(f, BASELINE[f])),
            "baseline": BASELINE[f],
            "shapley": round(v, 6),
            "share": round(abs(v) / span, 4),
            "direction": "raises" if v > 0 else "lowers" if v < 0 else "neutral",
        } for f, v in ranked],
        "note": ("Exact, not approximated: with seven features the full coalition "
                 "enumeration is cheap, so there is no sampling error to report. "
                 "Values are relative to the benign baseline above and satisfy the "
                 "efficiency axiom."),
    }


def demo() -> None:
    """Self-check: the axioms hold and the drivers are the ones a human expects."""
    malicious = {"is_fail": 0, "new_dst_for_user": 1, "new_src_for_user": 1,
                 "user_distinct_dst_sofar": 20, "user_fail_rate_sofar": 0.05,
                 "dst_rarity": 10.0, "is_ntlm": 1}
    out = explain_score(malicious)
    assert out["attributions"], out

    # a row identical to the baseline must attribute nothing
    flat = explain_score(dict(BASELINE))
    assert abs(flat["total_attribution"]) < 1e-9, flat["total_attribution"]
    assert all(abs(a["shapley"]) < 1e-9 for a in flat["attributions"]), flat

    # symmetry sanity: the same input twice gives the same explanation
    assert explain_score(malicious) == out

    top = out["attributions"][0]
    print(f"attribution ok: score {out['score']:.5f} vs baseline "
          f"{out['baseline_score']:.5f}; top driver {top['feature']} "
          f"({top['direction']}, share {top['share']}) — {top['meaning']}")
    for a in out["attributions"][:4]:
        print(f"    {a['feature']:26} {a['shapley']:+.5f}  {a['direction']}")


if __name__ == "__main__":
    demo()
