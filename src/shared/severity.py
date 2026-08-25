"""One severity policy, for every score this product puts on a screen.

WHY THIS MODULE EXISTS. The bands were written out five times and two of the
copies disagreed. `api/main.py`, `src/shared/views.py`, `frontend/src/lib/
format.ts` and `frontend/src/components/AttackGraph2D.tsx` used medium >= 45 and
high >= 70; `src/shared/correlate.py` used medium >= 50 and high >= 75. So a
score of 72 was `high` on the single-event endpoint and the attacker table, and
`medium` on the incident it belonged to -- the same number, two words, in one
product.

WHICH BANDS WON, AND WHY IT IS NOT A COIN TOSS. 50 is not a taste; it is the
detector's calibrated 1% false-positive point, and the repo already says so in
two places:

    src/shared/correlate.py:  ALERT_THRESHOLD = 50   # anomaly_score >= this is an "alert"
    src/shared/attack_mapper.py: ALERT_SCORE = 50    # ... (the 1% FPR line)

Under the 45 bands, a score of 47 was labelled `medium` while the same score was
not an alert at all -- the product called something medium severity and then
declined to raise it. Anchoring `medium` to the alert threshold makes the two
statements agree: below medium is below the line where this detector claims to
be measuring anything.

The consequence is visible and intended: scores in 45-49 move medium -> low, and
70-74 move high -> medium. Cached artifacts carry severities computed under the
old bands, so they are regenerated with this change rather than left to disagree
with freshly analysed logs.

WHAT THIS MODULE IS NOT FOR. Only the 0-100 anomaly score. The other bands in
this codebase measure different questions and keep their own vocabulary:

  * `src/shared/claims.py::Assessment._band` -- likelihood, impact and evidence
    confidence, which answer "how probable", "what does it cost" and "how well
    supported", and say `moderate`/`very low` rather than `medium`/`low`;
  * `src/agents/prioritizer.py::BAND_*` -- a 0-1 risk score over ranked attack
    chains, not an anomaly score at all.

Unifying those into this table would make four different measurements share one
word, which is the failure this module exists to prevent, not repeat.
"""
from __future__ import annotations

from src.shared.thresholds import ALERT_SCORE

# Bumped when a threshold moves. It travels with the analysis and into the audit
# chain, so a stored severity can be read back against the policy that produced
# it instead of the policy that happens to be current.
POLICY_VERSION = "1.0.0"

# ALERT_SCORE by name, not 50 by value, so the tie between "is an alert" and
# "is at least medium" cannot quietly come apart.
BAND_MEDIUM: int = ALERT_SCORE      # 50 -- the alert line
BAND_HIGH: int = 75
BAND_CRITICAL: int = 90

LEVELS = ("low", "medium", "high", "critical")


def severity_from_score(score: float | int | None) -> str:
    """The severity of one 0-100 anomaly score. The only implementation.

    None and unparseable values are `low` rather than an exception: this is
    called while rendering a payload, and a missing score must not take down a
    response that has already done its real work.
    """
    try:
        v = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "low"
    if v >= BAND_CRITICAL:
        return "critical"
    if v >= BAND_HIGH:
        return "high"
    if v >= BAND_MEDIUM:
        return "medium"
    return "low"


def policy() -> dict:
    """The bands as data, for /api/health, analysis meta and audit records.

    Reported rather than documented, because the acceptance criterion for this
    is that a reader can check which policy produced a stored severity without
    reading the source at the commit it was written.
    """
    return {
        "version": POLICY_VERSION,
        "bands": {"critical": BAND_CRITICAL, "high": BAND_HIGH,
                  "medium": BAND_MEDIUM, "low": 0},
        "scale": "0-100 anomaly score",
        "basis": (f"medium starts at the detector's calibrated 1% false-positive "
                  f"point ({ALERT_SCORE}), so nothing below the alert line is "
                  f"labelled a severity the product would not raise"),
        "applies_to": "anomaly scores only; likelihood, impact, evidence "
                      "confidence and chain risk keep their own bands",
    }
