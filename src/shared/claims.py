"""Evidence-calibrated claims: what is observed, inferred, predicted, or missing.

The product's central honesty problem, stated plainly in
`research/codex/it_ot_attack_detection_digital_twin_research.md` (§6, §7, §15):

  * An anomaly says an observation is *unusual*. It does not say it is malicious.
    Mapping an anomalous-but-successful login straight to `T1078 Valid Accounts`
    asserts adversarial use of a legitimate account, which the observation alone
    does not support.
  * A single "87% attack score" hides four different questions. Anomaly,
    likelihood, impact and confidence must be reported separately.
  * Repeating the same evidence through several detectors, agents or feeds must
    never increase confidence. Independent corroboration may.

So every ATT&CK conclusion this system draws is a `Claim` with a status, the
evidence behind it, the evidence it is still missing, and the benign alternatives
that have not been ruled out. Confidence is computed by noisy-OR across
*independence groups*, so duplicates are free and corroboration is not.

    from src.shared.claims import Claim, Evidence, ClaimStatus
    c = Claim(subject="host:WARD-PC-013", predicate="MAPS_TO", object="T1078",
              status=ClaimStatus.INFERRED)
    c.add_evidence(Evidence(id="evt-1", kind="auth-anomaly", source="detector",
                            independence_group="detector:autoencoder",
                            strength=0.8, reliability=0.7))
    c.confidence          # 0.56
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ClaimStatus(str, Enum):
    """How strongly the system is willing to stand behind a claim.

    The ordering matters: it is the vocabulary the UI shows an analyst, and the
    difference between OBSERVED and INFERRED is the difference between "we saw
    this" and "we think this explains what we saw".
    """

    OBSERVED = "observed"       # directly present in the telemetry, not derived
    INFERRED = "inferred"       # a rule or model derived it from observations
    PREDICTED = "predicted"     # a hypothesis about what has not happened yet
    CONFIRMED = "confirmed"     # corroborated by independent authoritative evidence
    DISPUTED = "disputed"       # contradicted by other evidence
    RETRACTED = "retracted"     # withdrawn


# Statuses an analyst may act on without further qualification. PREDICTED and
# DISPUTED deliberately are not here.
ACTIONABLE = {ClaimStatus.OBSERVED, ClaimStatus.CONFIRMED}


@dataclass(frozen=True)
class Evidence:
    """One piece of support for a claim.

    `independence_group` is the load-bearing field. Two evidence items derived
    from the same raw event, the same sensor, or the same upstream feed share a
    group and therefore cannot corroborate each other. Getting this wrong is how
    a system talks itself into certainty.
    """

    id: str
    kind: str                      # auth-anomaly, attack-citation, kev-listing...
    source: str                    # the module or document that produced it
    independence_group: str
    strength: float = 0.5          # how strongly THIS evidence supports the claim
    reliability: float = 0.5       # how much this source has earned trust, 0-1
    detail: str = ""

    def __post_init__(self) -> None:
        for name in ("strength", "reliability"):
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{name} must be within 0..1, got {v}")

    @property
    def support(self) -> float:
        return self.strength * self.reliability

    def as_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "source": self.source,
                "independence_group": self.independence_group,
                "strength": self.strength, "reliability": self.reliability,
                "support": round(self.support, 4), "detail": self.detail}


def combine(evidence: list[Evidence]) -> float:
    """Noisy-OR across independence groups; within a group, the strongest wins.

        C = 1 - product over independent groups of (1 - max support in group)

    Two properties this must have, both tested:
      * adding a duplicate of evidence already present changes nothing;
      * adding genuinely independent evidence increases confidence, but never
        past 1.0.
    """
    if not evidence:
        return 0.0
    strongest: dict[str, float] = {}
    for e in evidence:
        g = e.independence_group
        strongest[g] = max(strongest.get(g, 0.0), e.support)
    product = 1.0
    for support in strongest.values():
        product *= (1.0 - support)
    return round(1.0 - product, 4)


@dataclass
class Claim:
    """A single assertion, with everything needed to disagree with it."""

    subject: str
    predicate: str
    object: str
    status: ClaimStatus = ClaimStatus.INFERRED
    external_id: str = ""                       # e.g. the ATT&CK technique id
    mapper: str = ""                            # what produced the claim
    evidence: list[Evidence] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)
    contradicted_by: list[Evidence] = field(default_factory=list)
    note: str = ""

    def add_evidence(self, e: Evidence) -> "Claim":
        self.evidence.append(e)
        return self

    def contradict(self, e: Evidence) -> "Claim":
        self.contradicted_by.append(e)
        if self.status not in (ClaimStatus.RETRACTED,):
            self.status = ClaimStatus.DISPUTED
        return self

    @property
    def confidence(self) -> float:
        """Support for the claim, discounted by anything contradicting it."""
        for_ = combine(self.evidence)
        against = combine(self.contradicted_by)
        return round(max(0.0, for_ * (1.0 - against)), 4)

    @property
    def independent_groups(self) -> int:
        return len({e.independence_group for e in self.evidence})

    @property
    def band(self) -> str:
        """Confidence as words. The input data does not justify two decimals."""
        c = self.confidence
        return ("high" if c >= 0.75 else "moderate" if c >= 0.45
                else "low" if c >= 0.2 else "very low")

    def as_dict(self) -> dict:
        return {
            "subject": self.subject, "predicate": self.predicate,
            "object": self.object, "external_id": self.external_id,
            "status": self.status.value,
            "actionable": self.status in ACTIONABLE,
            "confidence": self.confidence,
            "confidence_band": self.band,
            "independent_groups": self.independent_groups,
            "mapper": self.mapper,
            "evidence": [e.as_dict() for e in self.evidence],
            "contradicted_by": [e.as_dict() for e in self.contradicted_by],
            "missing_evidence": self.missing_evidence,
            "alternatives": self.alternatives,
            "note": self.note,
        }


# --------------------------------------------------------------------------- #
# the four numbers, kept apart                                                 #
# --------------------------------------------------------------------------- #
@dataclass
class Assessment:
    """Anomaly, likelihood, impact and confidence — reported separately.

    Research §7: "A single '87% attack score' hides too much. The UI should say,
    for example: 'likelihood high, impact critical, confidence medium; strongest
    missing evidence is endpoint process telemetry on host X.'"

    Each is 0-100 and each answers a different question:
      anomaly     how unlike its baseline the behaviour is (the detector)
      likelihood  how probable it is that a malicious path is present
      impact      what it costs if the hypothesis is right (crown jewels)
      confidence  how good the evidence is — independence, corroboration
    """

    anomaly: float | None = None
    likelihood: float | None = None
    impact: float | None = None
    confidence: float | None = None
    missing_evidence: list[str] = field(default_factory=list)

    @staticmethod
    def _band(v: float | None, kind: str = "level") -> str:
        if v is None:
            return "not measured"
        if kind == "impact":
            return ("critical" if v >= 80 else "high" if v >= 60
                    else "moderate" if v >= 35 else "low")
        return ("high" if v >= 70 else "moderate" if v >= 40
                else "low" if v >= 15 else "very low")

    def as_dict(self) -> dict:
        return {
            "anomaly": {"value": self.anomaly, "band": self._band(self.anomaly),
                        "question": "how unlike its own baseline is this behaviour?"},
            "likelihood": {"value": self.likelihood, "band": self._band(self.likelihood),
                           "question": "how probable is it that a malicious path is present?"},
            "impact": {"value": self.impact, "band": self._band(self.impact, "impact"),
                       "question": "what does it cost if this hypothesis is right?"},
            "confidence": {"value": self.confidence, "band": self._band(self.confidence),
                           "question": "how good is the evidence behind the claim?"},
            "missing_evidence": self.missing_evidence,
            "summary": self.sentence(),
            "note": ("Four separate questions, deliberately not collapsed into one "
                     "score. A single number would hide which of them is weak."),
        }

    def sentence(self) -> str:
        """The one line an analyst reads first."""
        parts = [f"likelihood {self._band(self.likelihood)}",
                 f"impact {self._band(self.impact, 'impact')}",
                 f"confidence {self._band(self.confidence)}"]
        s = ", ".join(parts)
        if self.missing_evidence:
            s += f"; strongest missing evidence is {self.missing_evidence[0]}"
        return s


def demo() -> None:
    """Self-check: duplicates do not inflate, independent corroboration does."""
    def ev(gid: str, eid: str = "e", strength=0.8, reliability=0.7) -> Evidence:
        return Evidence(id=eid, kind="test", source="demo", independence_group=gid,
                        strength=strength, reliability=reliability)

    c = Claim(subject="host:A", predicate="MAPS_TO", object="T1078",
              status=ClaimStatus.INFERRED)
    c.add_evidence(ev("detector", "e1"))
    one = c.confidence
    assert abs(one - 0.56) < 1e-9, one

    # the same signal again, from the same group -> no change at all
    c.add_evidence(ev("detector", "e2"))
    assert c.confidence == one, f"duplicate evidence inflated confidence: {c.confidence}"

    # a genuinely independent source -> confidence rises, never above 1
    c.add_evidence(ev("edr", "e3"))
    assert c.confidence > one, c.confidence
    assert c.confidence <= 1.0
    two_group = c.confidence

    # contradiction pushes it back down and flips the status
    c.contradict(ev("change-management", "e4", strength=0.9, reliability=0.9))
    assert c.status is ClaimStatus.DISPUTED
    assert c.confidence < two_group, c.confidence

    a = Assessment(anomaly=88, likelihood=62, impact=100, confidence=41,
                   missing_evidence=["endpoint process telemetry on WARD-PC-013"])
    line = a.sentence()
    assert "likelihood moderate" in line and "impact critical" in line, line
    assert "endpoint process telemetry" in line

    empty = Assessment()
    assert empty.as_dict()["likelihood"]["band"] == "not measured"

    print(f"claims ok: 1 group {one} -> duplicate {one} (unchanged) -> "
          f"2 groups {two_group} -> disputed {c.confidence}")
    print(f"           assessment: {line}")


if __name__ == "__main__":
    demo()
