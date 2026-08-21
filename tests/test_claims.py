"""Evidence calibration: what a claim is allowed to assert, and what it must admit.

These encode the rules from
`research/codex/it_ot_attack_detection_digital_twin_research.md` §6, §7 and §15.
The one that matters most is the last section: an anomaly score alone must never
be enough to assert MITRE T1078.
"""
from __future__ import annotations

import pytest

from src.shared.attack_mapper import CLAIM_RULES, claim_for_event, map_event
from src.shared.claims import ACTIONABLE, Assessment, Claim, ClaimStatus, Evidence, combine


def ev(group: str, eid: str = "e", strength: float = 0.8,
       reliability: float = 0.7) -> Evidence:
    return Evidence(id=eid, kind="test", source="test", independence_group=group,
                    strength=strength, reliability=reliability)


# --------------------------------------------------------------------------- #
# the rule that stops a system talking itself into certainty                    #
# --------------------------------------------------------------------------- #
def test_repeating_the_same_evidence_never_increases_confidence():
    c = Claim(subject="s", predicate="MAPS_TO", object="T1078")
    c.add_evidence(ev("detector", "e1"))
    once = c.confidence
    for i in range(2, 12):
        c.add_evidence(ev("detector", f"e{i}"))
    assert c.confidence == once, ("ten copies of one signal inflated confidence "
                                  f"from {once} to {c.confidence}")


def test_independent_corroboration_does_increase_confidence():
    c = Claim(subject="s", predicate="MAPS_TO", object="T1078")
    c.add_evidence(ev("detector"))
    one = c.confidence
    c.add_evidence(ev("edr"))
    assert c.confidence > one
    c.add_evidence(ev("network"))
    assert c.confidence <= 1.0


def test_confidence_never_exceeds_one():
    c = Claim(subject="s", predicate="p", object="o")
    for i in range(30):
        c.add_evidence(ev(f"group-{i}", f"e{i}", strength=1.0, reliability=1.0))
    assert c.confidence <= 1.0


def test_no_evidence_means_no_confidence():
    assert Claim(subject="s", predicate="p", object="o").confidence == 0.0
    assert combine([]) == 0.0


def test_contradiction_lowers_confidence_and_disputes_the_claim():
    c = Claim(subject="s", predicate="p", object="o", status=ClaimStatus.INFERRED)
    c.add_evidence(ev("detector"))
    before = c.confidence
    c.contradict(ev("change-management", strength=0.9, reliability=0.9))
    assert c.status is ClaimStatus.DISPUTED
    assert c.confidence < before


def test_evidence_rejects_out_of_range_values():
    for bad in (-0.1, 1.1):
        with pytest.raises(ValueError):
            Evidence(id="e", kind="k", source="s", independence_group="g", strength=bad)
        with pytest.raises(ValueError):
            Evidence(id="e", kind="k", source="s", independence_group="g", reliability=bad)


def test_only_observed_and_confirmed_are_actionable():
    assert ACTIONABLE == {ClaimStatus.OBSERVED, ClaimStatus.CONFIRMED}
    for status in (ClaimStatus.INFERRED, ClaimStatus.PREDICTED,
                   ClaimStatus.DISPUTED, ClaimStatus.RETRACTED):
        c = Claim(subject="s", predicate="p", object="o", status=status)
        assert c.as_dict()["actionable"] is False, status


# --------------------------------------------------------------------------- #
# research §15: T1078 must not be asserted from an anomaly score               #
# --------------------------------------------------------------------------- #
def test_anomalous_login_yields_a_candidate_not_an_assertion():
    m = map_event("unusual_successful_login")
    assert m["technique_id"] == "T1078"
    assert m["claim_status"] == "inferred", "an anomaly is not an observation of T1078"
    assert m["claim_strength"] <= 0.35, "anomaly alone must carry little weight"


def test_the_anomalous_login_claim_admits_what_it_cannot_see():
    m = map_event("unusual_successful_login")
    missing = " ".join(m["missing_evidence"]).lower()
    assert "endpoint" in missing or "process" in missing
    assert "mfa" in missing or "managed" in missing


def test_benign_explanations_are_kept_on_the_record():
    """The research names these four explicitly."""
    alts = " ".join(map_event("unusual_successful_login")["alternatives"]).lower()
    for benign in ("role change", "travel", "maintenance", "enrollment"):
        assert benign in alts, f"benign alternative missing: {benign}"


def test_a_t1078_claim_from_one_anomaly_is_not_actionable():
    c = claim_for_event({
        "user": "lab.iyer@AIIMS", "technique_id": "T1078",
        "event_type": "unusual_successful_login", "anomaly_score": 62,
        "timestamp": 1, "source_host": "WARD-PC-041",
        "destination_host": "PACS-RADIOLOGY-01"})
    assert c["status"] == "inferred"
    assert c["actionable"] is False
    assert c["confidence"] < 0.45, c["confidence"]
    assert c["confidence_band"] in ("very low", "low")
    assert c["missing_evidence"] and c["alternatives"]


def test_even_a_maximum_anomaly_score_cannot_make_t1078_actionable():
    """The ceiling is the rule's strength, not the detector's certainty."""
    c = claim_for_event({
        "user": "u", "technique_id": "T1078",
        "event_type": "unusual_successful_login", "anomaly_score": 100,
        "timestamp": 1, "source_host": "A", "destination_host": "B"})
    assert c["confidence"] <= 0.3, c["confidence"]
    assert c["actionable"] is False


def test_the_detector_and_its_rule_are_one_independence_group():
    """The rule fires because of the detector's own features. Counting them as
    two sources would be the duplicate-evidence inflation this all exists to
    prevent."""
    c = claim_for_event({
        "user": "u", "technique_id": "T1550.002",
        "event_type": "ntlm_lateral_movement", "anomaly_score": 90,
        "timestamp": 1, "source_host": "A", "destination_host": "B"})
    assert c["independent_groups"] == 1, c["evidence"]


def test_expected_activity_claims_nothing():
    c = claim_for_event({"user": "u", "technique_id": "-",
                         "event_type": "normal_auth", "anomaly_score": 3,
                         "timestamp": 1, "source_host": "A", "destination_host": "B"})
    assert c["evidence"] == []
    assert c["confidence"] == 0.0


@pytest.mark.parametrize("event_type", sorted(CLAIM_RULES))
def test_every_calibrated_rule_is_complete(event_type):
    rule = CLAIM_RULES[event_type]
    assert rule["status"] in {s.value for s in ClaimStatus}
    assert 0.0 <= rule["strength"] <= 1.0
    assert rule["note"]
    assert rule["alternatives"], f"{event_type} claims no benign alternative exists"


def test_directly_observable_rules_outrank_inferred_ones():
    """A failed-login burst IS visible in the log; T1078 is an interpretation."""
    observed = map_event("failed_login_burst")
    inferred = map_event("unusual_successful_login")
    assert observed["claim_status"] == "observed"
    assert observed["claim_strength"] > inferred["claim_strength"]


# --------------------------------------------------------------------------- #
# research §7: four numbers, not one                                           #
# --------------------------------------------------------------------------- #
def test_assessment_keeps_the_four_questions_apart():
    a = Assessment(anomaly=88, likelihood=62, impact=100, confidence=41).as_dict()
    assert {"anomaly", "likelihood", "impact", "confidence"} <= set(a)
    assert len({a[k]["question"] for k in ("anomaly", "likelihood", "impact", "confidence")}) == 4


def test_an_unmeasured_dimension_says_so_rather_than_scoring_zero():
    a = Assessment(anomaly=50).as_dict()
    assert a["likelihood"]["value"] is None
    assert a["likelihood"]["band"] == "not measured"


def test_the_summary_sentence_names_the_biggest_gap():
    a = Assessment(likelihood=80, impact=90, confidence=20,
                   missing_evidence=["endpoint process telemetry on WARD-PC-013"])
    line = a.sentence()
    assert "likelihood high" in line
    assert "impact critical" in line
    assert "confidence low" in line
    assert "endpoint process telemetry on WARD-PC-013" in line


def test_impact_uses_consequence_words_not_probability_words():
    assert Assessment(impact=95).as_dict()["impact"]["band"] == "critical"
    assert Assessment(likelihood=95).as_dict()["likelihood"]["band"] == "high"
