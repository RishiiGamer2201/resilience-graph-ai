"""The AIIMS 2022 case file: exactly what the public record establishes.

Research §11. The failure mode this guards against is a product that draws a
complete, confident kill chain for a real incident where the Government
established one technique and nothing else.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.shared.casefile import CASEFILE_DIR, SCENARIO_CASEFILES, load_casefile

ANALYST = {"X-Role": "analyst"}


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def cf():
    return load_casefile("aiims_ransomware")


# --------------------------------------------------------------------------- #
# what may and may not be claimed                                             #
# --------------------------------------------------------------------------- #
def test_exactly_one_technique_is_confirmed(cf):
    """The Government reported encryption and availability loss. That is T1486
    and it is the only technique the public record establishes."""
    assert cf["confirmed_techniques"] == ["T1486"], cf["confirmed_techniques"]


def test_the_confirmed_technique_is_actionable_and_well_supported(cf):
    t = next(c for c in cf["claims"] if c["external_id"] == "T1486")
    assert t["status"] == "confirmed"
    assert t["actionable"] is True
    assert t["confidence"] >= 0.9
    assert t["missing_evidence"] == []


def test_lateral_movement_is_a_hypothesis_not_an_observation(cf):
    """Five affected servers make lateral movement reasonable to investigate. No
    public source establishes it, so it must not be shown as observed."""
    t = next(c for c in cf["claims"] if c["external_id"] == "T1021")
    assert t["status"] == "inferred"
    assert t["actionable"] is False
    assert t["confidence"] < 0.45
    assert t["missing_evidence"], "a hypothesis must say what would settle it"
    assert t["alternatives"], "a hypothesis must keep its benign rivals on record"


def test_no_claim_is_ever_marked_observed(cf):
    """We were not there. Nothing in a case file is first-hand observation."""
    assert all(c["status"] != "observed" for c in cf["claims"])


def test_the_unestablished_list_covers_what_people_assume(cf):
    blob = " ".join(cf["not_established"]).lower()
    for unknown in ("initial access", "ransomware family", "exfiltrat",
                    "patient data", "identity"):
        assert unknown in blob, f"not disclosed as unestablished: {unknown}"


def test_segmentation_is_a_control_weakness_not_a_technique(cf):
    weaknesses = " ".join(w["weakness"] for w in cf["control_weaknesses"]).lower()
    assert "segmentation" in weaknesses
    assert all("segment" not in c["object"].lower() for c in cf["claims"]), \
        "network segmentation is a control weakness, not an ATT&CK technique"


# --------------------------------------------------------------------------- #
# provenance                                                                   #
# --------------------------------------------------------------------------- #
def test_every_established_fact_carries_a_quote_and_a_source(cf):
    ids = {s["id"] for s in cf["sources"]}
    assert cf["established_facts"]
    for f in cf["established_facts"]:
        assert f["quote"].strip(), f
        assert f["source_id"] in ids, f


def test_every_source_has_a_resolvable_url_and_a_verification_state(cf):
    for s in cf["sources"]:
        assert s["url"].startswith("https://"), s
        assert isinstance(s["verified"], bool)
        if not s["verified"]:
            assert s["note"], "an unverified source must say why"


def test_an_unverified_source_supports_nothing(cf):
    """LS-2310 returned HTTP 403 when we tried to re-verify it. Nothing may
    depend on a source we could not read."""
    unverified = {s["id"] for s in cf["sources"] if not s["verified"]}
    for f in cf["established_facts"]:
        assert f["source_id"] not in unverified, f
    for c in cf["claims"]:
        assert not (set(c["source_ids"]) & unverified), c


def test_claims_from_one_government_record_are_one_independence_group(cf):
    """Two answers from the same Government about the same incident are not
    independent corroboration of each other."""
    for c in cf["claims"]:
        assert c["independent_groups"] == 1, c


def test_the_scenario_is_labelled_synthetic(cf):
    note = cf["relationship_to_scenario"]["note"].lower()
    assert "synthetic" in note
    assert "not" in note and "reconstruction" in note


# --------------------------------------------------------------------------- #
# scope                                                                        #
# --------------------------------------------------------------------------- #
def test_synthetic_scenarios_have_no_case_file():
    assert load_casefile("cbse_exam_breach") is None
    assert load_casefile("lanl_campaign_all") is None
    assert load_casefile(None) is None


def test_the_data_file_parses_and_is_the_only_source_of_truth():
    for name in SCENARIO_CASEFILES.values():
        json.loads((CASEFILE_DIR / name).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# API                                                                          #
# --------------------------------------------------------------------------- #
def test_endpoint_returns_the_case_file(client):
    r = client.get("/api/casefile/aiims_ransomware", headers=ANALYST)
    assert r.status_code == 200
    assert r.json()["confirmed_techniques"] == ["T1486"]


def test_endpoint_404s_for_a_synthetic_scenario(client):
    r = client.get("/api/casefile/cbse_exam_breach", headers=ANALYST)
    assert r.status_code == 404
    assert "synthetic" in r.json()["detail"]


def test_the_investigation_carries_the_case_file(client):
    r = client.post("/api/investigate", json={"scenario": "aiims_ransomware"},
                    headers=ANALYST)
    assert r.status_code == 200
    cf = r.json()["casefile"]
    assert cf and cf["case_id"] == "AIIMS-DELHI-2022"


def test_a_synthetic_investigation_carries_no_case_file(client):
    r = client.post("/api/investigate", json={"scenario": "cbse_exam_breach"},
                    headers=ANALYST)
    assert r.status_code == 200
    assert r.json()["casefile"] is None
