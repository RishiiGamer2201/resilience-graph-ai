"""Regression coverage for technique- and asset-aware response proposals."""
from __future__ import annotations

from src.shared.soar import recommend


def _step(technique_id: str, technique: str, *, score: int = 90,
          tactic: str = "Initial Access", user: str = "analyst-1",
          source: str = "LAPTOP-7", destination: str = "PORTAL-1") -> dict:
    return {
        "technique_id": technique_id, "technique": technique, "tactic": tactic,
        "event_type": "test_event", "anomaly_score": score, "timestamp": 123,
        "user": user, "source_host": source, "destination_host": destination,
    }


def _incident(*steps: dict) -> dict:
    return {
        "incident_id": "INC-PLAYBOOK-1", "severity": "critical",
        "technique_ids": list(dict.fromkeys(step["technique_id"] for step in steps)),
        "alerts": list(steps),
    }


def test_same_tactic_uses_distinct_technique_specific_actions():
    valid = _step("T1078", "Valid Accounts", score=65)
    exploit = _step("T1190", "Exploit Public-Facing Application")
    response = recommend(
        _incident(valid, exploit),
        architecture={
            "asset_types": {"PORTAL-1": "public_web_application"},
            "controls": ["waf"],
        },
    )

    by_id = {action["technique_id"]: action for action in response["actions"]}
    assert "Revoke active sessions" in by_id["T1078"]["action"]
    assert "WAF virtual patch" in by_id["T1190"]["action"]
    assert "account" not in by_id["T1190"]["action"].lower()
    assert by_id["T1078"]["action"] != by_id["T1190"]["action"]


def test_every_proposal_carries_the_review_and_recovery_contract():
    response = recommend(_incident(_step("T1078", "Valid Accounts", score=65)))
    proposal = response["actions"][0]
    required = {
        "triggering_evidence", "target", "prerequisites", "operational_cost",
        "rollback", "verification", "minimum_severity", "applicability",
        "applicability_reason", "technique_id", "technique", "kind", "action",
    }
    assert required <= proposal.keys()
    assert proposal["triggering_evidence"]["technique_id"] == "T1078"
    assert proposal["target"] == "analyst-1"
    assert proposal["prerequisites"]
    assert proposal["rollback"]
    assert proposal["verification"]


def test_minimum_severity_is_enforced_per_triggering_evidence():
    response = recommend(_incident(_step("T1190", "Exploit Public-Facing Application",
                                               score=74)))
    assert response["actions"] == []
    assert "below playbook minimum high" in response["skipped_actions"][0]["reason"]


def test_missing_or_incompatible_architecture_is_explicit():
    exploit = _step("T1190", "Exploit Public-Facing Application")

    missing = recommend(_incident(exploit))["actions"][0]
    assert missing["applicability"] == "not_configured"
    assert "Asset types" in missing["applicability_reason"]

    incompatible = recommend(
        _incident(exploit),
        architecture={"asset_types": {"PORTAL-1": "database"}, "controls": ["waf"]},
    )["actions"][0]
    assert incompatible["applicability"] == "not_applicable"
    assert "database" in incompatible["applicability_reason"]


def test_required_control_configuration_is_checked_when_supplied():
    exploit = _step("T1190", "Exploit Public-Facing Application")
    response = recommend(
        _incident(exploit),
        architecture={
            "asset_types": {"PORTAL-1": "web_application"},
            "controls": ["identity_provider"],
        },
    )
    assert response["actions"][0]["applicability"] == "not_configured"
    assert "patch_management" in response["actions"][0]["applicability_reason"]

