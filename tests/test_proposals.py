"""Regression tests for the server-issued proposal trust boundary."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.shared import proposals

RESPONDER = {"X-Role": "responder", "X-Actor": "proposal-test@soc"}


def _action() -> dict:
    return {
        "id": "ACT-01",
        "kind": "isolate",
        "action": "Isolate HOST-A",
        "touches_crown_jewel": True,
        "blast_radius_affected": 4,
        "policy": {
            "requires_approval": True,
            "required_permission": "approve_critical",
            "gate": "named human approval",
            "reasons": ["touches a crown jewel"],
            "policy_version": "1.0.0",
        },
    }


def _issue(store: proposals.ProposalStore, **kwargs) -> dict:
    return store.issue(
        incident_id="INC-PROPOSAL-1",
        action=_action(),
        input_digest=proposals.digest({"graph": "authoritative"}),
        evidence=[{"chunk_id": "attack:T1021", "sha256": "abc"}],
        technique_ids=["T1021"],
        affected_assets=["HOST-A"],
        **kwargs,
    )


def test_returned_copy_cannot_modify_the_stored_proposal():
    store = proposals.ProposalStore()
    issued = _issue(store)
    issued["kind"] = "monitor"
    issued["policy"]["required_permission"] = "read"

    stored = store.get(issued["proposal_id"])
    assert stored["action"]["kind"] == "isolate"
    assert stored["action"]["policy"]["required_permission"] == "approve_critical"
    assert stored["proposal_digest"] != proposals.digest({"kind": "monitor"})


def test_store_detects_modified_expiry_metadata():
    store = proposals.ProposalStore()
    issued = _issue(store)
    store._conn.execute(
        "UPDATE proposals SET expires_at = ? WHERE proposal_id = ?",
        ("2099-01-01T00:00:00Z", issued["proposal_id"]),
    )
    with pytest.raises(proposals.ProposalIntegrityError):
        store.get(issued["proposal_id"])


def test_expired_proposal_cannot_be_decided():
    store = proposals.ProposalStore()
    now = datetime.now(timezone.utc)
    issued = _issue(store, now=now, ttl_seconds=1)
    with pytest.raises(proposals.ProposalExpired):
        store.decide(
            issued["proposal_id"], decision="approve", actor="ravi", role="responder",
            reason="too late", now=now + timedelta(seconds=2),
        )
    assert store.get(issued["proposal_id"])["status"] == "expired"


def test_concurrent_duplicate_decisions_have_exactly_one_winner():
    store = proposals.ProposalStore()
    issued = _issue(store)

    def decide(index: int) -> str:
        try:
            store.decide(
                issued["proposal_id"], decision="approve", actor=f"r{index}",
                role="responder", reason="concurrency test",
            )
            return "accepted"
        except proposals.ProposalAlreadyDecided:
            return "conflict"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(decide, range(8)))
    assert outcomes.count("accepted") == 1
    assert outcomes.count("conflict") == 7


def test_durable_store_survives_restart(tmp_path):
    path = tmp_path / "proposals.db"
    first = proposals.ProposalStore(path)
    issued = _issue(first)
    first._conn.close()

    resumed = proposals.ProposalStore(path)
    assert resumed.get(issued["proposal_id"])["proposal_digest"] == issued["proposal_digest"]
    assert resumed.durable is True


def test_api_rejects_unknown_and_client_authored_proposals():
    client = TestClient(app)
    unknown = client.post(
        "/api/actions/approve", headers=RESPONDER,
        json={"proposal_id": "PRP-does-not-exist", "decision": "approve", "reason": "x"},
    )
    assert unknown.status_code == 404

    fabricated = client.post(
        "/api/actions/approve", headers=RESPONDER,
        json={
            "proposal_id": "PRP-does-not-exist",
            "decision": "approve",
            "reason": "x",
            "action": {"kind": "monitor"},
            "affected_assets": ["made-up-host"],
        },
    )
    assert fabricated.status_code == 422
    assert "extra_forbidden" in fabricated.text


def test_openapi_approval_contract_contains_no_client_authored_action_fields():
    schema = app.openapi()["components"]["schemas"]["ApprovalRequest"]
    assert set(schema["properties"]) == {"proposal_id", "decision", "reason"}
    assert schema.get("additionalProperties") is False


def test_api_decision_uses_the_same_digest_as_the_proposal_audit_record():
    client = TestClient(app)
    investigation = client.post(
        "/api/investigate", headers={"X-Role": "analyst", "X-Actor": "issuer@soc"},
        json={"scenario": "aiims_ransomware", "incident_id": "INC-DIGEST-1"},
    )
    assert investigation.status_code == 200, investigation.text
    proposal = investigation.json()["action"]["proposals"][0]

    response = client.post(
        "/api/actions/approve", headers=RESPONDER,
        json={
            "proposal_id": proposal["proposal_id"],
            "decision": "approve",
            "reason": "asset owner approved the simulated action",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["proposal_digest"] == proposal["proposal_digest"]

    records = client.get("/api/audit", headers={"X-Role": "admin"}).json()["records"]
    related = [
        record for record in records
        if record.get("details", {}).get("proposal_id") == proposal["proposal_id"]
    ]
    assert {record["kind"] for record in related} == {"action.proposed", "action.approved"}
    assert {record["details"]["proposal_digest"] for record in related} == {
        proposal["proposal_digest"]
    }


def test_api_rejects_a_second_decision():
    client = TestClient(app)
    investigation = client.post(
        "/api/investigate", headers={"X-Role": "analyst", "X-Actor": "issuer@soc"},
        json={"scenario": "cbse_exam_breach", "incident_id": "INC-ONCE-1"},
    ).json()
    proposal = investigation["action"]["proposals"][0]
    payload = {
        "proposal_id": proposal["proposal_id"],
        "decision": "reject",
        "reason": "not appropriate for this asset",
    }
    assert client.post("/api/actions/approve", headers=RESPONDER, json=payload).status_code == 200
    assert client.post("/api/actions/approve", headers=RESPONDER, json=payload).status_code == 409
