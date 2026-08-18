"""Governance: authorisation, the approval gate, and the tamper-evident chain.

These are the tests that have to hold for the product's central claim — "no
action reaches a real system without a named human" — to be more than a slogan.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.shared import rbac
from src.shared.audit import AuditChain, canonical, record_hash

ANALYST = {"X-Role": "analyst", "X-Actor": "asha@soc"}
RESPONDER = {"X-Role": "responder", "X-Actor": "ravi@soc"}
VIEWER = {"X-Role": "viewer"}
ADMIN = {"X-Role": "admin", "X-Actor": "root@soc"}


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# --------------------------------------------------------------------------- #
# RBAC                                                                         #
# --------------------------------------------------------------------------- #
def test_unknown_role_falls_back_to_the_least_privilege():
    p = rbac.resolve_principal("superuser", None, None)
    assert p["role"] == "viewer"


def test_permission_matrix_is_least_privilege():
    assert rbac.permissions_for("viewer") == ["read", "verify_audit"]
    assert "approve_critical" not in rbac.permissions_for("analyst")
    assert "approve_critical" in rbac.permissions_for("responder")
    assert "approve_critical" in rbac.permissions_for("admin")


@pytest.mark.parametrize("role,permission,allowed", [
    ("viewer", "read", True),
    ("viewer", "analyze", False),
    ("viewer", "approve_low", False),
    ("analyst", "analyze", True),
    ("analyst", "approve_critical", False),
    ("responder", "approve_critical", True),
    ("admin", "reset_session", True),
])
def test_require_enforces_the_matrix(role, permission, allowed):
    p = rbac.resolve_principal(role, None, None)
    if allowed:
        rbac.require(p, permission)
    else:
        with pytest.raises(rbac.Denied):
            rbac.require(p, permission)


def test_low_impact_action_is_pre_approved_but_crown_jewel_is_not():
    low = rbac.policy_for({"kind": "monitor", "blast_radius_affected": 2})
    assert not low["requires_approval"]
    crown = rbac.policy_for({"kind": "isolate", "touches_crown_jewel": True})
    assert crown["requires_approval"]
    assert crown["required_permission"] == "approve_critical"


def test_wide_blast_radius_forces_approval_even_without_a_crown_jewel():
    wide = rbac.policy_for({"kind": "isolate", "blast_radius_affected": 463})
    assert wide["requires_approval"], wide
    assert any("463" in r for r in wide["reasons"]), wide["reasons"]


def test_bearer_tokens_take_over_when_configured(monkeypatch):
    monkeypatch.setenv("NEXTATTACK_ROLE_TOKENS", "s3cret:responder")
    assert rbac.auth_mode() == "bearer-tokens"
    with pytest.raises(rbac.AuthError):
        rbac.resolve_principal("admin", None, None)          # declared role ignored
    with pytest.raises(rbac.AuthError):
        rbac.resolve_principal(None, None, "Bearer wrong")
    p = rbac.resolve_principal("admin", None, "Bearer s3cret")
    assert p["role"] == "responder" and p["authenticated"] is True


# --------------------------------------------------------------------------- #
# audit chain                                                                  #
# --------------------------------------------------------------------------- #
def test_canonicalisation_is_key_order_independent():
    a = {"b": 1, "a": [1, 2], "c": {"z": 1, "y": 2}}
    b = {"c": {"y": 2, "z": 1}, "a": [1, 2], "b": 1}
    assert canonical(a) == canonical(b)
    assert record_hash("0" * 64, a) == record_hash("0" * 64, b)


def _chain() -> AuditChain:
    c = AuditChain({"detector": "abc"})
    c.append("analysis.completed", actor="asha", role="analyst", incident_id="INC-1")
    c.append("action.proposed", actor="asha", role="analyst", incident_id="INC-1",
             action={"kind": "isolate", "host": "H1"})
    c.append("action.approved", actor="ravi", role="responder", incident_id="INC-1",
             decision="approved", reason="owner contacted")
    return c


def test_a_clean_chain_verifies():
    ok, problem = _chain().verify()
    assert ok, problem


def test_editing_a_record_is_detected_and_located():
    recs = json.loads(json.dumps(_chain().records()))
    recs[3]["reason"] = "approved without checking"
    ok, problem = AuditChain.verify_records(recs)
    assert not ok
    assert "record 3" in problem and "hash mismatch" in problem


def test_deleting_a_record_is_detected():
    recs = json.loads(json.dumps(_chain().records()))
    del recs[2]
    ok, _ = AuditChain.verify_records(recs)
    assert not ok


def test_reordering_records_is_detected():
    recs = json.loads(json.dumps(_chain().records()))
    recs[1], recs[2] = recs[2], recs[1]
    ok, _ = AuditChain.verify_records(recs)
    assert not ok


def test_rehashing_a_forged_record_still_breaks_the_link():
    """Recomputing the forged record's own hash is not enough — the NEXT record's
    prev_hash no longer matches, which is the point of chaining."""
    recs = json.loads(json.dumps(_chain().records()))
    recs[2]["reason"] = "forged"
    payload = {k: v for k, v in recs[2].items() if k != "hash"}
    recs[2]["hash"] = record_hash(recs[2]["prev_hash"], payload)
    ok, problem = AuditChain.verify_records(recs)
    assert not ok and "record 3" in problem, problem


def test_export_is_honest_about_what_it_claims():
    exp = _chain().export()
    assert exp["verified"] is True
    assert "tamper-EVIDENT" in exp["claim"] or "Tamper-EVIDENT" in exp["claim"]
    assert "blockchain" in exp["claim"].lower()          # explicitly disclaimed
    assert exp["record_count"] == len(exp["records"])


def test_markdown_export_lists_every_record():
    md = _chain().markdown()
    assert "action.approved" in md and "VERIFIED" in md
    assert md.count("### ") == 4


# --------------------------------------------------------------------------- #
# API: authorisation is enforced server-side, not by hiding buttons            #
# --------------------------------------------------------------------------- #
def test_viewer_cannot_run_an_investigation(client):
    r = client.post("/api/investigate", json={"scenario": "aiims_ransomware"},
                    headers=VIEWER)
    assert r.status_code == 403
    assert "not permitted" in r.json()["detail"]


def test_viewer_cannot_export_the_audit(client):
    assert client.get("/api/audit/export", headers=VIEWER).status_code == 403


def test_viewer_can_still_verify_the_audit(client):
    r = client.get("/api/audit/verify", headers=VIEWER)
    assert r.status_code == 200 and r.json()["verified"] is True


@pytest.fixture(scope="module")
def investigation(client):
    r = client.post("/api/investigate", json={"scenario": "aiims_ransomware"},
                    headers=ANALYST)
    assert r.status_code == 200, r.text
    return r.json()


def test_a_gated_action_refuses_an_analyst(client, investigation):
    gated = next(p for p in investigation["action"]["proposals"]
                 if p["policy"]["requires_approval"])
    r = client.post("/api/actions/approve", headers=ANALYST, json={
        "incident_id": "INC-LIVE-001", "action": gated,
        "decision": "approve", "reason": "looks fine"})
    assert r.status_code == 403


def test_a_gated_action_refuses_approval_without_a_reason(client, investigation):
    gated = next(p for p in investigation["action"]["proposals"]
                 if p["policy"]["requires_approval"])
    r = client.post("/api/actions/approve", headers=RESPONDER, json={
        "incident_id": "INC-LIVE-001", "action": gated,
        "decision": "approve", "reason": "   "})
    assert r.status_code == 422
    assert "reason" in r.json()["detail"]


def test_approval_is_recorded_and_nothing_is_executed(client, investigation):
    gated = next(p for p in investigation["action"]["proposals"]
                 if p["policy"]["requires_approval"])
    r = client.post("/api/actions/approve", headers=RESPONDER, json={
        "incident_id": "INC-LIVE-001", "action": gated, "decision": "approve",
        "reason": "ward PC, out of hours, owner contacted",
        "affected_assets": ["WARD-PC-013"]})
    assert r.status_code == 200
    body = r.json()
    assert body["executed"] is False
    assert body["decision"] == "approved"
    assert len(body["record"]["hash"]) == 64
    assert client.get("/api/audit/verify", headers=VIEWER).json()["verified"] is True


def test_a_denial_is_itself_audited(client, investigation):
    before = client.get("/api/audit", headers=ADMIN).json()["count"]
    gated = next(p for p in investigation["action"]["proposals"]
                 if p["policy"]["requires_approval"])
    client.post("/api/actions/approve", headers=VIEWER, json={
        "incident_id": "INC-LIVE-001", "action": gated,
        "decision": "approve", "reason": "x"})
    records = client.get("/api/audit", headers=ADMIN).json()
    assert records["count"] > before
    assert any(r["kind"] == "action.denied" for r in records["records"])
    assert records["verified"] is True


def test_exported_chain_can_be_reverified_and_tampering_is_caught(client):
    exp = client.get("/api/audit/export", headers=ADMIN).json()
    clean = client.post("/api/audit/verify-export", json=exp, headers=VIEWER).json()
    assert clean["verified"] is True
    exp["records"][1]["reason"] = "edited"
    dirty = client.post("/api/audit/verify-export", json=exp, headers=VIEWER).json()
    assert dirty["verified"] is False and "record 1" in dirty["problem"]
