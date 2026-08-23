"""The payload contract the SPA actually reads.

There is no TypeScript across this boundary (ADR 0004), so this file is the type
system: it asserts the exact keys each screen and component dereferences. It exists
because a real bug slipped through — `Investigate.jsx` read `incident.users_involved`
while the view exposed `accounts_involved`, which renders "0 accounts" instead of
crashing. A silently wrong number is worse than a stack trace.

When you change a payload, change this file in the same commit.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app

ANALYST = {"X-Role": "analyst", "X-Actor": "contract@test"}


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def result(client):
    r = client.post("/api/investigate",
                    json={"scenario": "aiims_ransomware"}, headers=ANALYST)
    assert r.status_code == 200, r.text
    return r.json()


def _has(obj: dict, *keys: str) -> None:
    missing = [k for k in keys if k not in obj]
    assert not missing, f"missing keys {missing}; present: {sorted(obj)[:25]}"


# --- Investigate.jsx -------------------------------------------------------
def test_top_level_shape(result):
    _has(result, "ok", "trace", "understand", "evidence", "signals", "impact",
         "action", "headline", "meta", "llm", "principal", "audit")


def test_understand_panel(result):
    _has(result["understand"], "source", "provenance", "n_events", "accounts_total",
         "hosts_total", "crown_jewels_designated", "columns_missing",
         "crown_jewels_not_in_log")


def test_stage_rail(result):
    _has(result["trace"], "nodes", "total_ms", "bounded_by", "degraded")
    for n in result["trace"]["nodes"]:
        _has(n, "node", "status", "ms", "summary", "notes", "output")


def test_plan_panel(result):
    plan = next(n for n in result["trace"]["nodes"] if n["node"] == "plan")
    for step in plan["output"]["steps"]:
        _has(step, "node", "tool", "selected", "why")


def test_signals_panel(result):
    _has(result["signals"], "overview", "incident", "graph", "threat_intel",
         "report", "attackers", "soar")
    inc = result["signals"]["incident"]
    # `accounts_involved` is what the screen reads — this is the bug this file caught
    _has(inc, "incident_id", "severity", "max_anomaly_score", "alert_count",
         "event_count", "technique_ids", "accounts_involved", "users_involved")
    assert isinstance(inc["accounts_involved"], list)
    g = result["signals"]["graph"]
    _has(g, "entry_host", "critical_assets_at_risk", "blast_radius_size", "nodes",
         "edges", "paths_to_critical")
    _has(result["signals"]["report"], "predicted_next")
    for p in result["signals"]["report"]["predicted_next"]:
        _has(p, "technique_id", "name")


# --- Headline.jsx ----------------------------------------------------------
@pytest.mark.parametrize("key", ["attack_progression_likelihood",
                                 "evidence_confidence", "crown_jewel_exposure"])
def test_headline_metric(result, key):
    m = result["headline"][key]
    _has(m, "value", "unit", "state", "terms", "formula")
    for t in m["terms"]:
        # the component renders name-or-asset, weight/value/score, detail-or-why
        assert ("name" in t) or ("asset" in t), t
        assert any(k in t for k in ("value", "score")), t
        assert ("detail" in t) or ("why" in t), t


def test_headline_carries_the_four_number_assessment(result):
    a = result["headline"]["assessment"]
    _has(a, "anomaly", "likelihood", "impact", "confidence", "missing_evidence",
         "summary", "note")
    for dim in ("anomaly", "likelihood", "impact", "confidence"):
        _has(a[dim], "value", "band", "question")


def test_claims_panel_contract(result):
    for c in result["impact"]["claims"]:
        _has(c, "subject", "predicate", "object", "external_id", "status",
             "actionable", "confidence", "confidence_band", "independent_groups",
             "mapper", "evidence", "missing_evidence", "alternatives", "note")


# --- EvidenceList.jsx ------------------------------------------------------
def test_evidence_cards(result):
    ev = result["evidence"]
    _has(ev, "citations", "corpus", "retrieval")
    for c in ev["citations"]:
        _has(c, "chunk_id", "title", "url", "publisher", "authority", "section",
             "published", "retrieved_at", "excerpt", "sha256", "identifiers",
             "match_reason")


# --- ImpactPanel.jsx -------------------------------------------------------
def test_twin_candidates(result, client):
    r = client.post("/api/twin/candidates",
                    json={"graph": result["signals"]["graph"], "limit": 5},
                    headers=ANALYST)
    assert r.status_code == 200
    for c in r.json()["candidates"]:
        _has(c, "host", "crown_jewels_protected", "blast_radius_reduction",
             "blast_radius_reduction_pct", "sessions_severed", "accounts_disrupted",
             "is_crown_jewel", "verdict")


def test_twin_simulation(result, client):
    graph = result["signals"]["graph"]
    host = graph["edges"][0]["from"]
    r = client.post("/api/twin/simulate",
                    json={"graph": graph, "isolate_host": host}, headers=ANALYST)
    assert r.status_code == 200, r.text
    s = r.json()
    _has(s, "candidate", "before", "after", "delta", "operational_cost", "verdict",
         "method", "note", "simulated")
    _has(s["before"], "blast_radius", "crown_jewels_reachable", "n_nodes", "n_edges")
    _has(s["after"], "blast_radius", "crown_jewels_reachable", "n_nodes", "n_edges")
    _has(s["operational_cost"], "hosts_taken_offline", "sessions_severed",
         "accounts_disrupted", "host_is_crown_jewel")


def test_vulnerability_panel(result):
    v = result["impact"]["vulnerabilities"]
    _has(v, "findings", "total_findings", "assets_considered", "inventory_provenance")
    if v["findings"]:
        _has(v, "config", "kev_catalog_size", "note")
        _has(v["config"], "version", "sha256", "weights", "bands")
        for f in v["findings"]:
            _has(f, "cve", "host", "owner", "priority_score", "band", "confidence",
                 "unknown_factors", "factors", "citation")
            _has(f["citation"], "url", "publisher")
            for fac in f["factors"].values():
                _has(fac, "value", "fact")


# --- ActionPanel.jsx -------------------------------------------------------
def test_action_proposals(result):
    a = result["action"]
    _has(a, "proposals", "mitre_mitigations", "gating_policy", "rfi", "executed", "note")
    for p in a["proposals"]:
        _has(p, "id", "kind", "tactic", "action", "touches_crown_jewel",
             "blast_radius_affected", "hosts_taken_offline", "simulated", "policy")
        _has(p["policy"], "requires_approval", "gate", "required_permission",
             "reasons", "policy_version")
    _has(a["rfi"], "to", "subject", "context", "questions", "generated_by", "note")
    for q in a["rfi"]["questions"]:
        _has(q, "field", "ask", "why")


def test_approval_response_shape(result, client):
    p = result["action"]["proposals"][0]
    r = client.post("/api/actions/approve", headers={"X-Role": "responder",
                                                     "X-Actor": "contract@test"},
                    json={"incident_id": "INC-LIVE-001", "action": p,
                          "decision": "approve", "reason": "contract test"})
    assert r.status_code == 200, r.text
    body = r.json()
    _has(body, "recorded", "executed", "decision", "policy", "record", "chain", "note")
    _has(body["record"], "seq", "hash", "at")


# --- AuditPanel.jsx --------------------------------------------------------
def test_audit_list_shape(client):
    body = client.get("/api/audit?limit=20", headers=ANALYST).json()
    _has(body, "records", "count", "head", "verified", "problem")
    for r in body["records"]:
        _has(r, "seq", "at", "kind", "actor", "role", "decision", "reason", "hash",
             "prev_hash", "incident_id", "evidence", "technique_ids",
             "affected_assets", "action", "versions")


def test_audit_export_shape(client):
    exp = client.get("/api/audit/export", headers={"X-Role": "admin"}).json()
    _has(exp, "chain_version", "hash_algorithm", "canonicalisation", "exported_at",
         "record_count", "head_hash", "verified", "records", "claim")


# --- ExplainTrace.jsx ------------------------------------------------------
def test_explain_shape(client):
    r = client.post("/api/explain",
                    json={"scenario": "aiims_ransomware",
                          "critical_assets": ["PATIENT-DB-01"], "step_index": 0},
                    headers=ANALYST)
    assert r.status_code == 200, r.text
    t = r.json()
    _has(t, "available", "step_index", "alerts_available", "step", "stages", "note")
    _has(t["step"], "user", "source_host", "destination_host", "anomaly_score",
         "technique_id")
    for s in t["stages"]:
        _has(s, "stage", "produced_by", "value", "explanation")


# --- Scoreboard.jsx --------------------------------------------------------
def test_scoreboard_shape(client):
    b = client.get("/api/scoreboard").json()
    _has(b, "generated_at", "groups", "cards", "summary", "sources", "refused_claims",
         "note")
    _has(b["summary"], "total", "measured", "not_measured", "missing_reports")
    _has(b["sources"], "regenerate")
    for g in b["groups"]:
        _has(g, "name", "cards")
    for c in b["cards"]:
        _has(c, "id", "group", "name", "definition", "dataset", "sample", "state",
             "value", "unit", "baseline", "higher_is_better", "report",
             "report_exists", "why", "note", "provenance", "lift")


# --- Investigate.jsx degraded banner --------------------------------------
def test_capabilities_shape(client):
    caps = client.get("/api/capabilities").json()
    _has(caps, "capabilities", "degraded", "usable_offline", "keys_required",
         "versions", "note")
    for name, cap in caps["capabilities"].items():
        _has(cap, "state", "detail")
        assert isinstance(cap["state"], str), name


def test_meta_carries_the_calibration_basis(result):
    """The UI renders a score's scale from this block, so it is load-bearing.

    A 78 produced against the shipped LANL anchors and a 78 produced by ranking
    within an out-of-distribution log are not the same claim, and the screens now
    say which one they are showing. If this block stops arriving the badge
    silently disappears and every score goes back to looking calibrated, which is
    the bug the OOD work exists to prevent -- so the contract asserts it here
    rather than leaving the frontend to discover it.
    """
    cal = result["meta"].get("calibration")
    assert cal is not None, "meta.calibration is missing; the UI cannot label the scale"
    assert isinstance(cal.get("basis"), str) and cal["basis"], "basis must be a non-empty string"
    assert isinstance(cal.get("out_of_distribution"), bool)
    assert isinstance(cal.get("rarity_shift_sigma"), (int, float))
    # the note is the user-facing explanation: required when OOD, empty otherwise
    if cal["out_of_distribution"]:
        assert cal.get("note"), "an OOD run must explain itself"
    else:
        assert cal.get("note") == "", "a normally-calibrated run must not carry a warning"
