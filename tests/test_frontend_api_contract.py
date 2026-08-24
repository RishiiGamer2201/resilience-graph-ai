"""Contract checks for requests issued by ``frontend/src/lib/api.ts``.

This is intentionally a small route matrix rather than an assertion over every
backend route: it documents the methods and paths the SPA depends on, including
the two authenticated SSE requests and the direct multipart/text fetches.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app


ANALYST = {"X-Role": "analyst", "X-Actor": "frontend-contract@test"}
VIEWER = {"X-Role": "viewer", "X-Actor": "frontend-contract@test"}

# Dynamic client URLs are represented by their OpenAPI templates. Query strings
# do not participate in FastAPI route matching, so /audit?limit= is /api/audit.
FRONTEND_REQUESTS = {
    ("get", "/api/overview"),
    ("get", "/api/incident"),
    ("get", "/api/graph"),
    ("get", "/api/threat-intel"),
    ("get", "/api/metrics"),
    ("get", "/api/methodology"),
    ("get", "/api/report"),
    ("get", "/api/attackers"),
    ("get", "/api/health"),
    ("get", "/api/llm"),
    ("get", "/api/scoreboard"),
    ("get", "/api/capabilities"),
    ("get", "/api/readiness"),
    ("get", "/api/scenarios"),
    ("post", "/api/threat-radar"),
    ("post", "/api/analyze"),
    ("post", "/api/analyze/upload"),
    ("get", "/api/analyze/stream"),
    ("get", "/api/agents/stream"),
    ("post", "/api/score-event"),
    ("post", "/api/predict-next"),
    ("post", "/api/investigate"),
    ("get", "/api/casefile/{scenario}"),
    ("post", "/api/evidence/search"),
    ("get", "/api/evidence/stats"),
    ("post", "/api/vulnerabilities"),
    ("get", "/api/vulnerabilities/config"),
    ("post", "/api/twin/simulate"),
    ("post", "/api/twin/candidates"),
    ("post", "/api/twin/chat"),
    ("post", "/api/explain"),
    ("post", "/api/actions/approve"),
    ("get", "/api/audit"),
    ("get", "/api/audit/verify"),
    ("get", "/api/audit/export"),
    ("post", "/api/audit/verify-export"),
    ("post", "/api/audit/rotate"),
    ("get", "/api/audit/export.md"),
}


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_every_frontend_request_has_a_matching_fastapi_method():
    paths = app.openapi()["paths"]
    missing = sorted(
        (method.upper(), path)
        for method, path in FRONTEND_REQUESTS
        if path not in paths or method not in paths[path]
    )
    assert not missing, f"frontend requests without FastAPI routes: {missing}"


def test_advisor_accepts_the_exact_frontend_method_and_payload(client, monkeypatch):
    # The contract suite must never turn an ambient developer key into a paid
    # request. This is explicit here as well as in the suite-wide fixture.
    monkeypatch.setenv("NEXTATTACK_LLM_PROVIDER", "off")
    payload = {
        "message": "What is at risk?",
        "history": [{"role": "user", "content": "Summarise the incident."}],
        "incident_id": "INC-CONTRACT-001",
        "graph": {
            "entry_host": "HOST-A",
            "critical_assets_at_risk": ["PATIENT-DB-01"],
            "blast_radius_size": 2,
        },
    }
    response = client.post("/api/twin/chat", json=payload, headers=VIEWER)
    assert response.status_code == 200, response.text
    assert {"reply", "sources", "facts_used", "follow_ups"} <= response.json().keys()

    # The API schema exposes only POST. (A production build's SPA catch-all may
    # answer an accidental GET with index.html, so OpenAPI is the reliable verb
    # contract.) If POST receives a 405 in the UI, it reached another service.
    assert set(app.openapi()["paths"]["/api/twin/chat"]) == {"post"}


VALID_SCORE_FEATURES = {
    "is_fail": 1,
    "new_dst_for_user": 1,
    "new_src_for_user": 0,
    "user_distinct_dst_sofar": 12,
    "user_fail_rate_sofar": 0.25,
    "dst_rarity": 4.2,
    "is_ntlm": 0,
}


def test_score_event_requires_the_complete_frontend_feature_vector(client):
    assert client.post("/api/score-event", json={}, headers=ANALYST).status_code == 422

    partial = dict(VALID_SCORE_FEATURES)
    partial.pop("dst_rarity")
    assert client.post(
        "/api/score-event", json=partial, headers=ANALYST
    ).status_code == 422

    response = client.post(
        "/api/score-event", json=VALID_SCORE_FEATURES, headers=ANALYST
    )
    assert response.status_code == 200, response.text
    assert {"anomaly_score", "severity", "raw"} <= response.json().keys()


@pytest.mark.parametrize("field,value", [
    ("is_fail", 2),
    ("user_fail_rate_sofar", 1.1),
    ("dst_rarity", -0.1),
])
def test_score_event_rejects_out_of_domain_features(client, field, value):
    payload = {**VALID_SCORE_FEATURES, field: value}
    assert client.post(
        "/api/score-event", json=payload, headers=ANALYST
    ).status_code == 422


def test_predict_next_requires_a_nonempty_bounded_chain(client):
    assert client.post(
        "/api/predict-next", json={"technique_ids": [], "k": 5}, headers=ANALYST
    ).status_code == 422
    assert client.post(
        "/api/predict-next", json={"technique_ids": ["T1059"], "k": 0}, headers=ANALYST
    ).status_code == 422

    response = client.post(
        "/api/predict-next",
        json={"technique_ids": ["T1059"], "k": 5},
        headers=ANALYST,
    )
    assert response.status_code == 200, response.text
    assert {"given", "predictions", "projection_narrative", "source"} <= response.json().keys()


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("post", "/api/score-event", VALID_SCORE_FEATURES),
        ("post", "/api/predict-next", {"technique_ids": ["T1059"], "k": 5}),
        ("post", "/api/analyze", {"scenario": "aiims_ransomware"}),
        ("get", "/api/analyze/stream?scenario=aiims_ransomware", None),
        ("get", "/api/agents/stream?scenario=aiims_ransomware", None),
    ],
)
def test_compute_requests_enforce_the_frontend_session_role(client, method, path, payload):
    response = client.request(method, path, json=payload, headers=VIEWER)
    assert response.status_code == 403, response.text
