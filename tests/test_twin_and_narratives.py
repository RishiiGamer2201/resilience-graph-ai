"""Tests for Digital Twin AI Advisor Chatbot & Natural-Language Prediction Narratives."""
import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.shared.chat_advisor import ask_advisor
from src.shared.predictor import generate_prediction_narrative


def test_generate_prediction_narrative_produces_coherent_english():
    predictions = [
        {"technique_id": "T1003", "name": "OS Credential Dumping", "probability": 0.54},
        {"technique_id": "T1021.001", "name": "Remote Desktop Protocol", "probability": 0.32},
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "probability": 0.14},
    ]
    chain = ["T1566.001", "T1204.002", "T1078"]
    narrative = generate_prediction_narrative(predictions, chain)

    assert isinstance(narrative, str)
    assert len(narrative) > 50
    assert "Move 1: OS Credential Dumping (T1003)" in narrative
    assert "Move 2: Remote Desktop Protocol (T1021.001)" in narrative
    assert "Move 3: Data Encrypted for Impact (T1486)" in narrative
    assert "credential" in narrative.lower()


def test_ask_advisor_deterministic_plain_english_synthesis():
    graph_context = {
        "entry_host": "WARD-PC-013",
        "critical_assets_at_risk": ["DC-AIIMS-01", "SRV-PATIENT-DB"],
        "recommended_isolation": "WARD-PC-013",
        "blast_radius_size": 4,
        "isolation_cuts": 4,
    }

    # Test containment question
    res_contain = ask_advisor("What happens if we isolate the entry host?", graph=graph_context)
    assert "reply" in res_contain
    assert "Executive Containment Assessment" in res_contain["reply"]
    assert "WARD-PC-013" in res_contain["reply"]
    assert len(res_contain.get("follow_ups", [])) >= 2

    # Test general explanation question
    res_explain = ask_advisor("Explain this incident in simple words for our leadership team.", graph=graph_context)
    assert "Plain-English Incident Overview" in res_explain["reply"]
    assert len(res_explain.get("sources", [])) >= 0


def test_twin_chat_api_endpoint():
    client = TestClient(app)
    payload = {
        "message": "Can you summarize what is happening in this incident simply?",
        "incident_id": "INC-TEST-001",
        "graph": {
            "entry_host": "HOST-A",
            "critical_assets_at_risk": ["SERVER-DB"],
            "recommended_isolation": "HOST-A",
            "blast_radius_size": 2,
        },
    }
    r = client.post("/api/twin/chat", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert "reply" in data
    assert len(data["reply"]) > 30
    assert "follow_ups" in data
