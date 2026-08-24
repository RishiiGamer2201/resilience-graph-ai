from __future__ import annotations

import json

from src.shared import llm
from src.shared.llm_prediction import generate


def test_llm_prediction_returns_three_grounded_techniques_and_campaigns(monkeypatch):
    payload = {"predictions": [
        {"technique_id": "T1059.001", "reason": "PowerShell is a plausible continuation.",
         "previous_attacks": [{"name": "Operation Wocao", "brief": "The campaign used PowerShell. Its documented chain included other execution activity."}]},
        {"technique_id": "T1059.003", "reason": "Windows Command Shell is a documented continuation.",
         "previous_attacks": [{"name": "SolarWinds Compromise", "brief": "The campaign used Windows Command Shell. Its wider chain included follow-on execution."}]},
        {"technique_id": "T1204.002", "reason": "A malicious file can follow command execution.",
         "previous_attacks": [{"name": "Operation Honeybee", "brief": "The campaign included Malicious File. ATT&CK records other execution-stage activity."}]},
    ]}
    monkeypatch.setattr(llm, "complete", lambda *args, **kwargs: llm.LLMResult(
        text=json.dumps(payload), provider="openai", model="test-model", ok=True))
    result = generate(["T1059"], 3)
    assert len(result["predictions"]) == 3
    assert result["source"] == "llm:openai"
    assert result["authoritative"] is False
    assert all(row["reason"] and row["previous_attacks"] for row in result["predictions"])


def test_llm_prediction_rejects_an_invented_campaign(monkeypatch):
    payload = {"predictions": [
        {"technique_id": tid, "reason": "reason", "previous_attacks": [
            {"name": "Invented Operation", "brief": "Invented history."}]}
        for tid in ("T1059.001", "T1059.003", "T1204.002")
    ]}
    monkeypatch.setattr(llm, "complete", lambda *args, **kwargs: llm.LLMResult(
        text=json.dumps(payload), provider="openai", model="test-model", ok=True))
    try:
        generate(["T1059"], 3)
    except RuntimeError as exc:
        assert "grounded campaign example" in str(exc)
    else:
        raise AssertionError("invented campaign was accepted")
