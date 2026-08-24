"""The reasoning lane: its guards, and the endpoint that exposes it.

Everything here runs with no provider configured, which is the default and the
path a fresh clone takes. What is being tested is not the model -- it is the
code around the model: argument routing, citation filtering, and the promise
that nothing this lane produces is authoritative.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import app
from src.shared import agent_loop, agent_tools

client = TestClient(app)
ANALYST = {"X-Role": "analyst"}


def _bundle() -> dict:
    return {
        "incident": {"incident_id": "INC-T", "alert_count": 2, "incident_count": 1,
                     "technique_ids": ["T1110"], "severity": "high", "steps": [
                         {"is_alert": True, "user": "u@d", "source_host": "A",
                          "destination_host": "B", "technique_id": "T1110",
                          "tactic": "Credential Access", "anomaly_score": 71}]},
        "graph": {"n_nodes": 2, "n_edges": 1, "attacker_pivots": ["A"],
                  "recommended_isolation": "A", "isolation_cuts": 1,
                  "blast_radius_size": 1, "paths_to_critical": {}},
        "meta": {"calibration": {"basis": "ranked-within-this-log"}},
        "claims": [],
    }


# --------------------------------------------------------------------------- #
# argument routing                                                             #
# --------------------------------------------------------------------------- #
def test_arguments_are_filtered_to_what_each_tool_accepts():
    """The strict schema forces every key on every call. Five tools take none.

    Without this filter `graph_summary` was invoked as graph_summary(host='all',
    limit=10), returned "bad arguments", and the agent -- correctly -- reported
    that it had no evidence. The lane looked like a model failure for a whole
    afternoon and was a plumbing failure.
    """
    reply = {"tool": "graph_summary", "host": "all", "limit": 10, "done": False}
    assert agent_loop._args_from(reply, "graph_summary") == {}
    assert agent_loop._args_from(reply, "list_alerts") == {"limit": 10}
    assert agent_loop._args_from(reply, "twin_isolate") == {"host": "all"}


def test_every_tool_survives_the_full_argument_set():
    """No tool may answer with 'bad arguments' when the schema is obeyed."""
    reply = {"tool": "", "host": "A", "limit": 5, "done": False}
    for name in agent_tools.TOOLS:
        args = agent_loop._args_from(reply, name)
        out = agent_tools.call(name, _bundle(), **args)
        assert "bad arguments" not in (out.get("error") or ""), (name, out)


def test_accepts_is_read_from_the_signature_not_a_list():
    """A new tool with a new argument must not need a second edit to work."""
    assert agent_tools.accepts("containment_candidates") == {"limit"}
    assert agent_tools.accepts("calibration") == set()


# --------------------------------------------------------------------------- #
# the offline path                                                             #
# --------------------------------------------------------------------------- #
def test_template_path_returns_the_same_shape(monkeypatch):
    monkeypatch.setattr(agent_loop.llm, "chosen_provider", lambda: None)
    out = agent_loop.investigate_with_agents(_bundle())
    for key in ("provider", "hypothesis", "techniques", "confidence",
                "evidence_ids", "tool_calls", "authoritative", "notes"):
        assert key in out
    assert out["authoritative"] is False
    assert out["confidence"] == 0.0, "a template states facts, it does not believe them"


def test_endpoint_runs_and_is_never_authoritative():
    r = client.post("/api/agents/reason",
                    json={"scenario": "aiims_ransomware"}, headers=ANALYST)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["authoritative"] is False
    assert body["incident_id"]
    # the workflow's own verdict travels with it, so the two are comparable on
    # screen rather than the advisory one standing alone
    assert body["workflow_severity"]


def test_endpoint_needs_a_scenario_or_events():
    r = client.post("/api/agents/reason", json={}, headers=ANALYST)
    assert r.status_code == 422


def test_a_citation_that_was_never_shown_is_dropped(monkeypatch):
    """The one guard that cannot be delegated to a prompt.

    On the first live run the model cited alert-001 and alert-003, neither of
    which it had received. Both were dropped here and the confidence zeroed.
    """
    monkeypatch.setattr(agent_loop.llm, "chosen_provider", lambda: "groq")

    calls = {"n": 0}

    def fake_ask(system, prompt, schema=None):
        calls["n"] += 1
        if schema is agent_loop.TOOL_SCHEMA:
            if calls["n"] == 1:
                return {"tool": "list_alerts", "host": "", "limit": 5,
                        "done": False}, "groq"
            return {"done": True, "tool": "", "host": "", "limit": 0}, "groq"
        if "REFUTE" in system:
            return {"refuted": False, "reasons": [], "missing_evidence": [],
                    "alternative": ""}, "groq"
        return {"hypothesis": "a claim", "techniques": ["T1110"],
                "confidence": 0.9,
                "evidence_ids": ["alert-000", "alert-999"], "missing": []}, "groq"

    monkeypatch.setattr(agent_loop, "_ask", fake_ask)
    out = agent_loop.investigate_with_agents(_bundle())
    assert out["evidence_ids"] == ["alert-000"]
    assert out["rejected_citations"] == ["alert-999"]
    assert out["confidence"] == 0.9, "one surviving citation keeps the confidence"


def test_losing_every_citation_costs_the_confidence(monkeypatch):
    monkeypatch.setattr(agent_loop.llm, "chosen_provider", lambda: "groq")

    def fake_ask(system, prompt, schema=None):
        if schema is agent_loop.TOOL_SCHEMA:
            return {"done": True, "tool": "", "host": "", "limit": 0}, "groq"
        if "REFUTE" in system:
            return {"refuted": False, "reasons": [], "missing_evidence": [],
                    "alternative": ""}, "groq"
        return {"hypothesis": "invented", "techniques": [], "confidence": 0.95,
                "evidence_ids": ["alert-404"], "missing": []}, "groq"

    monkeypatch.setattr(agent_loop, "_ask", fake_ask)
    out = agent_loop.investigate_with_agents(_bundle())
    assert out["evidence_ids"] == []
    assert out["confidence"] == 0.0


# --------------------------------------------------------------------------- #
# rate limits                                                                  #
# --------------------------------------------------------------------------- #
def test_only_rate_limits_are_retried(monkeypatch):
    """A 401 must fail once. Retrying it only delays the reason reaching a human."""
    from src.shared import llm

    monkeypatch.setenv("NEXTATTACK_LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "test-not-a-real-key")
    monkeypatch.setattr(llm.time, "sleep", lambda _s: None)

    for err, expected in ((Exception("HTTP Error 429: Too Many Requests"),
                           llm.RETRIES + 1),
                          (Exception("HTTP Error 401: Unauthorized"), 1)):
        seen = {"n": 0}

        def boom(*a, **k):
            seen["n"] += 1
            raise err

        monkeypatch.setattr(llm, "_groq", boom)
        res = llm.complete("s", "p")
        assert seen["n"] == expected, (err, seen)
        assert res.ok is False and res.error
