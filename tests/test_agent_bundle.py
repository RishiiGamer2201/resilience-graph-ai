"""The agent lane rides on the standard bundle without overwriting it.

ADR 0007: the deterministic workflow is authoritative, the agent lane is
advisory. When the agent lane began writing into the standard `/api/analyze`
bundle it replaced four authoritative fields, and the graph swap was the
dangerous one — it left the bundle reporting a 28-host blast radius over a 2-node
graph and made the digital twin recommend isolating a user account.
"""
from __future__ import annotations

import json

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.shared.live_analyze import analyze_events

CRIT = ["PATIENT-DB-01", "DC-AIIMS-01"]
ANALYST = {"X-Role": "analyst"}


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def bundle(client):
    r = client.post("/api/analyze",
                    json={"scenario": "aiims_ransomware", "critical_assets": CRIT},
                    headers=ANALYST)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope="module")
def authoritative():
    df = pd.read_csv("data/demo/scenarios/aiims_ransomware.csv")
    return analyze_events(df, critical_assets=set(CRIT))


# --------------------------------------------------------------------------- #
# the topology must survive                                                    #
# --------------------------------------------------------------------------- #
def test_the_host_topology_is_not_replaced_by_the_agent_entity_graph(bundle, authoritative):
    g, auth = bundle["graph"], authoritative["graph"]
    assert len(g["nodes"]) == len(auth["nodes"]), (
        f"topology replaced: {len(g['nodes'])} nodes vs {len(auth['nodes'])}")
    assert len(g["edges"]) == len(auth["edges"])
    assert g["topology_source"] == "attack-path analysis"


def test_the_graph_is_internally_consistent(bundle):
    """It reported blast_radius_size 28 over a 2-node graph."""
    g = bundle["graph"]
    assert len(g["nodes"]) >= g["blast_radius_size"], (
        f"{g['blast_radius_size']} hosts in blast radius but only "
        f"{len(g['nodes'])} nodes in the graph")


def test_the_agent_entity_view_is_kept_alongside(bundle):
    ag = bundle["graph"]["agent_graph"]
    assert isinstance(ag, dict), "agent_graph must be the view, not a boolean flag"
    assert "nodes" in ag and "note" in ag
    assert "authoritative" in ag["note"]


def test_the_twin_still_recommends_a_host_not_a_user_account(bundle, client):
    """With the entity graph in nodes/edges the twin recommended isolating
    `reception.rao@AIIMS` and claimed a 100% blast-radius reduction."""
    r = client.post("/api/twin/candidates",
                    json={"graph": bundle["graph"], "limit": 3}, headers=ANALYST)
    assert r.status_code == 200
    candidates = r.json()["candidates"]
    assert candidates
    top = candidates[0]
    assert "@" not in top["host"], f"twin recommended isolating an account: {top['host']}"
    assert top["crown_jewels_protected"], "top candidate protects no crown jewel"


# --------------------------------------------------------------------------- #
# authoritative fields stay authoritative                                      #
# --------------------------------------------------------------------------- #
def test_the_report_summary_is_the_deterministic_one(bundle, authoritative):
    """The report is the audit-ready artifact. Its summary must not come from an
    advisory lane."""
    assert bundle["report"]["summary"] == authoritative["report"]["summary"]


def test_the_overview_summary_is_the_deterministic_one(bundle, authoritative):
    assert (bundle["overview"]["active_incident"]["summary"]
            == authoritative["overview"]["active_incident"]["summary"])


def test_the_attack_mapping_is_the_deterministic_one(bundle, authoritative):
    assert (bundle["threat_intel"]["mapping"]
            == authoritative["threat_intel"]["mapping"])


def test_agent_output_is_present_but_clearly_labelled(bundle):
    assert bundle["report"]["agent_narrative"]
    assert bundle["overview"]["agent_narrative"]
    ti = bundle["threat_intel"]
    if "agent_mapping" in ti:
        assert "authoritative mapping above is unchanged" in ti["agent_note"]


@pytest.mark.parametrize("path", [
    ("report", "summary"), ("overview", "active_incident"),
    ("threat_intel", "mapping"),
])
def test_no_authoritative_key_is_missing_after_the_merge(bundle, path):
    node = bundle
    for key in path:
        assert key in node, f"{'.'.join(path)} lost in the agent merge"
        node = node[key]


# --------------------------------------------------------------------------- #
# contract consistency                                                         #
# --------------------------------------------------------------------------- #
def test_the_agent_pipeline_is_attached_to_the_bundle(bundle):
    ap = bundle["meta"]["agent_pipeline"]
    assert ap["status"] in ("ok", "partial", "failed")
    assert bundle["meta"]["pipeline"] == "standard+10-agent"
    if ap["status"] != "failed":
        assert ap["agent_traces"]


def test_the_streaming_path_returns_the_same_contract(client):
    """The POST path attached the agent lane and the SSE path did not, so the
    same screen behaved differently depending on which button was pressed."""
    done = None
    with client.stream("GET",
                       "/api/analyze/stream?scenario=aiims_ransomware&delay=0",
                       headers=ANALYST) as r:
        for line in r.iter_lines():
            if line.startswith("data: ") and '"meta"' in line:
                done = json.loads(line[6:])
    assert done is not None, "stream produced no done event"
    assert "agent_pipeline" in done["meta"]
    assert done["meta"]["pipeline"] == "standard+10-agent"
    assert "analysis" in done


def test_the_agent_stream_returns_the_enriched_contract(client):
    """The animated agent lane must publish the same analysis layer as POST."""
    done = None
    with client.stream(
        "GET", "/api/agents/stream?scenario=aiims_ransomware", headers=ANALYST
    ) as response:
        for line in response.iter_lines():
            if line.startswith("data: ") and '"meta"' in line:
                done = json.loads(line[6:])
    assert done is not None, "agent stream produced no done event"
    assert "analysis" in done
    assert done["analysis"]["claims"]
    assert done["meta"]["pipeline"] == "standard+10-agent"


def test_an_agent_failure_still_returns_a_usable_bundle(monkeypatch, client):
    import api.main as main
    monkeypatch.setattr(main, "_run_agents_for_standard_bundle",
                        lambda *a, **k: {"enabled": True, "status": "failed",
                                         "error": "lane down", "agent_traces": []})
    r = client.post("/api/analyze", json={"scenario": "aiims_ransomware"}, headers=ANALYST)
    assert r.status_code == 200
    b = r.json()
    assert b["incident"]["alert_count"] > 0
    assert b["graph"]["nodes"]
    assert b["meta"]["agent_pipeline"]["status"] == "failed"


def test_the_upload_path_carries_auth_headers():
    """analyze and analyzeUpload were calling fetch without the role header, so
    the backend saw an anonymous caller."""
    client = (__import__("pathlib").Path("frontend/src/lib/api.ts")).read_text(
        encoding="utf-8"
    )
    upload = client[client.index("export async function analyzeUpload"):]
    assert "authHeaders()" in upload[:600], "upload still omits the role header"
