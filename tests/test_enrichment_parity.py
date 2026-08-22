"""Every analysis path must produce the same analysis layer.

The Investigation tab had claims, the four-number assessment, the progression
forecast and the agent cross-check. The Analyze tab had only the agent lane. The
cached sample had neither. Same product, same log, different answers depending on
which button started it — which is what a teammate reported and what
`src/shared/enrich.py` exists to prevent.

These tests fail if any path drifts again.
"""
from __future__ import annotations

import json

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from api.main import app

SCENARIO = "aiims_ransomware"
CRIT = ["PATIENT-DB-01", "DC-AIIMS-01"]
ANALYST = {"X-Role": "analyst"}

# Everything src/shared/enrich attaches. A path missing any of these has drifted.
LAYER = {"claims", "assessment", "attack_progression_likelihood",
         "evidence_confidence", "crown_jewel_exposure", "progression_forecast",
         "crosscheck"}


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def via_analyze(client):
    r = client.post("/api/analyze",
                    json={"scenario": SCENARIO, "critical_assets": CRIT})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope="module")
def via_investigate(client):
    r = client.post("/api/investigate",
                    json={"scenario": SCENARIO, "critical_assets": CRIT},
                    headers=ANALYST)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope="module")
def via_upload(client):
    csv = open(f"data/demo/scenarios/{SCENARIO}.csv", "rb").read()
    r = client.post("/api/analyze/upload",
                    files={"file": (f"{SCENARIO}.csv", csv, "text/csv")},
                    data={"critical_assets": ",".join(CRIT)},
                    headers=ANALYST)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope="module")
def via_stream(client):
    done = None
    with client.stream("GET", f"/api/analyze/stream?scenario={SCENARIO}"
                              f"&critical_assets={','.join(CRIT)}&delay=0") as r:
        for line in r.iter_lines():
            if line.startswith("data: ") and '"meta"' in line:
                done = json.loads(line[6:])
    assert done is not None, "stream produced no done event"
    return done


@pytest.fixture(scope="module")
def via_cache():
    return json.load(open("api/cache/overview.json", encoding="utf-8"))


# --------------------------------------------------------------------------- #
# every path carries the layer                                                 #
# --------------------------------------------------------------------------- #
def test_analyze_carries_the_analysis_layer(via_analyze):
    assert LAYER <= set(via_analyze["analysis"]), \
        sorted(LAYER - set(via_analyze["analysis"]))


def test_upload_carries_the_analysis_layer(via_upload):
    assert LAYER <= set(via_upload["analysis"]), \
        sorted(LAYER - set(via_upload["analysis"]))


def test_the_sse_replay_carries_the_analysis_layer(via_stream):
    assert LAYER <= set(via_stream["analysis"]), \
        sorted(LAYER - set(via_stream["analysis"]))


def test_the_cached_sample_carries_the_analysis_layer(via_cache):
    """The landing page must not show a thinner product than a live run."""
    assert "analysis" in via_cache, "rebuild the cache: python -m scripts.build_cache"
    assert LAYER <= set(via_cache["analysis"]), \
        sorted(LAYER - set(via_cache["analysis"]))


def test_the_investigation_still_carries_it(via_investigate):
    imp = via_investigate["impact"]
    for key in ("claims", "assessment", "progression_forecast"):
        assert key in imp, key
    assert via_investigate["crosscheck"] is not None


# --------------------------------------------------------------------------- #
# and they agree                                                               #
# --------------------------------------------------------------------------- #
def test_analyze_and_investigate_agree_on_the_claims(via_analyze, via_investigate):
    a = {c["external_id"]: c["status"] for c in via_analyze["analysis"]["claims"]}
    i = {c["external_id"]: c["status"] for c in via_investigate["impact"]["claims"]}
    assert a == i, (a, i)


def test_analyze_and_investigate_agree_on_the_forecast(via_analyze, via_investigate):
    a = via_analyze["analysis"]["progression_forecast"]
    i = via_investigate["impact"]["progression_forecast"]
    assert a["infiltration_probability"] == i["infiltration_probability"]
    assert a["reliable_horizon"] == i["reliable_horizon"]


def test_analyze_and_investigate_agree_on_severity(via_analyze, via_investigate):
    assert (via_analyze["incident"]["severity"]
            == via_investigate["signals"]["incident"]["severity"])


def test_analyze_and_upload_agree(via_analyze, via_upload):
    """The same log by scenario name and by file upload is the same analysis."""
    assert (via_analyze["incident"]["technique_ids"]
            == via_upload["incident"]["technique_ids"])
    assert (via_analyze["analysis"]["assessment"]["impact"]["value"]
            == via_upload["analysis"]["assessment"]["impact"]["value"])


# --------------------------------------------------------------------------- #
# shape                                                                        #
# --------------------------------------------------------------------------- #
def test_the_assessment_keeps_the_four_numbers_apart(via_analyze):
    a = via_analyze["analysis"]["assessment"]
    for dim in ("anomaly", "likelihood", "impact", "confidence"):
        assert a[dim]["value"] is not None, dim
        assert a[dim]["question"], dim


def test_the_forecast_is_monotone_everywhere(via_analyze, via_upload, via_stream):
    for b in (via_analyze, via_upload, via_stream):
        cum = b["analysis"]["progression_forecast"]["infiltration_probability"]
        assert cum == sorted(cum), cum


def test_enrichment_does_not_overwrite_the_authoritative_bundle(via_analyze):
    from src.shared.live_analyze import analyze_events
    df = pd.read_csv(f"data/demo/scenarios/{SCENARIO}.csv")
    auth = analyze_events(df, critical_assets=set(CRIT))
    assert via_analyze["report"]["summary"] == auth["report"]["summary"]
    assert len(via_analyze["graph"]["nodes"]) == len(auth["graph"]["nodes"])


def test_enrichment_survives_a_failing_agent_lane(monkeypatch, client):
    import src.shared.enrich as enrich
    monkeypatch.setattr(enrich, "run_agent_lane", lambda *a, **k: None)
    r = client.post("/api/analyze", json={"scenario": SCENARIO})
    assert r.status_code == 200
    a = r.json()["analysis"]
    # deterministic half still lands; only the cross-check goes away
    assert a["claims"] and a["assessment"]
    assert a["progression_forecast"]["available"] is True
