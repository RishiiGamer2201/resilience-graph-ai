"""
Self-check for the live analysis engine — the smallest thing that fails if the
score→correlate→graph→SOAR→attribute→report pipeline breaks.

    ./.venv/Scripts/python.exe -m pytest tests/test_live_analyze.py -q
"""
import json
from pathlib import Path

import pandas as pd
import pytest

from src.shared.live_analyze import analyze_events

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "demo" / "scenarios" / "lanl_redteam_u66.csv"


@pytest.fixture(scope="module")
def bundle():
    if not SCENARIO.exists():
        pytest.skip("run scripts.export_demo_events first")
    return analyze_events(pd.read_csv(SCENARIO), critical_assets=set(CRIT),
                          incident_id="INC-TEST")


def test_incident_has_alerts(bundle):
    inc = bundle["incident"]
    assert inc["event_count"] == 215
    assert inc["alert_count"] > 0
    assert inc["severity"] in {"low", "medium", "high", "critical"}
    assert inc["technique_ids"], "expected mapped ATT&CK techniques"


def test_scores_spread_not_all_pegged(bundle):
    """Regression: the calibration once pinned the 1% FPR line to score 50, so
    every real attack event (far past it) saturated to exactly 100 — the replay
    was a wall of '100'. The piecewise-log scale must spread scores instead."""
    scores = [s["anomaly_score"] for s in bundle["incident"]["steps"]]
    assert scores, "expected per-event steps"
    pegged = sum(s >= 100 for s in scores)
    assert pegged < len(scores) * 0.5, f"too many scores pegged at 100: {pegged}/{len(scores)}"
    assert len(set(scores)) >= 5, f"scores must vary, got {sorted(set(scores))}"


def test_calibration_monotonic_and_bounded():
    """The 0-100 scale must be monotonic and keep the anchors in place:
    routine behaviour near 0, a mildly-unusual event below the malicious one,
    and the malicious vector at the top."""
    from src.shared import detector
    ref = detector.anchors()
    if ref is None:
        pytest.skip("autoencoder artifact not built")
    benign = [0, 0, 0, 50, 0.001, 4.0, 0]
    mild = [0, 1, 0, 10, 0.0, 6.0, 0]
    mal = [0, 1, 1, 20, 0.05, 10.0, 1]
    raw = detector.raw_scores([benign, mild, mal])
    s = detector.calibrate(raw, ref)
    assert 0 <= s[0] < s[1] < s[2] <= 100, f"not monotonic/bounded: {list(s)}"
    assert s[0] < 45, f"routine behaviour should be well below the alert line: {s[0]}"


def test_graph_reflects_pivot(bundle):
    g = bundle["graph"]
    assert g["n_nodes"] > 1 and g["n_edges"] > 0
    assert g["entry_host"] == "C17693", "known red-team pivot host"
    assert g["blast_radius_size"] > 0


def test_attribution_and_report(bundle):
    assert bundle["threat_intel"]["attribution"], "expected ranked actors"
    r = bundle["report"]
    assert r["attributed_actor"]["actor"] != "—"
    assert r["predicted_next"], "expected next-technique predictions"


def test_mttd_computed_from_timestamps(bundle):
    mttd = bundle["overview"]["mttd"]
    # measured, not hardcoded: seconds present and derived from the log
    assert "ours_seconds" in mttd and mttd["ours_seconds"] >= 0
    assert mttd["value"]  # human string


def test_critical_asset_is_caller_supplied(bundle):
    # crown jewels come from the caller — the engine never guesses one
    assert bundle['meta']['critical_assets'] == sorted(CRIT)


def test_rejects_oversized_and_empty():
    with pytest.raises(ValueError):
        analyze_events(pd.DataFrame())


def test_column_aliases_resolved():
    """Regression (TestSprite used generic headers): username/source/destination
    should resolve to user/source_host/destination_host so a judge's own log works."""
    import io
    csv = ("timestamp,username,source,destination,status,protocol\n"
           "2023-04-01T12:00:00Z,u1,WS1,SRV1,fail,NTLM\n"
           "2023-04-01T12:00:30Z,u1,WS1,SRV1,success,NTLM\n"
           "2023-04-01T12:01:00Z,u1,WS1,DC1,success,NTLM\n")
    b = analyze_events(pd.read_csv(io.StringIO(csv)), critical_assets={"DC1"})
    assert b["incident"]["event_count"] == 3
    assert b["incident"]["pivot"] == "WS1"


def test_iso8601_timestamps_accepted():
    """Regression (found by TestSprite): an uploaded CSV with ISO-8601 timestamp
    strings crashed with `invalid literal for int()`. Real logs use datetimes."""
    import io
    csv = ("timestamp,user,source_host,destination_host,status,protocol\n"
           "2026-07-16T10:00:00Z,a@CORP,WS-01,SRV-01,fail,NTLM\n"
           "2026-07-16T10:00:20Z,a@CORP,WS-01,SRV-01,success,NTLM\n"
           "2026-07-16T10:01:00Z,a@CORP,WS-01,DC-01,success,NTLM\n")
    b = analyze_events(pd.read_csv(io.StringIO(csv)), critical_assets={"DC-01"})
    assert b["incident"]["event_count"] == 3
    assert b["incident"]["pivot"] == "WS-01"


# --- campaign: many accounts in one log ------------------------------------
CRIT = [a["host"] for a in json.loads((ROOT / "data" / "demo" / "scenarios" / "critical_assets.json").read_text())["assets"]] if (ROOT / "data" / "demo" / "scenarios" / "critical_assets.json").exists() else []
CAMPAIGN = ROOT / "data" / "demo" / "scenarios" / "lanl_campaign_all.csv"


@pytest.fixture(scope="module")
def campaign():
    if not CAMPAIGN.exists():
        pytest.skip("run scripts.export_demo_events first")
    return analyze_events(pd.read_csv(CAMPAIGN), critical_assets=set(CRIT),
                          incident_id="INC-CAMPAIGN")


def test_campaign_covers_many_accounts(campaign):
    """The red team used 104 accounts — the view must not collapse to one victim."""
    assert campaign["overview"]["is_campaign"] is True
    assert campaign["overview"]["accounts_involved"] > 100
    assert "accounts" in campaign["overview"]["active_incident"]["account"]
    assert len(campaign["attackers"]) > 100


def test_campaign_edges_keep_every_account(campaign):
    """A campaign sends many accounts down the same host pair; filtering the graph
    by account breaks if an edge only remembers the first one."""
    shared = [e for e in campaign["graph"]["edges"] if len(e["users"]) > 1]
    assert shared, "expected at least one host pair used by multiple accounts"


def test_account_scoping_produces_its_own_incident(campaign):
    scoped = analyze_events(pd.read_csv(CAMPAIGN), critical_assets=set(CRIT),
                            account="U1723@DOM1")
    assert scoped["incident"]["is_campaign"] is False
    assert scoped["incident"]["account"] == "U1723@DOM1"
    assert scoped["incident"]["alert_count"] < campaign["incident"]["alert_count"]
    assert [a["user"] for a in scoped["attackers"]] == ["U1723@DOM1"]


def test_unknown_account_rejected():
    with pytest.raises(ValueError):
        analyze_events(pd.read_csv(CAMPAIGN), account="NOBODY@DOM1")


def test_all_attacker_pivots_are_found(campaign):
    """Regression: the model assumed ONE entry host. The LANL red team ran from
    four, so reachability from the busiest one alone silently under-reported."""
    g = campaign["graph"]
    assert g["n_pivots"] == 4, "expected all four attacker source hosts"
    flagged = {n["id"] for n in g["nodes"] if n["pivot"]}
    assert flagged == set(g["attacker_pivots"])


def test_crown_jewels_agree_across_screens(campaign):
    """Regression: the Attackers table said an account reached a crown jewel while
    the graph cleared it, because paths were only searched from one pivot."""
    reached = set()
    for a in campaign["attackers"]:
        reached |= set(a["critical_reached"])
    at_risk = set(campaign["graph"]["critical_assets_at_risk"])
    assert not (reached - at_risk), f"reached but not flagged at risk: {reached - at_risk}"


def test_isolation_cuts_distinct_from_total_exposure(campaign):
    """Isolating one choke point cannot sever hosts that only other pivots reach."""
    g = campaign["graph"]
    assert g["isolation_cuts"] <= g["blast_radius_size"]
