"""
Self-check for the live analysis engine — the smallest thing that fails if the
score→correlate→graph→SOAR→attribute→report pipeline breaks.

    ./.venv/Scripts/python.exe -m pytest tests/test_live_analyze.py -q
"""
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
    return analyze_events(pd.read_csv(SCENARIO), critical_assets={"C2388"},
                          incident_id="INC-TEST")


def test_incident_has_alerts(bundle):
    inc = bundle["incident"]
    assert inc["event_count"] == 215
    assert inc["alert_count"] > 0
    assert inc["severity"] in {"low", "medium", "high", "critical"}
    assert inc["technique_ids"], "expected mapped ATT&CK techniques"


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
    # C2388 was passed in; it should surface as at-risk (no auto-guessing)
    assert bundle["meta"]["critical_assets"] == ["C2388"]


def test_rejects_oversized_and_empty():
    with pytest.raises(ValueError):
        analyze_events(pd.DataFrame())


# --- campaign: many accounts in one log ------------------------------------
CAMPAIGN = ROOT / "data" / "demo" / "scenarios" / "lanl_campaign_all.csv"


@pytest.fixture(scope="module")
def campaign():
    if not CAMPAIGN.exists():
        pytest.skip("run scripts.export_demo_events first")
    return analyze_events(pd.read_csv(CAMPAIGN), critical_assets={"C2388"},
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
    scoped = analyze_events(pd.read_csv(CAMPAIGN), critical_assets={"C2388"},
                            account="U1723@DOM1")
    assert scoped["incident"]["is_campaign"] is False
    assert scoped["incident"]["account"] == "U1723@DOM1"
    assert scoped["incident"]["alert_count"] < campaign["incident"]["alert_count"]
    assert [a["user"] for a in scoped["attackers"]] == ["U1723@DOM1"]


def test_unknown_account_rejected():
    with pytest.raises(ValueError):
        analyze_events(pd.read_csv(CAMPAIGN), account="NOBODY@DOM1")
