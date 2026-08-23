"""
Correlation must produce MANY incidents.

`correlate()` used to return one incident for any input -- every event in the
frame, unconditionally -- so "2,732 events correlated into 1 incident" was
arithmetic, not analysis. These tests pin the clustering down:

    python3 -m pytest tests/test_correlate.py -q
"""
from pathlib import Path

import pandas as pd
import pytest

from src.shared import correlate as C

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "data" / "demo" / "scenarios"

MONTH = 30 * 24 * 3600


def _events(rows: list[tuple]) -> pd.DataFrame:
    """(offset_sec, user, src, dst) -> scored frame. All rows alert (score 80)."""
    return pd.DataFrame(
        [{"timestamp": t, "user": u, "source_host": s, "destination_host": d,
          "status": "success", "protocol": "NTLM", "anomaly_score": 80,
          "event_type": "ntlm_lateral_movement"} for t, u, s, d in rows])


def _campaign(t0: int, user: str, host: str, n: int = 5) -> list[tuple]:
    """One continuous campaign: n alerts 10 min apart, one user, one host pair."""
    return [(t0 + i * 600, user, host, f"{host}-DC") for i in range(n)]


# --- 1. two unrelated campaigns a month apart -------------------------------
def test_two_unrelated_campaigns_are_two_incidents():
    """Nothing shared -- different users, different hosts, a month of silence."""
    df = _events(_campaign(1_000_000, "alice@CORP", "WS-A")
                 + _campaign(1_000_000 + MONTH, "bob@CORP", "WS-B"))
    inc = C.correlate(df)

    assert inc["incident_count"] == 2, "unrelated campaigns must not merge"
    assert len(inc["incidents"]) == 2
    assert [i["incident_id"] for i in inc["incidents"]] == \
        ["INC-PS7-001-01", "INC-PS7-001-02"]
    assert [i["users_involved"] for i in inc["incidents"]] == \
        [["alice@CORP"], ["bob@CORP"]]
    # ...and the roll-up still describes the whole log
    assert inc["alert_count"] == 10 and inc["users_involved"] == ["alice@CORP", "bob@CORP"]


def test_correlate_all_returns_every_incident():
    df = _events(_campaign(1_000_000, "alice@CORP", "WS-A")
                 + _campaign(1_000_000 + MONTH, "bob@CORP", "WS-B"))
    incidents = C.correlate_all(df, incident_id="INC-X")
    assert len(incidents) == 2
    assert [i["incident_id"] for i in incidents] == ["INC-X-01", "INC-X-02"]
    # same shape as correlate()'s dict, minus the two added keys
    assert set(incidents[0]) == set(C.correlate(df)) - {"incidents", "incident_count"}


# --- 2. one continuous campaign --------------------------------------------
def test_one_continuous_campaign_is_one_incident():
    df = _events(_campaign(1_000_000, "alice@CORP", "WS-A", n=12))
    assert C.correlate(df)["incident_count"] == 1


def test_shared_entity_bridges_the_gap():
    """A shared host holds one incident together across a >1h step; a lone alert
    sharing neither user nor host does not join it."""
    same_host = _events(_campaign(1_000_000, "alice@CORP", "WS-A", n=2)
                        + _campaign(1_000_000 + 3000, "bob@CORP", "WS-A", n=2))
    assert C.correlate(same_host)["incident_count"] == 1

    stranger = _events(_campaign(1_000_000, "alice@CORP", "WS-A", n=2)
                       + [(1_000_000 + 300, "eve@CORP", "WS-Z", "WS-Z-DC")])
    assert C.correlate(stranger)["incident_count"] == 2


def test_benign_events_never_form_an_incident():
    """Below the alert line = no incident, and the roll-up still counts the events."""
    df = _events(_campaign(1_000_000, "alice@CORP", "WS-A", n=4))
    df["anomaly_score"] = 10
    inc = C.correlate(df)
    assert inc["incident_count"] == 0 and inc["incidents"] == []
    assert inc["event_count"] == 4 and inc["alert_count"] == 0


# --- 3. SESSION_GAP is actually read ---------------------------------------
def test_session_gap_is_read_not_dead_code(monkeypatch):
    """The regression this whole module exists for: `SESSION_GAP` was declared,
    documented and never read. Widening it past a month must merge the two
    campaigns; narrowing it must split one campaign. If this passes for any value
    of SESSION_GAP, the constant is dead again."""
    two = _events(_campaign(1_000_000, "alice@CORP", "WS-A")
                  + _campaign(1_000_000 + MONTH, "bob@CORP", "WS-B"))
    one = _events(_campaign(1_000_000, "alice@CORP", "WS-A", n=6))  # 10 min apart

    assert C.correlate(two)["incident_count"] == 2
    assert C.correlate(one)["incident_count"] == 1

    monkeypatch.setattr(C, "SESSION_GAP", 2 * MONTH)
    assert C.correlate(two)["incident_count"] == 2, \
        "different users AND different hosts: time alone must not merge them"

    monkeypatch.setattr(C, "SESSION_GAP", 60)   # 1 min < the 10 min spacing
    assert C.correlate(one)["incident_count"] == 6, \
        "SESSION_GAP is not being read -- every alert should be its own incident"


def test_session_gap_boundary_is_inclusive():
    """Exactly SESSION_GAP apart is still one session; one second more is not."""
    u, h = "alice@CORP", "WS-A"
    assert C.correlate(_events([(0, u, h, "DC"), (C.SESSION_GAP, u, h, "DC")])
                       )["incident_count"] == 1
    assert C.correlate(_events([(0, u, h, "DC"), (C.SESSION_GAP + 1, u, h, "DC")])
                       )["incident_count"] == 2


# --- 4. shipped scenarios: roll-up unchanged, incident_count no longer 1 -----
# Recorded from the shipped scenarios BEFORE the clustering landed (score with
# the live detector, then correlate). The roll-up feeds live_analyze, views,
# workflow, explain and the agent lane, so these four fields may not move.
# `incidents` is what the clustering finds -- measured, not tuned. cbse really is
# ONE incident: 26 alerts inside 2,326s with a 444s worst gap and shared hosts
# throughout. The two logs that span weeks are the ones that split.
BEFORE = {
    "aiims_ransomware": (26, 125, "critical", ["T1110", "T1078", "T1550.002"]),
    "cbse_exam_breach": (26, 127, "critical", ["T1110", "T1078", "T1550.002"]),
    "lanl_campaign_all": (1243, 2732, "critical",
                          ["T1550.002", "T1078", "T1110", "T1021"]),
    "lanl_redteam_u66": (208, 215, "critical", ["T1550.002", "T1110", "T1078"]),
}
INCIDENTS = {"aiims_ransomware": 2, "cbse_exam_breach": 1,
             "lanl_campaign_all": 51, "lanl_redteam_u66": 9}


@pytest.fixture(scope="module")
def scored() -> dict[str, pd.DataFrame]:
    """The four shipped scenarios, scored exactly as the live pipeline scores them."""
    if not (SCENARIOS / "lanl_redteam_u66.csv").exists():
        pytest.skip("run scripts.export_demo_events first")
    from src.engine1.lanl_detect import engineer
    from src.shared.live_analyze import _prepare, _score

    out = {}
    for name in BEFORE:
        df = engineer(_prepare(pd.read_csv(SCENARIOS / f"{name}.csv")))
        df["anomaly_score"] = _score(df)[0].astype(int)
        out[name] = df
    return out


@pytest.mark.parametrize("name", list(BEFORE))
def test_shipped_scenario_rollup_unchanged(scored, name):
    alerts, events, severity, techniques = BEFORE[name]
    inc = C.correlate(scored[name], incident_id="INC-TEST")
    assert (inc["alert_count"], inc["event_count"], inc["severity"],
            inc["technique_ids"]) == (alerts, events, severity, techniques)


@pytest.mark.parametrize("name", list(BEFORE))
def test_shipped_scenario_incident_counts(scored, name):
    """`Incidents = 1` for all four scenarios was the defect, not a finding."""
    inc = C.correlate(scored[name])
    assert inc["incident_count"] == INCIDENTS[name]
    assert inc["incident_count"] == len(inc["incidents"])
    # every alert lands in exactly one incident, none invented, none dropped
    assert sum(i["alert_count"] for i in inc["incidents"]) == inc["alert_count"]
    assert all(i["alert_count"] > 0 for i in inc["incidents"])


def test_month_long_campaign_log_is_not_one_incident(scored):
    """The headline defect: 2,732 events over 28 days came back as `1 incident`
    because the function could not return anything else."""
    inc = C.correlate(scored["lanl_campaign_all"])
    assert inc["end_time"] - inc["start_time"] > 20 * 24 * 3600, "log spans weeks"
    assert inc["incident_count"] > 10
    assert max(i["alert_count"] for i in inc["incidents"]) < inc["alert_count"], \
        "no single incident may contain every alert in a month-long log"
