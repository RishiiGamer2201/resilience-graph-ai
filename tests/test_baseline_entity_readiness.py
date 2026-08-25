from __future__ import annotations

import pandas as pd

from src.shared import baseline
from src.shared.live_analyze import analyze_events


def _events(*, user: str, source: str, day: int, count: int = 10) -> pd.DataFrame:
    return pd.DataFrame({
        "timestamp": [day * baseline.SECONDS_PER_DAY + i * 60 for i in range(count)],
        "user": [user] * count,
        "source_host": [source] * count,
        "destination_host": ["FILES-01"] * count,
        "status": ["success"] * count,
        "protocol": ["Kerberos"] * count,
        "is_fail": [0] * count,
    })


def test_two_sparse_events_seven_days_apart_remain_learning(tmp_path, monkeypatch):
    monkeypatch.delenv(baseline.MIN_ACTIVE_DAYS_ENV, raising=False)
    monkeypatch.delenv(baseline.MIN_EVENTS_ENV, raising=False)
    path = tmp_path / "sparse.db"
    sparse = pd.concat([
        _events(user="asha@corp", source="LAPTOP-7", day=0, count=1),
        _events(user="asha@corp", source="LAPTOP-7", day=7, count=1),
    ], ignore_index=True)

    result = baseline.observe(sparse, path)

    assert result["history_span_days"] == 7.0
    assert result["active_days"] == 2
    assert result["events"] == 2
    assert result["state"] == "learning"
    assert result["allow_operational_alerts"] is False
    assert result["minimum_active_days"] == baseline.MIN_HISTORY_DAYS
    assert result["minimum_events_per_entity"] == baseline.MIN_EVENTS_PER_ENTITY
    assert result["coverage"]["account"]["mature"] == 0


def test_mature_store_keeps_a_new_account_diagnostic_only(tmp_path, monkeypatch):
    path = tmp_path / "mixed.db"
    monkeypatch.setenv("NEXTATTACK_BASELINE_DB", str(path))
    monkeypatch.setenv(baseline.MIN_ACTIVE_DAYS_ENV, "3")
    monkeypatch.setenv(baseline.MIN_EVENTS_ENV, "20")
    for day in range(3):
        baseline.observe(
            _events(user="mature@corp", source="LAPTOP-7", day=day), path)

    current = pd.concat([
        _events(user="mature@corp", source="LAPTOP-7", day=4),
        _events(user="new@corp", source="LAPTOP-7", day=4),
    ], ignore_index=True)
    from src.engine1.lanl_detect import engineer
    prepared = engineer(current.copy())

    applied, result = baseline.apply(prepared, path)

    mature = applied[applied["user"] == "mature@corp"]
    new = applied[applied["user"] == "new@corp"]
    assert mature["_baseline_entity_ready"].all()
    assert not new["_baseline_entity_ready"].any()
    assert result["state"] == "partial"
    assert result["analysis_coverage"] == {
        "events": 20,
        "operational_events": 10,
        "learning_events": 10,
        "coverage_percent": 50.0,
    }
    assert result["coverage"]["account"]["coverage_percent"] == 100.0


def test_scoping_to_new_account_cannot_restore_alerts_or_soar(tmp_path, monkeypatch):
    path = tmp_path / "scoped-new.db"
    monkeypatch.setenv("NEXTATTACK_BASELINE_DB", str(path))
    monkeypatch.setenv(baseline.MIN_ACTIVE_DAYS_ENV, "3")
    monkeypatch.setenv(baseline.MIN_EVENTS_ENV, "20")
    for day in range(3):
        baseline.observe(
            _events(user="mature@corp", source="LAPTOP-7", day=day), path)

    current = pd.concat([
        _events(user="mature@corp", source="LAPTOP-7", day=4),
        _events(user="new@corp", source="LAPTOP-7", day=4),
    ], ignore_index=True)
    bundle = analyze_events(current, account="new@corp", incident_id="INC-NEW")

    assert bundle["meta"]["baseline"]["state"] == "learning"
    assert bundle["meta"]["baseline"]["allow_operational_alerts"] is False
    assert bundle["meta"]["baseline"]["analysis_coverage"]["learning_events"] == 10
    assert bundle["meta"]["operational"] is False
    assert bundle["incident"]["alert_count"] == 0
    assert bundle["incident"]["severity"] == "learning"
    assert bundle["soar"]["actions"] == []


def test_readiness_policy_minimums_are_configurable(tmp_path, monkeypatch):
    monkeypatch.setenv(baseline.MIN_ACTIVE_DAYS_ENV, "2")
    monkeypatch.setenv(baseline.MIN_EVENTS_ENV, "4")
    path = tmp_path / "configured.db"
    for day in range(2):
        baseline.observe(
            _events(user="asha@corp", source="LAPTOP-7", day=day, count=2), path)

    result = baseline.status(path)

    assert result["state"] == "ready"
    assert result["minimum_active_days"] == 2
    assert result["minimum_events_per_entity"] == 4
    assert result["entity_coverage_percent"] == 100.0


def test_disabled_baseline_still_reports_off(monkeypatch):
    monkeypatch.delenv("NEXTATTACK_BASELINE_DB", raising=False)

    events = _events(user="asha@corp", source="LAPTOP-7", day=0, count=20)
    events["destination_host"] = [f"HOST-{i:02d}" for i in range(len(events))]
    bundle = analyze_events(
        events,
        incident_id="INC-BASELINE-OFF",
    )

    assert bundle["meta"]["baseline"]["state"] == "off"
    assert bundle["meta"]["baseline"]["enabled"] is False
    assert bundle["meta"]["operational"] is True
