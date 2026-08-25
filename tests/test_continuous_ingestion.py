"""Continuous ingestion, userless telemetry, and not alerting twice.

Issue #40. Every entry point took a finite batch and computed the whole result
from it; `/api/analyze/stream` computes the complete analysis first and then
paces a replay of it. Nothing kept state between calls, so adding ten events
meant re-sending the file they belong to -- and re-sending a file re-raised
every alert already in it. Network flows without a `user` were refused outright.
"""
from __future__ import annotations

import pandas as pd
import pytest

from src.shared import baseline, telemetry
from src.shared.ingest import checkpoint, fingerprints, ingest, novel


@pytest.fixture()
def store(tmp_path, monkeypatch):
    db = tmp_path / "profiles.db"
    monkeypatch.setenv(baseline.DB_ENV, str(db))
    return db


def batch(lo, hi):
    return pd.DataFrame({
        "timestamp": [i * 60 for i in range(lo, hi)],
        "user": [f"u{i % 4}" for i in range(lo, hi)],
        "source_host": [f"WS{i % 6}" for i in range(lo, hi)],
        "destination_host": [f"SRV{i % 3}" for i in range(lo, hi)],
    })


# --------------------------------------------------------------------------- #
# incremental, without replaying the file                                      #
# --------------------------------------------------------------------------- #
def test_only_new_events_are_scored(store):
    assert ingest(batch(0, 60), feed="c1")["new"] == 60
    second = ingest(batch(40, 100), feed="c1")
    assert second["new"] == 40, "already-ingested events were scored again"
    assert second["duplicates"] == 20


def test_an_exact_replay_scores_nothing_and_alerts_nothing(store):
    """What a collector does after a restart. It must be free."""
    ingest(batch(0, 60), feed="c1")
    again = ingest(batch(0, 60), feed="c1")
    assert again["state"] == "no_new_events"
    assert again["new"] == 0 and again["alerts"] == 0
    assert again["duplicates"] == 60


def test_duplicates_inside_one_payload_are_also_dropped(store):
    doubled = pd.concat([batch(0, 30), batch(0, 30)], ignore_index=True)
    out = ingest(doubled, feed="c1")
    assert out["new"] == 30 and out["duplicates"] == 30


def test_the_fingerprint_is_content_not_position():
    """A collector replaying its buffer sends the same events at different row
    numbers; a position-based id would call them new."""
    a = batch(0, 20)
    shuffled = a.sample(frac=1.0, random_state=3).reset_index(drop=True)
    assert sorted(fingerprints(a)) == sorted(fingerprints(shuffled))


def test_novel_leaves_the_ledger_alone(store):
    """novel() must not mark anything seen -- events are remembered only after
    they have been scored, or a crash mid-scoring would lose them silently."""
    ingest(batch(0, 20), feed="c1")
    fresh, dupes = novel(batch(20, 40), store)
    assert len(fresh) == 20 and dupes == 0
    again, _ = novel(batch(20, 40), store)
    assert len(again) == 20, "novel() marked events as seen"


# --------------------------------------------------------------------------- #
# the checkpoint is on disk                                                    #
# --------------------------------------------------------------------------- #
def test_the_checkpoint_survives_a_restart(store):
    ingest(batch(0, 60), feed="c1")
    ingest(batch(60, 100), feed="c1")
    cp = checkpoint("c1", store)
    assert cp["events"] == 100
    assert cp["last_timestamp"] == 99 * 60


def test_feeds_are_tracked_separately(store):
    ingest(batch(0, 30), feed="firewall")
    ingest(batch(0, 30), feed="dc-auth")     # same content, different feed
    assert checkpoint("firewall", store)["events"] == 30
    # the seen-ledger is estate-wide on purpose: the same event arriving down
    # two feeds is still one event and must not alert twice
    assert checkpoint("dc-auth", store)["events"] == 0 or \
        checkpoint("dc-auth", store)["duplicates"] == 30


def test_ingestion_without_a_store_says_so(monkeypatch):
    monkeypatch.delenv(baseline.DB_ENV, raising=False)
    out = ingest(batch(0, 10))
    assert out["state"] == "off" and baseline.DB_ENV in out["detail"]


# --------------------------------------------------------------------------- #
# userless telemetry                                                           #
# --------------------------------------------------------------------------- #
def test_flows_without_a_user_are_analysed_not_refused():
    """A NetFlow record has a source address and no principal. Refusing it is
    why network, DNS and endpoint telemetry could not enter detection at all."""
    from src.shared.live_analyze import analyze_events

    flows = pd.DataFrame({"timestamp": [i * 60 for i in range(60)],
                          "source_host": [f"10.0.0.{i % 5}" for i in range(60)],
                          "destination_host": [f"SRV{i % 3}" for i in range(60)]})
    bundle = analyze_events(flows, critical_assets=set(), incident_id="FLOW")
    assert bundle["incident"]["event_count"] == 60
    actors = bundle["meta"]["actors"]
    assert actors["device"] == 60 and actors["account"] == 0


def test_a_device_keyed_row_is_marked_as_such():
    """"This DEVICE reached five new hosts" is a weaker claim than the same
    sentence about an account, and the response to it differs."""
    df = pd.DataFrame({"user": ["", "alice"], "source_host": ["WS1", "WS2"],
                       "destination_host": ["SRV", "SRV"]})
    out, summary = telemetry.attribute_actor(df)
    assert out.loc[0, "user"] == "device:WS1"
    assert out.loc[0, telemetry.ACTOR_KIND] == "device"
    assert bool(out.loc[0, telemetry.ACTOR_INFERRED]) is True
    assert out.loc[1, "user"] == "alice"
    assert out.loc[1, telemetry.ACTOR_KIND] == "account"
    assert bool(out.loc[1, telemetry.ACTOR_INFERRED]) is False
    assert summary["device"] == 1 and summary["account"] == 1


def test_rows_with_nothing_to_profile_are_counted_not_dropped_silently():
    df = pd.DataFrame({"user": ["", ""], "source_host": ["", ""],
                       "destination_host": ["SRV", "SRV"]})
    _, summary = telemetry.attribute_actor(df)
    assert summary["unattributed"] == 2
    assert "cannot be profiled" in summary["note"]


def test_a_hostname_yields_no_segment():
    """Guessing a segment from a name would invent structure the log does not
    carry, which is how a baseline learns something false."""
    assert telemetry._segment_of("WS-FINANCE-04") is None
    assert telemetry._segment_of("10.2.3.4") == "10.2.3.0/24"


def test_an_estate_with_nothing_identifiable_is_still_refused():
    from src.shared.live_analyze import analyze_events

    nothing = pd.DataFrame({"timestamp": [1, 2], "destination_host": ["A", "B"]})
    with pytest.raises(ValueError, match="nothing to profile"):
        analyze_events(nothing, critical_assets=set(), incident_id="X")
