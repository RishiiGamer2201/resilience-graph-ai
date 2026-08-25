"""Enrolment: the workflow that makes the baseline reachable from the product.

Issue #37. `baseline.observe()` existed and nothing called it -- no route, no
CLI, no scheduler -- so the UEBA store could only be built by code outside the
application. `observe()` is also memoryless: it folds counts in with `n = n + 1`,
so running the same export twice doubled every count and moved entities toward
`mature` on evidence that never existed. That is worse than an empty store:
everything still looks new, but now it looks new authoritatively.

These tests cover the four properties the issue asks for -- enrollable,
auditable, resumable, idempotent -- plus surviving a restart, which is the one
that is easy to claim and hard to actually have.
"""
from __future__ import annotations

import sqlite3

import pandas as pd
import pytest

from src.shared import baseline


@pytest.fixture()
def store(tmp_path, monkeypatch):
    db = tmp_path / "profiles.db"
    monkeypatch.setenv(baseline.DB_ENV, str(db))
    return db


def history(n=300, users=5, days_apart=1):
    """A frame that looks like routine traffic across several days."""
    return pd.DataFrame({
        "timestamp": [i * 3600 * 24 * days_apart // 4 for i in range(n)],
        "user": [f"u{i % users}" for i in range(n)],
        "source_host": [f"WS{i % 7}" for i in range(n)],
        "destination_host": [f"SRV{i % 3}" for i in range(n)],
    })


def _sum(db, table="user_dst"):
    return sqlite3.connect(db).execute(f"SELECT COALESCE(SUM(n),0) FROM {table}").fetchone()[0]


# --------------------------------------------------------------------------- #
# it can be reached at all                                                     #
# --------------------------------------------------------------------------- #
def test_enrolling_populates_the_store(store):
    out = baseline.enroll(history(), source="history-jan.csv")
    assert out["state"] == "done"
    assert out["rows_done"] == 300
    assert _sum(store) == 300


def test_enrolling_without_a_configured_store_says_so_rather_than_failing(monkeypatch):
    monkeypatch.delenv(baseline.DB_ENV, raising=False)
    out = baseline.enroll(history())
    assert out["state"] == "off" and baseline.DB_ENV in out["detail"]


def test_a_frame_missing_the_required_columns_is_refused(store):
    with pytest.raises(ValueError):
        baseline.enroll(pd.DataFrame({"user": ["a"]}))


# --------------------------------------------------------------------------- #
# idempotent                                                                   #
# --------------------------------------------------------------------------- #
def test_enrolling_the_same_content_twice_counts_it_once(store):
    df = history()
    baseline.enroll(df, source="history-jan.csv")
    first = _sum(store)
    again = baseline.enroll(df, source="history-jan.csv")
    assert again["state"] == "already_enrolled"
    assert _sum(store) == first, "the second enrolment double-counted"


def test_the_key_is_the_content_not_the_filename(store):
    """The common way an operator double-counts: re-uploading the same export
    under a new name. A name-based key would not catch it."""
    df = history()
    baseline.enroll(df, source="history-jan.csv")
    first = _sum(store)
    out = baseline.enroll(df, source="a-completely-different-name.csv")
    assert out["state"] == "already_enrolled"
    assert _sum(store) == first


def test_different_content_is_a_different_batch(store):
    baseline.enroll(history(n=100), source="jan.csv")
    before = _sum(store)
    out = baseline.enroll(history(n=100, users=9), source="feb.csv")
    assert out["state"] == "done"
    assert _sum(store) > before, "genuinely new history must still be folded in"


# --------------------------------------------------------------------------- #
# resumable, across a restart                                                  #
# --------------------------------------------------------------------------- #
def test_a_crash_leaves_the_ledger_agreeing_with_the_counts(store, monkeypatch):
    """The property that makes resuming safe. If the watermark and the counts
    could disagree, resuming would either skip rows or double-count them."""
    real = baseline._fold
    calls = {"n": 0}

    def explode(c, part):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("process killed mid-enrolment")
        return real(c, part)

    monkeypatch.setattr(baseline, "_fold", explode)
    with pytest.raises(RuntimeError):
        baseline.enroll(history(n=300), source="big.csv", chunk=100)

    row = sqlite3.connect(store).execute(
        "SELECT state, rows, rows_done, error FROM enrollment").fetchone()
    assert row[0] == "error"
    assert row[2] == 100, "the watermark moved past a chunk that did not commit"
    assert _sum(store) == row[2], "counts and watermark disagree after a crash"
    assert "killed mid-enrolment" in row[3]


def test_re_running_after_a_crash_resumes_and_does_not_double_count(store, monkeypatch):
    real = baseline._fold
    calls = {"n": 0}

    def explode(c, part):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return real(c, part)

    monkeypatch.setattr(baseline, "_fold", explode)
    df = history(n=300)
    with pytest.raises(RuntimeError):
        baseline.enroll(df, source="big.csv", chunk=100)

    monkeypatch.setattr(baseline, "_fold", real)          # the restart
    out = baseline.enroll(df, source="big.csv", chunk=100)
    assert out["state"] == "done"
    assert out["resumed_from"] == 100
    assert _sum(store) == 300, "resuming re-folded rows that were already in"


def test_the_ledger_survives_a_restart(store, monkeypatch):
    """It is sqlite on disk, not process state. Asserted because 'resumable'
    is easy to implement in memory and useless there."""
    baseline.enroll(history(n=100), source="jan.csv")
    # a fresh module-level view of the same file is all a restart is here
    rows = baseline.enrollments()
    assert rows and rows[0]["state"] == "done" and rows[0]["rows_done"] == 100


# --------------------------------------------------------------------------- #
# reported                                                                     #
# --------------------------------------------------------------------------- #
def test_status_reports_error_and_stops_claiming_operational(store, monkeypatch):
    real = baseline._fold

    def explode(c, part):
        raise RuntimeError("disk went away")

    monkeypatch.setattr(baseline, "_fold", explode)
    with pytest.raises(RuntimeError):
        baseline.enroll(history(n=300), source="big.csv", chunk=100)
    monkeypatch.setattr(baseline, "_fold", real)

    st = baseline.status()
    assert st["state"] == "error"
    assert st["allow_operational_alerts"] is False
    assert "disk went away" in st["enrollment"]["last"]["error"]


def test_status_carries_the_batch_ledger(store):
    baseline.enroll(history(n=100), source="jan.csv")
    st = baseline.status()
    assert st["enrollment"]["batches"] == {"done": 1}
    assert st["enrollment"]["last"]["state"] == "done"


def test_a_mature_store_is_used_for_scoring_without_being_asked(store):
    """Acceptance criterion 4. apply() already gates per row on maturity; what
    was missing was any way to get history into the store in the first place."""
    baseline.enroll(history(n=600, users=3, days_apart=3), source="long.csv")
    st = baseline.status()
    assert st["state"] in ("ready", "partial")

    scored, applied = baseline.apply(history(n=20, users=3))
    assert applied["state"] == st["state"]
    assert "_baseline_entity_ready" in scored.columns


# --------------------------------------------------------------------------- #
# enrolling is an admin act                                                    #
# --------------------------------------------------------------------------- #
def test_only_an_admin_may_enroll():
    """Enrolling rewrites what `normal` means for every later analysis. A wrong
    enrolment is not a wrong answer to one question, it is a wrong baseline
    under all of them, and it is invisible in the answers."""
    from src.shared.rbac import PERMISSIONS
    assert PERMISSIONS["enroll_baseline"] == ("admin",)
