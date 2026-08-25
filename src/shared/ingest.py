"""Continuous ingestion: score what arrived, not the file it arrived in.

THE DEFECT. Every entry point takes a finite batch and computes the whole result
from it. `/api/analyze/stream` is named a stream and is not one -- it computes
the complete analysis first and then paces a replay of it, so a "streaming"
client waits for the full result before the first frame. Nothing keeps state
between calls, so the only way to add ten new events is to re-send the file they
belong to, and re-sending a file re-raises every alert already in it.

WHAT THIS ADDS. A checkpointed feed:

  * EVENTS ARE DEDUPLICATED BY CONTENT. Each row gets a fingerprint; a row whose
    fingerprint is already in the ledger is dropped before scoring. Re-sending an
    overlapping window -- which is what every collector does after a restart --
    costs nothing and raises nothing twice. This is the "no duplicate alerts"
    requirement, and it is a property of the ledger rather than of the caller
    being careful.
  * PROFILES UPDATE FROM THE FEED. New events fold into the entity baselines as
    they arrive, so "new for this device" keeps meaning new rather than
    first-in-this-batch.
  * THE CHECKPOINT IS ON DISK. It is the same sqlite store the baselines live in,
    so a restart resumes where the feed stopped instead of at the beginning.

WHAT IT DOES NOT DO, STATED PLAINLY. Scoring still needs a window of context --
the behavioural features are relative to an entity's history, and one event on
its own has none. So an ingest call scores the events it received against the
profiles as they now stand; it is incremental in the sense that no earlier
event is re-scored and no earlier alert is re-raised, not in the sense that the
detector is online. Making the detector itself online is a model change and is
not claimed here.

Endpoint, process and DNS telemetry are accepted as events and profiled by
actor, but they contribute no features of their own yet: the seven features are
authentication-shaped. Reducing the model's dependence on those seven is a
separate piece of work and this module does not pretend to have done it.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path

import pandas as pd

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ingest_seen (
    fingerprint TEXT PRIMARY KEY,
    first_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS ingest_checkpoint (
    feed TEXT PRIMARY KEY,
    events INTEGER NOT NULL DEFAULT 0,
    duplicates INTEGER NOT NULL DEFAULT 0,
    alerts INTEGER NOT NULL DEFAULT 0,
    last_timestamp REAL NOT NULL DEFAULT 0,
    updated REAL NOT NULL DEFAULT 0);
"""

FINGERPRINT_COLUMNS = ("timestamp", "user", "source_host", "destination_host",
                       "event_type", "status")


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.executescript(_SCHEMA)
    return c


def fingerprints(df: pd.DataFrame) -> list[str]:
    """One stable id per event, from the fields that identify it.

    Content, not position: a collector replaying its buffer sends the same
    events with different row numbers, and a position-based id would treat them
    as new. Two genuinely identical events in one batch collapse to one
    fingerprint, which is the correct reading of an auth log -- the same
    principal, host pair and timestamp is one event observed twice.
    """
    cols = [c for c in FINGERPRINT_COLUMNS if c in df.columns]
    if not cols:
        cols = list(df.columns)
    frame = df[cols].astype(str)
    return [hashlib.sha256("\x1f".join(row).encode()).hexdigest()[:24]
            for row in frame.itertuples(index=False, name=None)]


def checkpoint(feed: str, path: Path) -> dict | None:
    """Where this feed got to, or None if it has never been seen."""
    if not path.exists():
        return None
    with _lock, _connect(path) as c:
        row = c.execute(
            "SELECT feed,events,duplicates,alerts,last_timestamp,updated "
            "FROM ingest_checkpoint WHERE feed=?", (feed,)).fetchone()
    if row is None:
        return None
    return dict(zip(("feed", "events", "duplicates", "alerts",
                     "last_timestamp", "updated"), row))


def novel(df: pd.DataFrame, path: Path) -> tuple[pd.DataFrame, int]:
    """(rows not seen before, how many were dropped as duplicates)."""
    if df.empty:
        return df, 0
    fps = fingerprints(df)
    with _lock, _connect(path) as c:
        known = {r[0] for r in c.execute(
            "SELECT fingerprint FROM ingest_seen WHERE fingerprint IN "
            f"({','.join('?' * len(fps))})", fps)} if fps else set()
    mask = [fp not in known for fp in fps]
    # Also drop duplicates WITHIN this batch, so a collector that repeats a row
    # inside one payload does not score it twice either.
    seen_here: set[str] = set()
    for i, fp in enumerate(fps):
        if not mask[i]:
            continue
        if fp in seen_here:
            mask[i] = False
        else:
            seen_here.add(fp)
    out = df[pd.Series(mask, index=df.index)]
    return out, int(len(df) - len(out))


def remember(df: pd.DataFrame, path: Path) -> None:
    """Record these events as seen. Called only after they have been scored."""
    if df.empty:
        return
    now = time.time()
    with _lock, _connect(path) as c:
        c.executemany(
            "INSERT OR IGNORE INTO ingest_seen(fingerprint,first_seen) VALUES(?,?)",
            [(fp, now) for fp in fingerprints(df)])


def advance(feed: str, path: Path, *, events: int, duplicates: int,
            alerts: int, last_timestamp: float) -> None:
    with _lock, _connect(path) as c:
        c.execute(
            "INSERT INTO ingest_checkpoint(feed,events,duplicates,alerts,"
            "last_timestamp,updated) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(feed) DO UPDATE SET events=events+excluded.events, "
            "duplicates=duplicates+excluded.duplicates, "
            "alerts=alerts+excluded.alerts, "
            "last_timestamp=MAX(last_timestamp, excluded.last_timestamp), "
            "updated=excluded.updated",
            (feed, events, duplicates, alerts, last_timestamp, time.time()))


def ingest(df: pd.DataFrame, *, feed: str = "default",
           path: Path | None = None, critical_assets: set[str] | None = None,
           incident_id: str = "INC-FEED-001") -> dict:
    """Take a batch, score only what is new, and remember it.

    Returns the analysis of the NEW events plus the feed's running totals. When
    every row in the batch has been seen before -- the normal case for an
    overlapping replay -- nothing is scored and nothing is alerted, and the
    result says so rather than returning an empty analysis that looks like a
    quiet estate.
    """
    from src.shared import baseline
    from src.shared.live_analyze import analyze_events

    store = path or baseline.db_path()
    if store is None:
        return {"enabled": False, "state": "off",
                "detail": (f"continuous ingestion keeps its checkpoint in the "
                           f"baseline store; set {baseline.DB_ENV} to enable it")}

    fresh, duplicates = novel(df, store)
    if fresh.empty:
        # Still advance the checkpoint. A feed whose every batch is a duplicate
        # is alive and redundant, and without this it has no checkpoint row at
        # all -- indistinguishable from a feed that has never connected, which
        # is the opposite diagnosis.
        advance(feed, store, events=0, duplicates=duplicates, alerts=0,
                last_timestamp=0.0)
        cp = checkpoint(feed, store) or {}
        return {"enabled": True, "state": "no_new_events",
                "received": int(len(df)), "new": 0, "duplicates": duplicates,
                "alerts": 0, "checkpoint": cp,
                "detail": ("every event in this batch had already been ingested; "
                           "nothing was re-scored and no alert was re-raised")}

    bundle = analyze_events(fresh, critical_assets=critical_assets or set(),
                            incident_id=incident_id)
    alerts = int((bundle.get("incident") or {}).get("alert_count", 0) or 0)

    # Fold into the profiles only AFTER scoring, so a batch is never judged
    # against itself -- the store would learn the behaviour and then find it
    # ordinary, which is the same trap observe() documents.
    try:
        baseline.observe(fresh, store)
    except Exception:                             # noqa: BLE001 - profiles are best-effort
        pass

    remember(fresh, store)
    last_ts = 0.0
    if "timestamp" in fresh.columns:
        ts = pd.to_numeric(fresh["timestamp"], errors="coerce").dropna()
        last_ts = float(ts.max()) if len(ts) else 0.0
    advance(feed, store, events=int(len(fresh)), duplicates=duplicates,
            alerts=alerts, last_timestamp=last_ts)

    return {"enabled": True, "state": "ingested",
            "received": int(len(df)), "new": int(len(fresh)),
            "duplicates": duplicates, "alerts": alerts,
            "actors": bundle["meta"].get("actors", {}),
            "checkpoint": checkpoint(feed, store),
            "analysis": bundle}


__all__ = ["ingest", "novel", "remember", "advance", "checkpoint",
           "fingerprints", "FINGERPRINT_COLUMNS"]
