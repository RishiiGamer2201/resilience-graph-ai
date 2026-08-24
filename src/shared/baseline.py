"""Per-entity history, so "new" can mean new rather than first-in-this-file.

THE DEFECT THIS EXISTS TO FIX. `engine1.lanl_detect.engineer` computes every
behavioural feature from the uploaded log alone:

  * `new_dst_for_user` is "first occurrence in this file", not "first ever"
  * `user_distinct_dst_sofar` counts within the file
  * `dst_rarity` is -log(count/N) over the file

So the first time any user touches any host, it looks new -- because in that
file it is. On a log with no attacker in it at all, up to 48.2% of events alert
(`reports/clean_log.md`). It is also why a uniform log has nothing to be
unusual relative to.

WHY THIS IS OPT-IN, AND WHY THAT IS NOT A DODGE. Changing how features are
computed invalidates every number in `reports/` -- ROC-AUC, TPR@1%FPR, the
ablations, the triage cut, all of it was measured on file-local features. A
product whose features are computed one way and whose published metrics were
measured another is worse than one with a disclosed false-positive rate. So:

    NEXTATTACK_BASELINE_DB=/path/to/profiles.db   turns it on

and the default stays off until the evals are re-run against it. `reports/` and
the scoreboard remain true statements about what ships.

COLD START IS PART OF THE FIX, NOT AN AFTERTHOUGHT. A profile store with two
events seven days apart is worse than none: everything still looks new, but now
it looks new authoritatively. Readiness therefore requires distinct active days
AND enough events for the organisation, account and source device involved in a
row. New entities remain diagnostic-only even when older entities are mature.

Storage is stdlib sqlite3 -- no new dependency, one file, ADR 0001 intact.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
DB_ENV = "NEXTATTACK_BASELINE_DB"
MIN_ACTIVE_DAYS_ENV = "NEXTATTACK_BASELINE_MIN_ACTIVE_DAYS"
MIN_EVENTS_ENV = "NEXTATTACK_BASELINE_MIN_EVENTS_PER_ENTITY"

# Policy defaults. Keep MIN_HISTORY_DAYS as a compatibility alias for callers
# and reports written before readiness became coverage based.
MIN_HISTORY_DAYS = 7
MIN_EVENTS_PER_ENTITY = 40
SECONDS_PER_DAY = 86_400

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_dst (
    user TEXT NOT NULL, dst TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user, dst));
CREATE TABLE IF NOT EXISTS user_src (
    user TEXT NOT NULL, src TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user, src));
CREATE TABLE IF NOT EXISTS user_stats (
    user TEXT PRIMARY KEY, events INTEGER NOT NULL DEFAULT 0,
    fails INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS host_stats (
    dst TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS span (
    k TEXT PRIMARY KEY, v REAL NOT NULL);
CREATE TABLE IF NOT EXISTS entity_activity (
    entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
    active_day INTEGER NOT NULL, events INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (entity_type, entity_id, active_day));
"""


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def policy() -> dict:
    """Return the configured, fail-closed baseline readiness policy."""
    return {
        "minimum_active_days": _positive_int(
            MIN_ACTIVE_DAYS_ENV, MIN_HISTORY_DAYS),
        "minimum_events_per_entity": _positive_int(
            MIN_EVENTS_ENV, MIN_EVENTS_PER_ENTITY),
    }


def db_path() -> Path | None:
    raw = os.environ.get(DB_ENV, "").strip()
    if not raw or raw.lower() in ("off", "none", "0"):
        return None
    return Path(raw)


def enabled() -> bool:
    return db_path() is not None


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.executescript(_SCHEMA)
    return c


def _activity_rows(df: pd.DataFrame) -> list[tuple[str, str, int, int]]:
    """Aggregate evidence by entity and UTC active day.

    The source account and device are the actors whose behaviour is scored. A
    destination is deliberately not a readiness gate: contacting a previously
    unseen destination is exactly the novelty the detector must be able to see.
    If an ingest supplies a source/network segment, it is tracked and gated too.
    """
    if "timestamp" not in df.columns:
        return []
    timestamp = pd.to_numeric(df["timestamp"], errors="coerce")
    valid = timestamp.notna()
    if not valid.any():
        return []
    active_day = (timestamp[valid] // SECONDS_PER_DAY).astype("int64")
    evidence = df.loc[valid].copy()
    evidence["_active_day"] = active_day.to_numpy()

    specs = [("account", "user"), ("source_device", "source_host")]
    segment_column = next((name for name in (
        "source_segment", "network_segment", "segment") if name in df.columns), None)
    if segment_column:
        specs.append(("segment", segment_column))

    rows: list[tuple[str, str, int, int]] = []
    for entity_type, column in specs:
        grouped = (evidence.assign(_entity=evidence[column].astype(str))
                   .groupby(["_entity", "_active_day"], sort=False)
                   .size())
        rows.extend((entity_type, str(entity_id), int(day), int(events))
                    for (entity_id, day), events in grouped.items())

    # Organisation evidence counts each event once, unlike the entity views.
    for day, events in evidence.groupby("_active_day", sort=False).size().items():
        rows.append(("organisation", "organisation", int(day), int(events)))
    return rows


def _coverage(c: sqlite3.Connection, configured_policy: dict) -> tuple[dict, dict]:
    """Return coverage summaries and a readiness lookup by entity kind/id."""
    minimum_days = configured_policy["minimum_active_days"]
    minimum_events = configured_policy["minimum_events_per_entity"]
    raw = c.execute(
        "SELECT entity_type,entity_id,COUNT(*),COALESCE(SUM(events),0) "
        "FROM entity_activity GROUP BY entity_type,entity_id"
    ).fetchall()
    activity = {(kind, entity): (int(days), int(events))
                for kind, entity, days, events in raw}

    # Databases created by an older release have user_stats but no active-day
    # rows. Preserve their event count but treat their day coverage as zero.
    for entity, events in c.execute("SELECT user,events FROM user_stats"):
        activity.setdefault(("account", str(entity)), (0, int(events)))

    ready = {
        key: days >= minimum_days and events >= minimum_events
        for key, (days, events) in activity.items()
    }
    coverage: dict[str, dict] = {}
    for kind in ("account", "source_device", "segment", "organisation"):
        members = [(key, activity[key]) for key in activity if key[0] == kind]
        total = len(members)
        mature = sum(1 for key, _ in members if ready[key])
        coverage[kind] = {
            "total": total,
            "mature": mature,
            "learning": total - mature,
            "coverage_percent": round(100.0 * mature / total, 1) if total else 0.0,
            "active_days": max((facts[0] for _, facts in members), default=0),
            "events": sum(facts[1] for _, facts in members),
        }
    return coverage, ready


def observe(df: pd.DataFrame, path: Path | None = None) -> dict:
    """Fold a log into the profiles. Call this on traffic known to be routine.

    Deliberately separate from scoring: a store fed by the same events it is
    used to judge would learn the attack and then find it normal.
    """
    path = path or db_path()
    if path is None:
        return {"enabled": False}
    need = {"user", "source_host", "destination_host"}
    if not need.issubset(df.columns):
        raise ValueError(f"baseline needs {sorted(need)}")

    fail = (df["is_fail"] if "is_fail" in df.columns
            else pd.Series(0, index=df.index)).astype(int)
    with _lock, _connect(path) as c:
        c.executemany("INSERT INTO user_dst(user,dst,n) VALUES(?,?,1) "
                      "ON CONFLICT(user,dst) DO UPDATE SET n=n+1",
                      list(zip(df["user"].astype(str), df["destination_host"].astype(str))))
        c.executemany("INSERT INTO user_src(user,src,n) VALUES(?,?,1) "
                      "ON CONFLICT(user,src) DO UPDATE SET n=n+1",
                      list(zip(df["user"].astype(str), df["source_host"].astype(str))))
        c.executemany("INSERT INTO host_stats(dst,n) VALUES(?,1) "
                      "ON CONFLICT(dst) DO UPDATE SET n=n+1",
                      [(h,) for h in df["destination_host"].astype(str)])
        per_user = df.assign(_f=fail).groupby(df["user"].astype(str)).agg(
            events=("_f", "size"), fails=("_f", "sum"))
        c.executemany("INSERT INTO user_stats(user,events,fails) VALUES(?,?,?) "
                      "ON CONFLICT(user) DO UPDATE SET events=events+excluded.events, "
                      "fails=fails+excluded.fails",
                      [(u, int(r.events), int(r.fails)) for u, r in per_user.iterrows()])
        c.executemany(
            "INSERT INTO entity_activity(entity_type,entity_id,active_day,events) "
            "VALUES(?,?,?,?) ON CONFLICT(entity_type,entity_id,active_day) "
            "DO UPDATE SET events=events+excluded.events",
            _activity_rows(df),
        )
        if "timestamp" in df.columns:
            ts = pd.to_numeric(df["timestamp"], errors="coerce").dropna()
            if len(ts):
                for k, v, agg in (("first", float(ts.min()), min),
                                  ("last", float(ts.max()), max)):
                    row = c.execute("SELECT v FROM span WHERE k=?", (k,)).fetchone()
                    c.execute("INSERT OR REPLACE INTO span(k,v) VALUES(?,?)",
                              (k, v if row is None else agg(row[0], v)))
    return status(path)


def status(path: Path | None = None) -> dict:
    """What the store knows, and whether it knows enough to be used."""
    configured_policy = policy()
    minimum_days = configured_policy["minimum_active_days"]
    minimum_events = configured_policy["minimum_events_per_entity"]
    path = path or db_path()
    if path is None:
        return {"enabled": False, "state": "off",
                "allow_operational_alerts": True,
                "progress_percent": None,
                **configured_policy,
                "detail": f"set {DB_ENV} to build per-entity baselines"}
    if not path.exists():
        return {"enabled": True, "state": "learning", "days": 0, "active_days": 0,
                "users": 0, "events": 0, "min_history_days": minimum_days,
                **configured_policy,
                "mature_entities": 0, "learning_entities": 0,
                "entity_coverage_percent": 0.0,
                "coverage": {},
                "allow_operational_alerts": False, "progress_percent": 0.0,
                "detail": "no history yet"}
    with _lock, _connect(path) as c:
        users = c.execute("SELECT COUNT(*) FROM user_stats").fetchone()[0]
        events = c.execute("SELECT COALESCE(SUM(events),0) FROM user_stats").fetchone()[0]
        span = dict(c.execute("SELECT k,v FROM span").fetchall())
        coverage, readiness = _coverage(c, configured_policy)

    organisation = coverage["organisation"]
    entity_kinds = ("account", "source_device", "segment")
    total_entities = sum(coverage[kind]["total"] for kind in entity_kinds)
    mature_entities = sum(coverage[kind]["mature"] for kind in entity_kinds)
    entity_coverage = (round(100.0 * mature_entities / total_entities, 1)
                       if total_entities else 0.0)
    organisation_ready = readiness.get(("organisation", "organisation"), False)
    if not organisation_ready or mature_entities == 0:
        state = "learning"
    elif mature_entities == total_entities:
        state = "ready"
    else:
        state = "partial"
    # Status describes whether at least one mature account/device lane can be
    # operational. apply() narrows this to the entities in the current request.
    allow_operational = bool(
        organisation_ready
        and coverage["account"]["mature"]
        and coverage["source_device"]["mature"]
    )
    active_days = organisation["active_days"]
    event_progress = min(1.0, events / minimum_events) if minimum_events else 1.0
    day_progress = min(1.0, active_days / minimum_days) if minimum_days else 1.0
    coverage_progress = mature_entities / total_entities if total_entities else 0.0
    progress = round(100.0 * min(day_progress, event_progress, coverage_progress), 1)
    span_days = ((span.get("last", 0) - span.get("first", 0)) / SECONDS_PER_DAY
                 if len(span) == 2 else 0.0)
    return {
        "enabled": True,
        "state": state,
        "days": int(active_days), "active_days": int(active_days),
        "history_span_days": round(span_days, 2),
        "users": int(users), "events": int(events),
        "min_history_days": minimum_days,
        **configured_policy,
        "mature_entities": mature_entities,
        "learning_entities": total_entities - mature_entities,
        "entity_coverage_percent": entity_coverage,
        "coverage": coverage,
        "allow_operational_alerts": allow_operational,
        "progress_percent": progress,
        "detail": (
            f"{active_days} distinct active days and {events} events; "
            f"{mature_entities} of {total_entities} acting entities meet the "
            f"required {minimum_days} days and {minimum_events} events."
        ),
    }


def apply(df: pd.DataFrame, path: Path | None = None) -> tuple[pd.DataFrame, dict]:
    """Recompute the history-dependent features against the store.

    Returns `(df, status)`. Enabled stores add `_baseline_entity_ready`, a
    fail-closed per-row gate consumed by live analysis. History features are
    rewritten only for rows whose organisation, account, source device and
    optional segment all meet policy.

    Only the four features that depend on history are touched. `is_fail` and
    `is_ntlm` are per-row facts and do not.
    """
    st = status(path)
    if st.get("state") == "off":
        return df, st
    path = path or db_path()

    with _lock, _connect(path) as c:
        _, readiness = _coverage(c, policy())
        seen_dst = {(u, d) for u, d in c.execute("SELECT user,dst FROM user_dst")}
        seen_src = {(u, s) for u, s in c.execute("SELECT user,src FROM user_src")}
        fan = dict(c.execute("SELECT user, COUNT(*) FROM user_dst GROUP BY user"))
        ustat = {u: (e, f) for u, e, f in
                 c.execute("SELECT user,events,fails FROM user_stats")}
        hosts = dict(c.execute("SELECT dst,n FROM host_stats"))

    users = df["user"].astype(str)
    dsts = df["destination_host"].astype(str)
    srcs = df["source_host"].astype(str)
    organisation_ready = readiness.get(("organisation", "organisation"), False)
    ready_mask = users.map(
        lambda user: readiness.get(("account", user), False)
    ) & srcs.map(
        lambda device: readiness.get(("source_device", device), False)
    )
    segment_column = next((name for name in (
        "source_segment", "network_segment", "segment") if name in df.columns), None)
    if segment_column:
        segments = df[segment_column].astype(str)
        ready_mask &= segments.map(
            lambda segment: readiness.get(("segment", segment), False))
    ready_mask &= organisation_ready
    ready_mask = ready_mask.astype(bool)
    df = df.copy()
    df["_baseline_entity_ready"] = ready_mask.to_numpy()

    operational_events = int(ready_mask.sum())
    total_events = int(len(df))
    if operational_events == 0:
        request_state = "learning"
    elif operational_events == total_events:
        request_state = "ready"
    else:
        request_state = "partial"
    st = {
        **st,
        "state": request_state,
        "allow_operational_alerts": operational_events > 0,
        "analysis_coverage": {
            "events": total_events,
            "operational_events": operational_events,
            "learning_events": total_events - operational_events,
            "coverage_percent": (
                round(100.0 * operational_events / total_events, 1)
                if total_events else 0.0
            ),
        },
    }
    if not operational_events:
        st["detail"] += " No entity in this analysis is mature; output is diagnostic-only."
        return df, st
    if request_state == "partial":
        st["detail"] += (
            f" {total_events - operational_events} current events belong to learning "
            "entities and are diagnostic-only."
        )

    # "New" now means never seen for this account, not first-in-this-file.
    historical_new_dst = pd.Series(
        [0 if (u, d) in seen_dst else 1 for u, d in zip(users, dsts)], index=df.index)
    historical_new_src = pd.Series(
        [0 if (u, s) in seen_src else 1 for u, s in zip(users, srcs)], index=df.index)
    df.loc[ready_mask, "new_dst_for_user"] = (
        historical_new_dst[ready_mask].astype("int8"))
    df.loc[ready_mask, "new_src_for_user"] = (
        historical_new_src[ready_mask].astype("int8"))
    if df["new_dst_for_user"].notna().all():
        df["new_dst_for_user"] = df["new_dst_for_user"].astype("int8")
    if df["new_src_for_user"].notna().all():
        df["new_src_for_user"] = df["new_src_for_user"].astype("int8")

    # Fan-out and fail rate start from history and accumulate within the log.
    base_fan = users.map(lambda u: fan.get(u, 0)).astype("int32")
    historical_fanout = (
        base_fan + df.groupby(users, sort=False)["new_dst_for_user"].cumsum()
    )
    df.loc[ready_mask, "user_distinct_dst_sofar"] = (
        historical_fanout[ready_mask].astype("int32"))
    if df["user_distinct_dst_sofar"].notna().all():
        df["user_distinct_dst_sofar"] = df["user_distinct_dst_sofar"].astype("int32")

    prior_n = users.map(lambda u: ustat.get(u, (0, 0))[0]).astype("float64")
    prior_f = users.map(lambda u: ustat.get(u, (0, 0))[1]).astype("float64")
    fail = df["is_fail"].astype("float64") if "is_fail" in df.columns else 0.0
    g = df.groupby(users, sort=False)
    cum_f = prior_f + (g["is_fail"].cumsum() if "is_fail" in df.columns else 0.0)
    cum_n = prior_n + g.cumcount() + 1
    historical_fail_rate = (
        cum_f / cum_n.replace(0, np.nan)).fillna(0.0).astype("float32")
    df.loc[ready_mask, "user_fail_rate_sofar"] = historical_fail_rate[ready_mask]
    if df["user_fail_rate_sofar"].notna().all():
        df["user_fail_rate_sofar"] = df["user_fail_rate_sofar"].astype("float32")

    # Rarity against the ORG, which is the whole point: a host nobody has ever
    # touched is rare, and a busy shared server is not, no matter what a single
    # upload happens to contain.
    total = float(sum(hosts.values())) or 1.0
    historical_rarity = dsts.map(
        lambda h: -np.log(max(hosts.get(h, 0), 0.5) / total)).astype("float32")
    df.loc[ready_mask, "dst_rarity"] = historical_rarity[ready_mask]
    if df["dst_rarity"].notna().all():
        df["dst_rarity"] = df["dst_rarity"].astype("float32")
    return df, st


def demo() -> None:
    """Self-check: learning mode refuses, a mature store makes routine boring."""
    import tempfile

    path = Path(tempfile.mkdtemp()) / "profiles.db"
    day = SECONDS_PER_DAY

    def log(n, t0=0, user="asha@corp", dst="FILES-01", step=60):
        return pd.DataFrame({
            "timestamp": [t0 + i * step for i in range(n)],
            "user": [user] * n, "source_host": ["LAPTOP-7"] * n,
            "destination_host": [dst] * n, "is_fail": [0] * n})

    assert status(path)["state"] == "learning", "an empty store cannot be ready"

    # Two days of history is not enough, and must say so rather than be used.
    observe(log(200, 0), path)
    observe(log(200, 2 * day), path)
    st = status(path)
    assert st["state"] == "learning", st
    out, st = apply(log(30, 3 * day), path)
    assert st["state"] == "learning"
    assert "new_dst_for_user" not in out.columns, "learning mode must not rewrite features"

    # Thirty days in, the same routine traffic is no longer novel.
    for d in range(3, 31):
        observe(log(200, d * day), path)
    st = status(path)
    assert st["state"] == "ready", st
    assert st["days"] >= MIN_HISTORY_DAYS

    routine, st = apply(log(30, 31 * day), path)
    assert routine["new_dst_for_user"].sum() == 0, "a host seen 6000 times is not new"
    assert routine["new_src_for_user"].sum() == 0
    assert routine["user_fail_rate_sofar"].max() == 0.0

    # A destination nobody has ever used is rarer than the one everybody uses.
    novel, _ = apply(log(5, 32 * day, dst="FINANCE-DB-01"), path)
    assert novel["new_dst_for_user"].sum() == 5, "an unseen host IS new"
    assert novel["dst_rarity"].iloc[0] > routine["dst_rarity"].iloc[0], \
        "an unseen destination must be rarer than a heavily used one"

    print(f"baseline ok: learning under {MIN_HISTORY_DAYS} days, "
          f"{st['users']} account(s) and {st['events']} events at "
          f"{st['days']:.0f} days, routine traffic scores 0 new hosts")


if __name__ == "__main__":
    demo()
