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
days in it is worse than none: everything still looks new, but now it looks new
authoritatively. Under `MIN_HISTORY_DAYS` the store reports `learning` with
`allow_operational_alerts=False`. The live-analysis boundary consumes that
control before correlation, graph analysis and response generation; regression
tests cover the complete API and investigation paths.

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

# Below this, the store knows too little to call anything unusual.
MIN_HISTORY_DAYS = 7
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
"""


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
    path = path or db_path()
    if path is None:
        return {"enabled": False, "state": "off",
                "allow_operational_alerts": True,
                "progress_percent": None,
                "detail": f"set {DB_ENV} to build per-entity baselines"}
    if not path.exists():
        return {"enabled": True, "state": "learning", "days": 0.0, "users": 0,
                "events": 0, "min_history_days": MIN_HISTORY_DAYS,
                "allow_operational_alerts": False, "progress_percent": 0.0,
                "detail": "no history yet"}
    with _lock, _connect(path) as c:
        users = c.execute("SELECT COUNT(*) FROM user_stats").fetchone()[0]
        events = c.execute("SELECT COALESCE(SUM(events),0) FROM user_stats").fetchone()[0]
        span = dict(c.execute("SELECT k,v FROM span").fetchall())
    days = ((span.get("last", 0) - span.get("first", 0)) / SECONDS_PER_DAY
            if len(span) == 2 else 0.0)
    ready = days >= MIN_HISTORY_DAYS
    return {
        "enabled": True,
        "state": "ready" if ready else "learning",
        "days": round(days, 2), "users": int(users), "events": int(events),
        "min_history_days": MIN_HISTORY_DAYS,
        "allow_operational_alerts": ready,
        "progress_percent": round(min(100.0, days / MIN_HISTORY_DAYS * 100.0), 1),
        "detail": (f"{days:.1f} days of history across {users} accounts"
                   if ready else
                   f"{days:.1f} of {MIN_HISTORY_DAYS} days needed. In learning "
                   f"mode nothing is called unusual: with too little history "
                   f"every host looks new, and a store this thin would say so "
                   f"authoritatively instead of admitting it."),
    }


def apply(df: pd.DataFrame, path: Path | None = None) -> tuple[pd.DataFrame, dict]:
    """Recompute the history-dependent features against the store.

    Returns `(df, status)`. When the store is off or still learning the frame
    comes back untouched and the status says which, so the caller can neither
    accidentally use a thin baseline nor silently skip a good one.

    Only the four features that depend on history are touched. `is_fail` and
    `is_ntlm` are per-row facts and do not.
    """
    st = status(path)
    if st.get("state") != "ready":
        return df, st
    path = path or db_path()

    with _lock, _connect(path) as c:
        seen_dst = {(u, d) for u, d in c.execute("SELECT user,dst FROM user_dst")}
        seen_src = {(u, s) for u, s in c.execute("SELECT user,src FROM user_src")}
        fan = dict(c.execute("SELECT user, COUNT(*) FROM user_dst GROUP BY user"))
        ustat = {u: (e, f) for u, e, f in
                 c.execute("SELECT user,events,fails FROM user_stats")}
        hosts = dict(c.execute("SELECT dst,n FROM host_stats"))

    users = df["user"].astype(str)
    dsts = df["destination_host"].astype(str)
    srcs = df["source_host"].astype(str)

    # "New" now means never seen for this account, not first-in-this-file.
    df["new_dst_for_user"] = [
        0 if (u, d) in seen_dst else 1 for u, d in zip(users, dsts)]
    df["new_src_for_user"] = [
        0 if (u, s) in seen_src else 1 for u, s in zip(users, srcs)]
    df["new_dst_for_user"] = df["new_dst_for_user"].astype("int8")
    df["new_src_for_user"] = df["new_src_for_user"].astype("int8")

    # Fan-out and fail rate start from history and accumulate within the log.
    base_fan = users.map(lambda u: fan.get(u, 0)).astype("int32")
    df["user_distinct_dst_sofar"] = (
        base_fan + df.groupby(users, sort=False)["new_dst_for_user"].cumsum()
    ).astype("int32")

    prior_n = users.map(lambda u: ustat.get(u, (0, 0))[0]).astype("float64")
    prior_f = users.map(lambda u: ustat.get(u, (0, 0))[1]).astype("float64")
    fail = df["is_fail"].astype("float64") if "is_fail" in df.columns else 0.0
    g = df.groupby(users, sort=False)
    cum_f = prior_f + (g["is_fail"].cumsum() if "is_fail" in df.columns else 0.0)
    cum_n = prior_n + g.cumcount() + 1
    df["user_fail_rate_sofar"] = (cum_f / cum_n.replace(0, np.nan)).fillna(0.0).astype("float32")

    # Rarity against the ORG, which is the whole point: a host nobody has ever
    # touched is rare, and a busy shared server is not, no matter what a single
    # upload happens to contain.
    total = float(sum(hosts.values())) or 1.0
    df["dst_rarity"] = dsts.map(
        lambda h: -np.log(max(hosts.get(h, 0), 0.5) / total)).astype("float32")
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
