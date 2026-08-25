"""
Milestone 4 · S2 -- Attack-chain correlation.

Turns per-event anomaly alerts into incidents: alerts that share an entity and
sit close together in time tell one story, alerts that share neither do not.

Two alerts belong to the same incident when they share a user OR a host (source
or destination) AND fall within `SESSION_GAP` of each other. A >1h silence with
no shared entity starts a new incident, so two unrelated campaigns a month apart
come back as two incidents rather than one meaningless roll-up.

    from src.shared.correlate import correlate, correlate_all
    incident  = correlate(scored_events_df)      # roll-up + ["incidents"]
    incidents = correlate_all(scored_events_df)  # just the list

`correlate()` still returns the whole-log roll-up it always has (every existing
caller reads `alert_count` / `users_involved` / `steps` from it and means "this
log"), now carrying `incidents` and `incident_count` alongside. Callers that want
the real clustering read those, or call `correlate_all()`.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right

import networkx as nx
import pandas as pd

from src.shared.attack_mapper import infer_lanl_event_type, map_event
from src.shared.severity import severity_from_score
from src.shared.thresholds import ALERT_SCORE

SESSION_GAP = 3600          # seconds; a >1h silence starts a new session
# Re-exported from src.shared.thresholds so this and attack_mapper.ALERT_SCORE
# cannot drift apart -- they were two literals held together by a comment.
ALERT_THRESHOLD = ALERT_SCORE   # anomaly_score >= this is an "alert"


def _severity(alerts: list[dict]) -> tuple[str, int]:
    score = max((a["anomaly_score"] for a in alerts), default=0)
    return severity_from_score(score), int(score)


def _clusters(steps: list[dict]) -> list[list[dict]]:
    """Split time-ordered steps into one alert group per incident.

    Joins two alerts when they share an entity and are within `SESSION_GAP`;
    incidents are the connected components of that relation.

    Only consecutive alerts per entity are compared, which yields the same
    components as comparing every pair: if two alerts share an entity and are
    within the gap, so is every alert between them on that entity's timeline.
    O(n log n) instead of O(n^2) -- the campaign log alerts 1,243 times.

    Alerts only. A benign event is not evidence of an incident, and letting
    background traffic bridge two alert groups is how everything collapses back
    into one blob (a busy DC is a destination_host for half the log).
    """
    alerts = [s for s in steps if s["is_alert"]]        # already time-ordered
    by_entity: dict[tuple[str, str], list[int]] = {}
    for i, s in enumerate(alerts):
        for kind, name in (("user", s["user"]), ("host", s["source_host"]),
                           ("host", s["destination_host"])):
            # `name == name` is False only for NaN. A missing user arrives as
            # float('nan'), which is truthy and stringifies to "nan", so without
            # this every alert with a missing entity joined one shared
            # ("user", "nan") bucket and got linked to every other one.
            if name and name == name:
                by_entity.setdefault((kind, str(name)), []).append(i)

    g = nx.Graph()
    g.add_nodes_from(range(len(alerts)))
    for idxs in by_entity.values():
        for a, b in zip(idxs, idxs[1:]):
            if alerts[b]["timestamp"] - alerts[a]["timestamp"] <= SESSION_GAP:
                g.add_edge(a, b)

    groups = [[alerts[i] for i in sorted(c)] for c in nx.connected_components(g)]
    return sorted(groups, key=lambda grp: grp[0]["timestamp"])


def _steps(events: pd.DataFrame) -> list[dict]:
    """Score + ATT&CK-map every row into a time-ordered step list."""
    df = events.sort_values("timestamp").reset_index(drop=True)
    has_features = "new_dst_for_user" in df.columns

    steps = []
    for _, row in df.iterrows():
        et = (infer_lanl_event_type(row.to_dict()) if has_features
              else str(row.get("event_type", "normal_auth")))
        mapping = map_event(et)
        score = int(row.get("anomaly_score", mapping["base_severity"]))
        steps.append({
            "timestamp": int(row["timestamp"]),
            "user": row.get("user", ""),
            "source_host": row.get("source_host", ""),
            "destination_host": row.get("destination_host", ""),
            "anomaly_score": score,
            # event_type travels with the step so downstream consumers can rebuild
            # the full claim (status, missing evidence, benign alternatives) rather
            # than guessing it back from the technique id. Without it every claim
            # silently fell back to "normal_auth" and reported zero confidence.
            "event_type": et,
            **{k: mapping[k] for k in ("tactic", "technique", "technique_id", "explanation")},
            "is_alert": score >= ALERT_THRESHOLD,
        })
    return steps


def _incident(steps: list[dict], incident_id: str) -> dict:
    """Build one incident dict from a group of steps."""
    alerts = [s for s in steps if s["is_alert"]]
    level, max_score = _severity(alerts)
    users = sorted({s["user"] for s in alerts})
    hosts = sorted({s["source_host"] for s in alerts}
                   | {s["destination_host"] for s in alerts})
    techniques = []
    for s in alerts:                       # ordered, de-duplicated technique chain
        tid = s["technique_id"]
        if tid != "-" and tid not in techniques:
            techniques.append(tid)

    return {
        "incident_id": incident_id,
        "severity": level,
        "max_anomaly_score": max_score,
        "users_involved": users,
        "hosts_involved": hosts,
        "alert_count": len(alerts),
        "event_count": len(steps),   # sub-incidents get the true span in _split()
        "start_time": min((s["timestamp"] for s in steps), default=0),
        "end_time": max((s["timestamp"] for s in steps), default=0),
        "attack_chain": [s["tactic"] for s in alerts if s["tactic"] != "Normal"],
        "technique_ids": techniques,
        "steps": steps,
        "alerts": alerts,
    }


def _split(steps: list[dict], incident_id: str) -> list[dict]:
    """One incident per cluster, each with the true event span of its window.

    `_incident` derives `event_count` from the steps it is handed, and a
    sub-incident is handed alerts only -- so it reported `event_count ==
    alert_count` and every caller formatting one printed "N alerts correlated
    from N events". The honest number is how many events the log actually holds
    between the incident's first and last alert, which is what we count here.
    """
    ts = [s["timestamp"] for s in steps]        # _steps() sorted these
    out = []
    for n, grp in enumerate(_clusters(steps), 1):
        inc = _incident(grp, f"{incident_id}-{n:02d}")
        inc["event_count"] = (bisect_right(ts, inc["end_time"])
                              - bisect_left(ts, inc["start_time"]))
        out.append(inc)
    return out


def correlate_all(events: pd.DataFrame, *, incident_id: str = "INC-PS7-001") -> list[dict]:
    """Every incident in `events`, chronologically, same dict shape as `correlate`.

    An incident's `steps` are the alerts that formed it -- the benign events
    around them stay on the `correlate()` roll-up, which is the whole log. Its
    `event_count` is therefore NOT `len(steps)`: it is every event in the log
    inside the incident's window, alerts and benign traffic alike.
    """
    return _split(_steps(events), incident_id)


def correlate(events: pd.DataFrame, *, incident_id: str = "INC-PS7-001") -> dict:
    """Correlate scored events into the whole-log incident roll-up.

    `events` must have schema columns + `anomaly_score`. If the LANL engineered
    columns are present, event types are inferred from behavior; otherwise the
    existing `event_type` column is used.

    Top-level keys describe the entire log, unchanged. `incidents` is the real
    clustering (see `correlate_all`) and `incident_count` is how many there are
    -- the number that used to be 1 for any input.
    """
    steps = _steps(events)
    incident = _incident(steps, incident_id)
    incident["incidents"] = _split(steps, incident_id)
    incident["incident_count"] = len(incident["incidents"])
    return incident
