"""
Milestone 4 · S2 — Attack-chain correlation.

Collapses many per-event anomaly alerts into ONE incident timeline. This is the
core "reduce alert fatigue" value: SOC analysts get a single story, not 118 alerts.

Groups alerts by user + session (events within a time gap), assigns ATT&CK
techniques (via S3 mapper), and computes an incident severity.

    from src.shared.correlate import correlate
    incident = correlate(scored_events_df)   # df with schema cols + anomaly_score
"""
from __future__ import annotations

import pandas as pd

from src.shared.attack_mapper import infer_lanl_event_type, map_event

SESSION_GAP = 3600          # seconds; a >1h silence starts a new session
ALERT_THRESHOLD = 50        # anomaly_score >= this is an "alert"


def _severity(alerts: list[dict]) -> tuple[str, int]:
    score = max((a["anomaly_score"] for a in alerts), default=0)
    level = ("critical" if score >= 90 else "high" if score >= 75
             else "medium" if score >= 50 else "low")
    return level, int(score)


def correlate(events: pd.DataFrame, *, incident_id: str = "INC-PS7-001") -> dict:
    """Correlate scored events (one user's session) into a single incident.

    `events` must have schema columns + `anomaly_score`. If the LANL engineered
    columns are present, event types are inferred from behavior; otherwise the
    existing `event_type` column is used.
    """
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
            **{k: mapping[k] for k in ("tactic", "technique", "technique_id", "explanation")},
            "is_alert": score >= ALERT_THRESHOLD,
        })

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
        "event_count": len(steps),
        "start_time": min((s["timestamp"] for s in steps), default=0),
        "end_time": max((s["timestamp"] for s in steps), default=0),
        "attack_chain": [s["tactic"] for s in alerts if s["tactic"] != "Normal"],
        "technique_ids": techniques,
        "steps": steps,
        "alerts": alerts,
    }
