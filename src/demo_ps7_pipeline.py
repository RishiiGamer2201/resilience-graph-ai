import csv
import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "data" / "demo"
OUT_DIR = DEMO_DIR / "pipeline_outputs"
SCENARIO_FILE = DEMO_DIR / "red_team_scenario.csv"


MITRE_RULES = {
    "failed_login_burst": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "severity": 55,
    },
    "unusual_successful_login": {
        "tactic": "Initial Access",
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "severity": 65,
    },
    "discovery_command": {
        "tactic": "Discovery",
        "technique": "System Network Configuration Discovery",
        "technique_id": "T1016",
        "severity": 50,
    },
    "lateral_movement": {
        "tactic": "Lateral Movement",
        "technique": "Remote Services",
        "technique_id": "T1021",
        "severity": 78,
    },
    "critical_asset_access": {
        "tactic": "Collection",
        "technique": "Data from Information Repositories",
        "technique_id": "T1213",
        "severity": 85,
    },
    "large_outbound_transfer": {
        "tactic": "Exfiltration",
        "technique": "Exfiltration Over Web Service",
        "technique_id": "T1567",
        "severity": 92,
    },
}


def write_demo_scenario():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    rows = [
        ["timestamp", "user", "source_host", "destination_host", "event_type", "status", "bytes_out", "command", "asset_criticality"],
        ["100", "U104@GOV", "C101", "AUTH-SRV", "normal_login", "success", "1200", "", "medium"],
        ["140", "U217@GOV", "C233", "AUTH-SRV", "normal_login", "success", "900", "", "medium"],
        ["200", "U748@GOV", "C17693", "AUTH-SRV", "failed_login_burst", "failure", "0", "", "medium"],
        ["214", "U748@GOV", "C17693", "AUTH-SRV", "unusual_successful_login", "success", "1000", "", "medium"],
        ["260", "U748@GOV", "C17693", "C305", "discovery_command", "success", "500", "whoami /all && net view", "medium"],
        ["310", "U748@GOV", "C17693", "C728", "lateral_movement", "success", "2200", "psexec-like remote session", "high"],
        ["360", "U748@GOV", "C728", "DB-CITIZEN-01", "critical_asset_access", "success", "8700", "database enumeration", "critical"],
        ["420", "U748@GOV", "DB-CITIZEN-01", "EXT-185.77.21.9", "large_outbound_transfer", "success", "850000000", "archive upload", "critical"],
    ]

    with SCENARIO_FILE.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)


def read_events():
    with SCENARIO_FILE.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def normalize_events(events):
    normalized = []
    for event in events:
        normalized.append(
            {
                "timestamp": int(event["timestamp"]),
                "user": event["user"],
                "source_host": event["source_host"],
                "destination_host": event["destination_host"],
                "event_type": event["event_type"],
                "status": event["status"],
                "bytes_out": int(event["bytes_out"]),
                "command": event["command"],
                "asset_criticality": event["asset_criticality"],
            }
        )
    return sorted(normalized, key=lambda row: row["timestamp"])


def score_and_map_events(events):
    enriched = []
    for event in events:
        rule = MITRE_RULES.get(event["event_type"])
        if not rule:
            anomaly_score = 5
            tactic = "Normal"
            technique = "Expected Activity"
            technique_id = "-"
        else:
            anomaly_score = rule["severity"]
            tactic = rule["tactic"]
            technique = rule["technique"]
            technique_id = rule["technique_id"]

        if event["bytes_out"] > 100_000_000:
            anomaly_score = max(anomaly_score, 95)
        if event["asset_criticality"] == "critical":
            anomaly_score = min(100, anomaly_score + 5)

        enriched.append(
            {
                **event,
                "anomaly_score": anomaly_score,
                "mitre_tactic": tactic,
                "mitre_technique": technique,
                "mitre_technique_id": technique_id,
                "is_alert": anomaly_score >= 50,
            }
        )
    return enriched


def correlate_incident(events):
    alerts = [event for event in events if event["is_alert"]]
    users = sorted({event["user"] for event in alerts})
    hosts = sorted({event["source_host"] for event in alerts} | {event["destination_host"] for event in alerts})
    max_score = max(event["anomaly_score"] for event in alerts)

    if max_score >= 90:
        severity = "critical"
    elif max_score >= 75:
        severity = "high"
    elif max_score >= 50:
        severity = "medium"
    else:
        severity = "low"

    return {
        "incident_id": "INC-PS7-DEMO-001",
        "title": "Compromised account with lateral movement and possible exfiltration",
        "severity": severity,
        "users_involved": users,
        "hosts_involved": hosts,
        "alert_count": len(alerts),
        "start_time": min(event["timestamp"] for event in alerts),
        "end_time": max(event["timestamp"] for event in alerts),
        "max_anomaly_score": max_score,
    }


def build_attack_path(events):
    edges = []
    for event in events:
        if event["is_alert"]:
            edges.append(
                {
                    "from": event["source_host"],
                    "to": event["destination_host"],
                    "user": event["user"],
                    "event_type": event["event_type"],
                    "mitre_tactic": event["mitre_tactic"],
                    "score": event["anomaly_score"],
                }
            )
    return edges


def recommend_soar_actions(incident, events):
    actions = []
    users = incident["users_involved"]
    critical_hosts = sorted(
        {
            event["destination_host"]
            for event in events
            if event["asset_criticality"] == "critical" and event["is_alert"]
        }
    )

    if users:
        actions.append(
            {
                "action": "Disable or step-up verify compromised account",
                "target": ", ".join(users),
                "mode": "human approval required",
                "reason": "Valid account activity appears in multiple attack stages.",
            }
        )
    if critical_hosts:
        actions.append(
            {
                "action": "Isolate critical asset session and preserve forensic snapshot",
                "target": ", ".join(critical_hosts),
                "mode": "simulated containment",
                "reason": "Critical asset access and possible exfiltration detected.",
            }
        )
    actions.append(
        {
            "action": "Block suspicious external destination",
            "target": "EXT-185.77.21.9",
            "mode": "simulated firewall block",
            "reason": "Large outbound transfer mapped to Exfiltration.",
        }
    )
    actions.append(
        {
            "action": "Open incident ticket and notify SOC lead",
            "target": incident["incident_id"],
            "mode": "automatic",
            "reason": "Critical severity incident requires response coordination.",
        }
    )
    return actions


def write_outputs(events, incident, attack_path, actions):
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    enriched_file = OUT_DIR / "01_enriched_events.csv"
    with enriched_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(events[0].keys()))
        writer.writeheader()
        writer.writerows(events)

    attack_path_file = OUT_DIR / "02_attack_path_edges.csv"
    with attack_path_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(attack_path[0].keys()))
        writer.writeheader()
        writer.writerows(attack_path)

    with (OUT_DIR / "03_incident_summary.json").open("w", encoding="utf-8") as f:
        json.dump(incident, f, indent=2)

    with (OUT_DIR / "04_soar_actions.json").open("w", encoding="utf-8") as f:
        json.dump(actions, f, indent=2)

    report_lines = [
        "# PS7 Demo Incident Report",
        "",
        f"Incident: {incident['incident_id']}",
        f"Title: {incident['title']}",
        f"Severity: {incident['severity']}",
        f"Max anomaly score: {incident['max_anomaly_score']}",
        "",
        "## Attack Timeline",
    ]
    for event in events:
        if event["is_alert"]:
            report_lines.append(
                f"- t={event['timestamp']}: {event['event_type']} from {event['source_host']} "
                f"to {event['destination_host']} mapped to {event['mitre_tactic']} / "
                f"{event['mitre_technique']} ({event['mitre_technique_id']}); score={event['anomaly_score']}."
            )

    report_lines.extend(["", "## Recommended Response"])
    for action in actions:
        report_lines.append(f"- {action['action']} on {action['target']} ({action['mode']}): {action['reason']}")

    (OUT_DIR / "05_incident_report.md").write_text("\n".join(report_lines), encoding="utf-8")


def main():
    write_demo_scenario()
    raw_events = read_events()
    normalized = normalize_events(raw_events)
    enriched = score_and_map_events(normalized)
    incident = correlate_incident(enriched)
    attack_path = build_attack_path(enriched)
    actions = recommend_soar_actions(incident, enriched)
    write_outputs(enriched, incident, attack_path, actions)

    print("PS7 demo pipeline completed.")
    print(f"Scenario input: {SCENARIO_FILE}")
    print(f"Outputs: {OUT_DIR}")
    print(json.dumps(incident, indent=2))


if __name__ == "__main__":
    main()
