import requests
import json

BASE_URL = "http://localhost:8000"
TIMEOUT = 30
HEADERS = {"Content-Type": "application/json"}


def test_analyze_raw_events():
    url = f"{BASE_URL}/api/analyze"

    # Updated minimal valid event schema with correct field names
    valid_events = [
        {
            "id": "evt-1",
            "timestamp": "2023-04-01T12:00:00Z",
            "source_ip": "192.168.1.10",
            "dest_ip": "10.0.0.5",
            "username": "user1",
            "event_type": "auth_success",
            "device_id": "device123"
        },
        {
            "id": "evt-2",
            "timestamp": "2023-04-01T12:05:00Z",
            "source_ip": "192.168.1.10",
            "dest_ip": "10.0.0.5",
            "username": "user1",
            "event_type": "file_read",
            "file_name": "/etc/passwd"
        }
    ]

    # 1. Test POST with a valid events array - expect 200 with full incident bundle keys
    payload_valid = {"events": valid_events}
    resp = requests.post(url, headers=HEADERS, json=payload_valid, timeout=TIMEOUT)
    assert resp.status_code == 200, f"Expected 200 for valid events but got {resp.status_code}"
    data = resp.json()
    # Validate presence of keys: overview, incident, graph, threat_intel, report, attackers, meta
    expected_keys = {"overview", "incident", "graph", "threat_intel", "report", "attackers", "meta"}
    assert expected_keys.issubset(data.keys()), "Response JSON missing expected keys for valid events"

    # 2. Test POST with valid events array and account scoping - expect 200 and scoped incident
    # Using a sample account identifier assumed valid
    account_id = "account123"
    payload_account = {"events": valid_events, "account": account_id}
    resp = requests.post(url, headers=HEADERS, json=payload_account, timeout=TIMEOUT)
    assert resp.status_code == 200, f"Expected 200 for valid events with account scoping but got {resp.status_code}"
    data = resp.json()
    # Incident and meta presence check
    assert "incident" in data and "meta" in data, "Response missing incident or meta for account scoped analysis"

    # 3. Test POST with empty events array -> expect 422 validation error
    payload_empty_events = {"events": []}
    resp = requests.post(url, headers=HEADERS, json=payload_empty_events, timeout=TIMEOUT)
    assert resp.status_code == 422, f"Expected 422 for empty events array but got {resp.status_code}"

    # 4. Test POST with oversized input (>50k rows) -> expect 422 validation error
    # Generate 50,001 mock events
    oversized_events = []
    base_event = {
        "id": "evt-x",
        "timestamp": "2023-04-01T12:00:00Z",
        "source_ip": "192.168.1.10",
        "dest_ip": "10.0.0.5",
        "username": "user1",
        "event_type": "login_attempt",
        "device_id": "device123"
    }
    # Create 50001 events changing id to keep unique
    for i in range(50001):
        event = base_event.copy()
        event["id"] = f"evt-{i}"
        oversized_events.append(event)
    payload_oversized = {"events": oversized_events}
    resp = requests.post(url, headers=HEADERS, json=payload_oversized, timeout=TIMEOUT)
    assert resp.status_code == 422, f"Expected 422 for oversized events but got {resp.status_code}"

    # 5. Test POST with unknown account identifier -> expect 422 validation error
    unknown_account = "unknown-account-999"
    payload_unknown_account = {"events": valid_events, "account": unknown_account}
    resp = requests.post(url, headers=HEADERS, json=payload_unknown_account, timeout=TIMEOUT)
    assert resp.status_code == 422, f"Expected 422 for unknown account but got {resp.status_code}"


test_analyze_raw_events()