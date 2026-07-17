import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30
HEADERS = {"Content-Type": "application/json"}

def test_score_single_event():
    url = f"{BASE_URL}/api/score-event"

    # Valid authentication event payload (example fields, as typical behavioral anomaly model input)
    valid_event = {
        "user": "alice",
        "timestamp": "2024-06-10T12:34:56Z",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "auth_type": "password",
        "success": True,
        "behavioral_features": {
            "login_count_24h": 5,
            "login_count_1h": 1,
            "avg_session_length": 3600,
            "failed_attempts": 0
        }
    }
    # Event missing required behavioral fields (remove "behavioral_features")
    invalid_event = {
        "user": "alice",
        "timestamp": "2024-06-10T12:34:56Z",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "auth_type": "password",
        "success": True
        # behavioral_features missing
    }

    # Test valid event: expect HTTP 200 with anomaly_score and severity in response
    try:
        response_valid = requests.post(url, json=valid_event, headers=HEADERS, timeout=TIMEOUT)
        assert response_valid.status_code == 200, f"Unexpected status code for valid event: {response_valid.status_code}"
        json_valid = response_valid.json()
        assert "anomaly_score" in json_valid, "Missing 'anomaly_score' in valid response"
        assert "severity" in json_valid, "Missing 'severity' in valid response"
        assert isinstance(json_valid["anomaly_score"], (int, float)), "'anomaly_score' is not numeric"
        assert isinstance(json_valid["severity"], str), "'severity' is not string"
    except (requests.RequestException, AssertionError) as e:
        raise AssertionError(f"Valid event test failed: {e}")

    # Test invalid event (missing behavioral fields): expect HTTP 422 validation error
    try:
        response_invalid = requests.post(url, json=invalid_event, headers=HEADERS, timeout=TIMEOUT)
        assert response_invalid.status_code == 422, f"Expected 422 for invalid event, got {response_invalid.status_code}"
    except (requests.RequestException, AssertionError) as e:
        raise AssertionError(f"Invalid event test failed: {e}")

test_score_single_event()