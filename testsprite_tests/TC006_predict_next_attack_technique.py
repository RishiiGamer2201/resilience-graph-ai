import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_predict_next_attack_technique():
    url = f"{BASE_URL}/api/predict-next"
    headers = {"Content-Type": "application/json"}

    # Test case 1: Valid partial ATT&CK technique chain (example technique_ids and k)
    valid_payload = {
        "technique_ids": ["T1003", "T1059"],  # example MITRE ATT&CK technique IDs
        "k": 3
    }
    try:
        response = requests.post(url, json=valid_payload, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        resp_json = response.json()
        # Validate that response includes predicted next techniques and ranking
        assert "predictions" in resp_json, "Missing 'predictions' in response"
        assert isinstance(resp_json["predictions"], list), "'predictions' should be a list"
        assert len(resp_json["predictions"]) <= valid_payload["k"], "Number of predictions exceeds k"
        for pred in resp_json["predictions"]:
            assert "technique_id" in pred and isinstance(pred["technique_id"], str), "Each prediction must have 'technique_id' string"
            assert "score" in pred, "Each prediction must have 'score'"
            score = pred["score"]
            # Allow score to be int, float, or string that can convert to float
            if isinstance(score, (float, int)):
                pass
            elif isinstance(score, str):
                try:
                    float(score)
                except ValueError:
                    assert False, "Each prediction 'score' must be numeric or numeric string"
            else:
                assert False, "Each prediction 'score' must be numeric or numeric string"
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

    # Test case 2: Empty chain payload -> expect 422 validation error
    empty_payload = {
        "technique_ids": [],
        "k": 3
    }
    try:
        response = requests.post(url, json=empty_payload, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 422, f"Expected 422 for empty technique_ids, got {response.status_code}"
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

    # Test case 3: Invalid payload (missing technique_ids key)
    invalid_payload = {
        "k": 3
    }
    try:
        response = requests.post(url, json=invalid_payload, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 422, f"Expected 422 for missing technique_ids, got {response.status_code}"
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

test_predict_next_attack_technique()
