import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30
HEADERS = {"Content-Type": "application/json"}

def test_analyze_named_scenario():
    # 1) Get a valid scenario name from /api/scenarios
    try:
        resp_scenarios = requests.get(f"{BASE_URL}/api/scenarios", timeout=TIMEOUT)
        resp_scenarios.raise_for_status()
        scenarios = resp_scenarios.json()
        assert isinstance(scenarios, list) and len(scenarios) > 0, "No scenarios found"
        valid_scenario_name = scenarios[0].get("name")
        assert valid_scenario_name, "Scenario name missing in scenario entry"
    except Exception as e:
        assert False, f"Failed to get scenarios list: {str(e)}"

    # 2) Test POST /api/analyze with valid scenario name -> expect 200 and full incident bundle keys
    payload_valid = {"scenario": valid_scenario_name}
    try:
        resp_valid = requests.post(f"{BASE_URL}/api/analyze", json=payload_valid, headers=HEADERS, timeout=TIMEOUT)
        assert resp_valid.status_code == 200, f"Expected 200 but got {resp_valid.status_code}"
        data = resp_valid.json()
        expected_keys = {"overview", "incident", "graph", "threat_intel", "report", "attackers", "meta"}
        assert isinstance(data, dict), "Response JSON is not a dict"
        missing_keys = expected_keys - data.keys()
        assert not missing_keys, f"Missing keys in response: {missing_keys}"
    except Exception as e:
        assert False, f"Valid scenario analyze request failed: {str(e)}"

    # 3) Test POST /api/analyze with unknown scenario name -> expect 404
    payload_unknown = {"scenario": "unknown_scenario_test_XYZ"}
    try:
        resp_unknown = requests.post(f"{BASE_URL}/api/analyze", json=payload_unknown, headers=HEADERS, timeout=TIMEOUT)
        assert resp_unknown.status_code == 404, f"Expected 404 but got {resp_unknown.status_code}"
    except Exception as e:
        assert False, f"Unknown scenario analyze request failed: {str(e)}"

    # 4) Test POST /api/analyze with no scenario and no events -> expect 422 validation error
    payload_empty = {}
    try:
        resp_empty = requests.post(f"{BASE_URL}/api/analyze", json=payload_empty, headers=HEADERS, timeout=TIMEOUT)
        assert resp_empty.status_code == 422, f"Expected 422 but got {resp_empty.status_code}"
    except Exception as e:
        assert False, f"Empty payload analyze request failed: {str(e)}"


test_analyze_named_scenario()
