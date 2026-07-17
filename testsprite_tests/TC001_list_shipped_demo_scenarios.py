import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_list_shipped_demo_scenarios():
    url = f"{BASE_URL}/api/scenarios"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"

    try:
        data = response.json()
    except ValueError:
        assert False, "Response content is not valid JSON"

    # If the response is a dict, try to extract the list of scenarios
    if isinstance(data, dict):
        # Attempt to find a list of scenarios in values
        scenarios = None
        for value in data.values():
            if isinstance(value, list):
                scenarios = value
                break
        assert scenarios is not None, "Response JSON dict does not contain a scenario list"
    elif isinstance(data, list):
        scenarios = data
    else:
        assert False, f"Expected list or dict in response JSON, got {type(data)}"

    assert isinstance(scenarios, list), f"Expected a list of scenarios, got {type(scenarios)}"

    # Validate each scenario has required fields: name, label, n_events
    for scenario in scenarios:
        assert isinstance(scenario, dict), f"Scenario item should be dict, got {type(scenario)}"
        assert "name" in scenario, "Scenario missing 'name' field"
        assert isinstance(scenario["name"], str), "'name' should be a string"
        assert "label" in scenario, "Scenario missing 'label' field"
        assert isinstance(scenario["label"], str), "'label' should be a string"
        assert "n_events" in scenario, "Scenario missing 'n_events' field"
        assert isinstance(scenario["n_events"], int), "'n_events' should be an integer"

        # Optional metadata fields check
        metadata_fields = ["critical_default", "description", "meta", "metadata"]
        has_metadata = any(field in scenario for field in metadata_fields)
        assert has_metadata, "Scenario missing scenario metadata for live analysis selection"

test_list_shipped_demo_scenarios()