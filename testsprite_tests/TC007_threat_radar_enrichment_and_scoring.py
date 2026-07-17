import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30
HEADERS = {"Content-Type": "application/json"}


def test_threat_radar_enrichment_and_scoring():
    # Step 1: GET /api/threat-radar, expect 200 with cached radar items and metadata
    get_url = f"{BASE_URL}/api/threat-radar"
    try:
        get_response = requests.get(get_url, timeout=TIMEOUT)
        assert get_response.status_code == 200, f"GET /api/threat-radar returned {get_response.status_code}"
        get_data = get_response.json()
        assert "items" in get_data and isinstance(get_data["items"], list), "Missing or invalid 'items' list"
        assert "meta" in get_data and isinstance(get_data["meta"], dict), "Missing or invalid 'meta' object"
    except Exception as e:
        raise AssertionError(f"Exception during GET /api/threat-radar: {e}")

    # To test POST /api/threat-radar with incident context and live refresh,
    # we need valid incident context (technique_ids, actors, edges).
    # Try to get it from the cached data if available, else create minimal valid context.
    incident_context = {}
    try:
        # Try to extract technique_ids, actors, edges from cached items or meta if they exist
        # If not present, use example plausible minimal payload.
        # We'll attempt best effort:
        technique_ids = []
        actors = []
        edges = []

        # Check items for technique_ids and actors
        if "items" in get_data and isinstance(get_data["items"], list) and len(get_data["items"]) > 0:
            sample_item = get_data["items"][0]
            # If sample_item has attributes holding techniques or actors, collect them
            # This is heuristic: there is no exact schema for items given
            if isinstance(sample_item, dict):
                # attempt to find technique_ids in items
                if "technique_ids" in sample_item and isinstance(sample_item["technique_ids"], list):
                    technique_ids = sample_item["technique_ids"]
                if "actors" in sample_item and isinstance(sample_item["actors"], list):
                    actors = sample_item["actors"]
                if "edges" in sample_item and isinstance(sample_item["edges"], list):
                    edges = sample_item["edges"]
        # If no valid data found, fallback to a minimal example payload
        if not technique_ids:
            technique_ids = ["T1003", "T1059"]  # example ATT&CK technique IDs
        if not actors:
            actors = ["APT28"]
        if not edges:
            edges = [{"source": "APT28", "target": "T1003"}]

        incident_context = {
            "technique_ids": technique_ids,
            "actors": actors,
            "edges": edges
        }
    except Exception:
        incident_context = {
            "technique_ids": ["T1003", "T1059"],
            "actors": ["APT28"],
            "edges": [{"source": "APT28", "target": "T1003"}]
        }

    post_url = f"{BASE_URL}/api/threat-radar"

    # Step 2: POST /api/threat-radar with incident context -> expect 200 with scored radar items
    try:
        post_response = requests.post(post_url, json=incident_context, headers=HEADERS, timeout=TIMEOUT)
        assert post_response.status_code == 200, f"POST /api/threat-radar with incident context returned {post_response.status_code}"
        post_data = post_response.json()
        assert "items" in post_data and isinstance(post_data["items"], list), "Missing or invalid 'items' list in scored response"
        assert "meta" in post_data and isinstance(post_data["meta"], dict), "Missing or invalid 'meta' in scored response"
    except Exception as e:
        raise AssertionError(f"Exception during POST /api/threat-radar with incident context: {e}")

    # Step 3: POST /api/threat-radar requesting live refresh -> expect 200 with refreshed or cached items
    try:
        context_with_refresh = incident_context.copy()
        context_with_refresh["refresh"] = True
        refresh_response = requests.post(post_url, json=context_with_refresh, headers=HEADERS, timeout=TIMEOUT)
        assert refresh_response.status_code == 200, f"POST /api/threat-radar with refresh returned {refresh_response.status_code}"
        refresh_data = refresh_response.json()
        assert "items" in refresh_data and isinstance(refresh_data["items"], list), "Missing or invalid 'items' list in refresh response"
        assert "meta" in refresh_data and isinstance(refresh_data["meta"], dict), "Missing or invalid 'meta' in refresh response"
        # meta.source can be 'cache' or 'live' per known limitations but no assertion required on it
    except Exception as e:
        raise AssertionError(f"Exception during POST /api/threat-radar with refresh: {e}")

    # Step 4: POST /api/threat-radar with insufficient incident context -> expect 422 validation error
    try:
        insufficient_context = {}  # empty payload
        invalid_response = requests.post(post_url, json=insufficient_context, headers=HEADERS, timeout=TIMEOUT)
        assert invalid_response.status_code == 422, f"POST /api/threat-radar with insufficient context returned {invalid_response.status_code}, expected 422"
    except Exception as e:
        raise AssertionError(f"Exception during POST /api/threat-radar with insufficient context: {e}")


test_threat_radar_enrichment_and_scoring()