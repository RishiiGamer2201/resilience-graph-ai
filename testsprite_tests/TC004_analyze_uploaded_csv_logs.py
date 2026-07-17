import requests
from io import BytesIO

BASE_URL = "http://localhost:8000"
TIMEOUT = 30


def test_analyze_uploaded_csv_logs():
    url = f"{BASE_URL}/api/analyze/upload"
    headers = {}

    # Valid CSV with ISO-8601 timestamps (removed 'account' column)
    csv_iso8601 = (
        "event_id,timestamp,event_type,source,destination\n"
        "1,2023-04-01T12:00:00Z,login,userA,server1\n"
        "2,2023-04-01T12:05:00Z,file_access,userB,server2\n"
    )
    # Valid CSV with epoch-integer timestamps (removed 'account' column)
    csv_epoch = (
        "event_id,timestamp,event_type,source,destination\n"
        "1,1680355200,login,userA,server1\n"
        "2,1680355500,file_access,userB,server2\n"
    )
    # Malformed CSV (missing timestamp column)
    csv_malformed = (
        "event_id,event_type,source,destination\n"
        "1,login,userA,server1\n"
        "2,file_access,userB,server2\n"
    )
    # Unsupported content type (sending a non-CSV content but declared as CSV)
    non_csv_content = "Just some plain text that's not CSV"

    def post_csv_data(csv_content):
        files = {
            "file": ("events.csv", BytesIO(csv_content.encode()), "text/csv")
        }
        try:
            resp = requests.post(url, headers=headers, files=files, timeout=TIMEOUT)
        except requests.RequestException as e:
            raise AssertionError(f"Request failed: {e}")
        return resp

    # Test valid ISO-8601 timestamp CSV
    resp = post_csv_data(csv_iso8601)
    assert resp.status_code == 200, f"Expected 200 for ISO-8601 CSV, got {resp.status_code}"
    json_resp = resp.json()
    assert isinstance(json_resp, dict), "Response JSON should be a dictionary for ISO-8601 CSV"

    # Test valid epoch-integer timestamp CSV
    resp = post_csv_data(csv_epoch)
    assert resp.status_code == 200, f"Expected 200 for epoch timestamp CSV, got {resp.status_code}"
    json_resp = resp.json()
    assert isinstance(json_resp, dict), "Response JSON should be a dictionary for epoch timestamp CSV"

    # Test malformed CSV (missing required columns) expecting 422
    resp = post_csv_data(csv_malformed)
    assert resp.status_code == 422, f"Expected 422 for malformed CSV, got {resp.status_code}"

    # Test unsupported content type but with CSV extension, expecting 422
    files = {
        "file": ("events.csv", BytesIO(non_csv_content.encode()), "text/csv")
    }
    try:
        resp = requests.post(url, headers=headers, files=files, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise AssertionError(f"Request failed: {e}")
    assert resp.status_code == 422, f"Expected 422 for unsupported CSV content, got {resp.status_code}" 


test_analyze_uploaded_csv_logs()
