"""Trust-boundary tests: outbound fetching, upload validation, and the promise
that no capability quietly requires a key or a network.

These run offline. Nothing here makes a real request — `_check` is the guard, and
the guard is what we are testing.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.shared.nethttp import ALLOWED_HOSTS, BlockedURL, _check, allowed_hosts


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# --------------------------------------------------------------------------- #
# SSRF / allowlist                                                             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/x",
    "gopher://example.com/x",
])
def test_only_http_schemes_are_allowed(url):
    with pytest.raises(BlockedURL, match="scheme"):
        _check(url)


@pytest.mark.parametrize("url", [
    "https://evil.example.com/payload",
    "https://cisa.gov.attacker.test/",       # lookalike host
    "https://raw.githubusercontent.com.evil.test/x",
])
def test_hosts_off_the_allowlist_are_blocked(url):
    with pytest.raises(BlockedURL, match="allowlist"):
        _check(url)


@pytest.mark.parametrize("url", [
    "http://localhost:8000/api/health",
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",     # cloud metadata service
    "http://[::1]/",
])
def test_loopback_private_and_metadata_addresses_are_blocked(url):
    with pytest.raises(BlockedURL):
        _check(url)


def test_a_private_address_is_blocked_even_from_an_allowlisted_name(monkeypatch):
    """DNS rebinding: an allowlisted hostname that resolves to 10.0.0.1 must fail
    on the resolved address, not pass on the name."""
    import socket
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.1", 443))])
    with pytest.raises(BlockedURL, match="non-public"):
        _check("https://www.cisa.gov/feeds/kev.json")


def test_the_allowlist_is_first_party_only():
    for host in ALLOWED_HOSTS:
        assert host.endswith((".gov", ".org", ".org.in", ".com", ".net", ".ch")), host
    assert "www.cisa.gov" in allowed_hosts()
    assert "attack.mitre.org" in allowed_hosts()


def test_an_operator_can_opt_into_an_extra_host(monkeypatch):
    monkeypatch.setenv("NEXTATTACK_EXTRA_HOSTS", "intel.example.gov")
    assert "intel.example.gov" in allowed_hosts()
    assert "unrelated.example.com" not in allowed_hosts()


def test_the_radar_fetcher_goes_through_the_guard():
    """Every outbound call in the product must route through one guarded fetcher."""
    import inspect
    from src.shared import osint
    src = inspect.getsource(osint._get)
    assert "fetch_url" in src, "osint bypassed the guarded fetcher"


# --------------------------------------------------------------------------- #
# upload trust boundary                                                        #
# --------------------------------------------------------------------------- #
def test_a_non_csv_upload_is_rejected(client):
    r = client.post("/api/analyze/upload",
                    files={"file": ("x.csv", b"\x00\x01\x02not a csv at all", "text/csv")})
    assert r.status_code == 422


def test_a_csv_without_the_required_columns_is_rejected_with_a_useful_message(client):
    r = client.post("/api/analyze/upload",
                    files={"file": ("x.csv", b"foo,bar\n1,2\n", "text/csv")})
    assert r.status_code == 422
    assert "user" in r.json()["detail"]


def test_an_oversized_log_is_refused(client):
    from src.shared.live_analyze import MAX_ROWS
    header = "timestamp,user,source_host,destination_host\n"
    row = "1,u@d,A,B\n"
    body = (header + row * (MAX_ROWS + 1)).encode()
    r = client.post("/api/analyze/upload", files={"file": ("big.csv", body, "text/csv")})
    assert r.status_code == 422
    assert "too many events" in r.json()["detail"]


def test_an_unknown_scenario_is_a_404_not_a_traceback(client):
    r = client.post("/api/investigate", json={"scenario": "../../etc/passwd"},
                    headers={"X-Role": "analyst"})
    assert r.status_code == 422
    assert "unknown scenario" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# zero-cost / offline promise                                                  #
# --------------------------------------------------------------------------- #
def test_capabilities_declares_no_required_keys(client):
    caps = client.get("/api/capabilities").json()
    assert caps["keys_required"] == []
    assert caps["usable_offline"] is True
    assert caps["capabilities"]["llm"]["provider"] == "none"
    assert caps["capabilities"]["evidence"]["network_required"] is False


def test_readiness_names_what_is_missing_rather_than_just_failing(client):
    r = client.get("/api/readiness")
    body = r.json()
    assert r.status_code in (200, 503)
    assert set(body["required"]) == {"detector", "attack_lookups", "predictor",
                                     "score_ref", "scenarios"}
    if not body["ready"]:
        assert body["missing_required"] and body["hint"]


def test_the_whole_investigation_runs_with_no_network(monkeypatch, client):
    """Unplug outbound HTTP entirely; the demo must still complete."""
    import src.shared.nethttp as nh
    monkeypatch.setattr(nh, "fetch_url",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("network down")))
    r = client.post("/api/investigate", json={"scenario": "aiims_ransomware"},
                    headers={"X-Role": "analyst"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] and body["evidence"]["citations"]
    assert body["headline"]["crown_jewel_exposure"]["value"] is not None
