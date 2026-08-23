"""Trust-boundary tests: outbound fetching, upload validation, and the promise
that no capability quietly requires a key or a network.

These run offline. Nothing here makes a real request — `_check` is the guard, and
the guard is what we are testing.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import api.main as main
from api.main import app
from src.shared.nethttp import ALLOWED_HOSTS, BlockedURL, _check, allowed_hosts

HEADER = "timestamp,user,source_host,destination_host\n"
ROW = "1,u@d,A,B\n"


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def _csv(n_rows: int, pad: str = "") -> bytes:
    """n_rows of valid schema, optionally padded to make each row fat."""
    row = f"1,u@d,A{pad},B{pad}\n"
    return (HEADER + row * n_rows).encode()


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


# --------------------------------------------------------------------------- #
# upload size cap -- bytes, before anything parses                              #
# --------------------------------------------------------------------------- #
# `MAX_ROWS` is a row cap enforced inside live_analyze._prepare, which only runs
# after pandas has already materialised the whole file. It cannot save a
# container from a 2 GB CSV, because the OOM happens first. MAX_UPLOAD_BYTES is
# the cap that runs while the body is still arriving.
UPLOAD_ROUTES = ["/api/analyze/upload",
                 "/api/agents/analyze/upload",
                 "/api/agents/stream/upload"]


@pytest.mark.parametrize("route", UPLOAD_ROUTES)
def test_an_oversized_upload_is_refused_with_413(client, monkeypatch, route):
    """Every upload route, not just the one someone remembered to patch."""
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 4096)
    body = _csv(400, pad="x" * 40)
    assert len(body) > 4096
    r = client.post(route, files={"file": ("big.csv", body, "text/csv")})
    assert r.status_code == 413, r.text
    assert "exceeds" in r.json()["detail"]


def test_the_oversized_upload_never_reaches_the_parser(client, monkeypatch):
    """413 must happen while reading, not after `pd.read_csv` has eaten the file.

    A cap applied after parsing is not a cap; it is a post-mortem. So we make the
    parser fatal: if the request still returns 413, nothing parsed.
    """
    def _explode(*a, **k):
        raise AssertionError("pd.read_csv ran -- the body was parsed before the cap")

    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 4096)
    monkeypatch.setattr(main.pd, "read_csv", _explode)
    r = client.post("/api/analyze/upload",
                    files={"file": ("big.csv", _csv(400, pad="x" * 40), "text/csv")})
    assert r.status_code == 413, r.text


def test_the_cap_counts_bytes_not_rows(client, monkeypatch):
    """A few very wide rows must be refused; MAX_ROWS would have waved them through.

    This is the whole point of the second cap. 200 rows is nowhere near the
    50,000-row limit, so the row check has no opinion about this file -- but it is
    over the byte ceiling, and the byte ceiling is what protects the memory.
    """
    from src.shared.live_analyze import MAX_ROWS

    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 8192)
    body = _csv(200, pad="x" * 200)
    assert body.count(b"\n") - 1 < MAX_ROWS, "this test must stay under the row cap"
    assert len(body) > 8192
    r = client.post("/api/analyze/upload",
                    files={"file": ("wide.csv", body, "text/csv")})
    assert r.status_code == 413
    assert "too many events" not in r.json()["detail"], "wrong cap fired"


def test_the_row_cap_still_applies_below_the_byte_cap(client):
    """The two caps are complements, not substitutes -- a narrow file with too many
    rows fits comfortably under 64 MB and must still be refused, by the row cap."""
    from src.shared.live_analyze import MAX_ROWS

    body = _csv(MAX_ROWS + 1)
    assert len(body) < main.MAX_UPLOAD_BYTES
    r = client.post("/api/analyze/upload", files={"file": ("big.csv", body, "text/csv")})
    assert r.status_code == 422
    assert "too many events" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# authorisation on the live-analysis surface                                   #
# --------------------------------------------------------------------------- #
# These endpoints used to be completely open while eighteen endpoints on the
# finalist router were gated, so the same product enforced `analyze` on
# /api/investigate and handed the identical pipeline to anyone on /api/analyze.
ANALYZE_ROUTES = [
    ("post", "/api/analyze", {"json": {"scenario": "aiims_ransomware"}}),
    ("post", "/api/analyze/upload", {"files": {"file": ("x.csv", _csv(3), "text/csv")}}),
    ("get", "/api/analyze/stream", {"params": {"scenario": "aiims_ransomware", "delay": 0}}),
    ("post", "/api/agents/analyze", {"json": {"scenario": "aiims_ransomware"}}),
    ("post", "/api/agents/analyze/upload", {"files": {"file": ("x.csv", _csv(3), "text/csv")}}),
    ("get", "/api/agents/stream", {"params": {"scenario": "aiims_ransomware"}}),
    ("post", "/api/agents/stream/upload", {"files": {"file": ("x.csv", _csv(3), "text/csv")}}),
]


@pytest.mark.parametrize("method,path,kw", ANALYZE_ROUTES)
def test_a_role_without_analyze_is_refused(client, method, path, kw):
    """`viewer` holds `read`, not `analyze` (src/shared/rbac.PERMISSIONS)."""
    r = getattr(client, method)(path, headers={"X-Role": "viewer"}, **kw)
    assert r.status_code == 403, f"{path} let a viewer through: {r.status_code}"
    assert "analyze" in r.json()["detail"]


def test_the_refusal_names_the_roles_that_would_be_allowed(client):
    r = client.post("/api/analyze", json={"scenario": "aiims_ransomware"},
                    headers={"X-Role": "viewer"})
    detail = r.json()["detail"]
    assert "analyst" in detail and "responder" in detail and "admin" in detail


def test_a_role_holding_analyze_is_allowed(client):
    r = client.post("/api/analyze", headers={"X-Role": "analyst"}, json={
        "events": [{"timestamp": 1, "user": "u@d", "source_host": "A",
                    "destination_host": "B"}] * 3})
    assert r.status_code == 200, r.text


def test_configuring_tokens_closes_the_demo_default(client, monkeypatch):
    """The zero-config demo treats an undeclared caller as the demo operator, and
    that concession must vanish the moment real credentials are configured.

    In demo-headers mode the role is self-declared, so refusing an anonymous
    caller would deny nobody -- anyone can send `X-Role: admin`. But once
    NEXTATTACK_ROLE_TOKENS is set, resolve_principal refuses before any role
    defaulting can happen, and these endpoints are genuinely shut. That was not
    achievable at any setting before, because there was no check at all.
    """
    monkeypatch.setenv("NEXTATTACK_ROLE_TOKENS", "s3cret:analyst")
    body = {"scenario": "aiims_ransomware"}

    assert client.post("/api/analyze", json=body).status_code == 401
    assert client.post("/api/analyze", json=body,
                       headers={"X-Role": "admin"}).status_code == 401, \
        "a declared role must not substitute for a token"
    assert client.post("/api/analyze", json=body,
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/agents/stream", params={"scenario": "aiims_ransomware"}
                      ).status_code == 401


# --------------------------------------------------------------------------- #
# CORS                                                                         #
# --------------------------------------------------------------------------- #
def test_cors_does_not_default_to_a_wildcard(monkeypatch):
    """`allow_origins=["*"]` meant any page on the internet could make a browser
    drive this API. The single-container deploy is same-origin and never needed it."""
    monkeypatch.delenv("NEXTATTACK_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("NEXTATTACK_DEV", raising=False)
    origins = main._cors_origins()
    assert "*" not in origins
    assert all(o.startswith("http://localhost") or o.startswith("http://127.0.0.1")
               for o in origins), origins


def test_the_wired_middleware_refuses_an_unknown_origin(client):
    """Not just the helper -- the CORS middleware as actually installed on `app`."""
    r = client.get("/api/health", headers={"Origin": "https://evil.example.com"})
    assert r.headers.get("access-control-allow-origin") not in ("*", "https://evil.example.com")


def test_the_dev_origin_is_still_allowed(client):
    r = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_an_operator_can_name_their_own_origins(monkeypatch):
    monkeypatch.setenv("NEXTATTACK_CORS_ORIGINS",
                       "https://soc.example.org, https://war-room.example.org")
    assert main._cors_origins() == ["https://soc.example.org",
                                    "https://war-room.example.org"]


def test_the_wildcard_is_reachable_only_by_asking_for_it(monkeypatch):
    monkeypatch.delenv("NEXTATTACK_CORS_ORIGINS", raising=False)
    monkeypatch.setenv("NEXTATTACK_DEV", "1")
    assert main._cors_origins() == ["*"]


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
