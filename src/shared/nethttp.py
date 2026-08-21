"""Guarded outbound HTTP — the ONE place the product reaches the internet.

Every live fetch (Threat Radar feeds, evidence refresh) goes through `fetch_url`,
which enforces the trust boundary the rest of the code assumes:

  * host allowlist   — only first-party/official sources we chose on purpose
  * SSRF guard       — the host must not resolve to a loopback/private/link-local
                       address, checked again after every redirect
  * redirect control — redirects are re-validated, capped, and cannot leave the
                       allowlist (a 302 to 169.254.169.254 is the classic escape)
  * size + time caps — a slow or enormous response cannot hang or OOM the demo

Stdlib only (urllib + socket + ipaddress) so the deploy image gains no dependency.

    from src.shared.nethttp import fetch_url
    body = fetch_url("https://www.cisa.gov/...")          # bytes
"""
from __future__ import annotations

import ipaddress
import os
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse

TIMEOUT = 15
MAX_BYTES = 8 * 1024 * 1024        # 8 MB: the KEV catalogue is the biggest at ~2 MB
MAX_REDIRECTS = 3
UA = "nextATTACKs-ThreatRadar/1.0 (hackathon research; contact: repo owner)"

# Official / purpose-built sources only. Adding a host here is a deliberate,
# reviewable decision — see docs/security/threat-model.md.
ALLOWED_HOSTS: set[str] = {
    "www.cisa.gov",
    "nvd.nist.gov",
    "services.nvd.nist.gov",
    "attack.mitre.org",
    "raw.githubusercontent.com",          # mitre-attack/attack-stix-data
    "www.cert-in.org.in",
    "ciso.economictimes.indiatimes.com",
    "feeds.feedburner.com",
    "www.bleepingcomputer.com",
    "otx.alienvault.com",
    "threatfox-api.abuse.ch",
    # RAG corpus sources (src/retrieval/ingest.py), build-time only
    "bazaar.abuse.ch",
    "atlas.mitre.org",
    # Optional BYOK narrative wording (src/agents/summarizer.py). OFF unless
    # GEMINI_API_KEY is set. This is the ONLY host that receives incident-derived
    # content rather than sending us public reference data, which is why it is
    # called out here and in SECURITY.md.
    "generativelanguage.googleapis.com",
}


def allowed_hosts() -> set[str]:
    """Allowlist + any hosts an operator opted into via NEXTATTACK_EXTRA_HOSTS."""
    extra = os.environ.get("NEXTATTACK_EXTRA_HOSTS", "")
    return ALLOWED_HOSTS | {h.strip().lower() for h in extra.split(",") if h.strip()}


class BlockedURL(ValueError):
    """The URL is not permitted (scheme, host, or resolved address)."""


def _check(url: str) -> str:
    """Validate scheme + host + every resolved IP. Returns the hostname."""
    p = urlparse(url)
    if p.scheme not in ("https", "http"):
        raise BlockedURL(f"scheme not allowed: {p.scheme!r}")
    host = (p.hostname or "").lower()
    if host not in allowed_hosts():
        raise BlockedURL(f"host not on the allowlist: {host!r}")
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror as e:
        raise BlockedURL(f"cannot resolve {host!r}: {e}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            raise BlockedURL(f"{host!r} resolves to a non-public address {ip}")
    return host


class _GuardedRedirects(urllib.request.HTTPRedirectHandler):
    """Re-run the full URL check on every redirect target."""
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_GuardedRedirects())


def fetch_url(url: str, headers: dict | None = None, data: bytes | None = None,
              *, timeout: int = TIMEOUT, max_bytes: int = MAX_BYTES) -> bytes:
    """GET/POST an allowlisted URL and return at most `max_bytes` of body."""
    _check(url)
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": UA, **(headers or {})})
    with _opener.open(req, timeout=timeout) as r:
        body = r.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise BlockedURL(f"response exceeds {max_bytes} bytes: {url}")
    return body


def demo() -> None:
    """Self-check: the guard blocks what it must, offline, with no network call."""
    for bad in ("file:///etc/passwd", "http://127.0.0.1:8000/api/health",
                "https://evil.example.com/x", "http://localhost/x",
                "https://169.254.169.254/latest/meta-data/"):
        try:
            _check(bad)
        except BlockedURL:
            continue
        raise AssertionError(f"should have been blocked: {bad}")
    assert "www.cisa.gov" in allowed_hosts()
    print(f"nethttp ok: {len(allowed_hosts())} allowed hosts, 5 hostile URLs blocked")


if __name__ == "__main__":
    demo()
