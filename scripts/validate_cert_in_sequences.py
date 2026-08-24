"""Validate the provenance of analyst-verified CERT-In sequences.

Offline validation is deterministic and suitable for CI: advisory IDs must be
explicit, unique, agree with the URL, and cannot describe conflicting titles.
Verified entries must carry the title and content hash captured from the
official page during analyst review.

Use ``--online`` when reviewing or refreshing an entry. It fetches only the
allowlisted CERT-In URL through the repository's guarded HTTP client, extracts
the advisory body, and verifies both the official title and stored SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from src.shared.nethttp import fetch_url

ROOT = Path(__file__).resolve().parents[1]
SEQUENCES = ROOT / "data" / "manual" / "cert_in_sequences.json"
ID_PATTERN = re.compile(r"^CICA-\d{4}-\d{4}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._ignored = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style", "noscript"}:
            self._ignored += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._ignored:
            self._ignored -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored:
            self.parts.append(data)


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def extract_official_advisory(page: bytes) -> tuple[str, str]:
    parser = _Text()
    parser.feed(page.decode("utf-8", errors="replace"))
    text = normalize(" ".join(parser.parts))
    marker = "CURRENT ACTIVITIES "
    if marker not in text:
        raise ValueError("CERT-In page has no CURRENT ACTIVITIES advisory body")
    advisory = text.split(marker, 1)[1]
    if " Original Issue Date:" not in advisory:
        raise ValueError("CERT-In page has no advisory title/date boundary")
    title, remainder = advisory.split(" Original Issue Date:", 1)
    body = f"{normalize(title)} Original Issue Date: {remainder}"
    body = body.split(" Disclaimer ", 1)[0]
    return normalize(title), normalize(body)


def source_sha256(title: str, body: str) -> str:
    canonical = normalize(f"{title}\n{body}").encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _url_advisory_id(url: str) -> str | None:
    values = parse_qs(urlparse(url).query).get("CACODE", [])
    return values[0] if len(values) == 1 else None


def validate(entries: list[dict], *, online: bool = False,
             fetcher=fetch_url) -> list[dict]:
    errors: list[str] = []
    seen: dict[str, str] = {}
    checked: list[dict] = []
    for index, entry in enumerate(entries):
        label = f"entry {index}"
        advisory_id = str(entry.get("advisory_id", ""))
        title = normalize(str(entry.get("source_title", "")))
        url = str(entry.get("source_url", ""))
        if not ID_PATTERN.fullmatch(advisory_id):
            errors.append(f"{label}: invalid advisory_id {advisory_id!r}")
        if _url_advisory_id(url) != advisory_id:
            errors.append(f"{label}: source_url CACODE does not match {advisory_id!r}")
        previous = seen.get(advisory_id)
        if previous is not None:
            conflict = " with conflicting titles" if previous != title else ""
            errors.append(f"{label}: duplicate advisory_id {advisory_id!r}{conflict}")
        seen[advisory_id] = title

        if entry.get("verified"):
            if not title:
                errors.append(f"{label}: verified entry has no source_title")
            digest = str(entry.get("source_sha256", ""))
            if not SHA256_PATTERN.fullmatch(digest):
                errors.append(f"{label}: verified entry has no valid source_sha256")
            if not entry.get("verified_on"):
                errors.append(f"{label}: verified entry has no verified_on date")

        mapped = set(entry.get("ordered_technique_ids", []))
        evidence = entry.get("technique_evidence")
        if evidence is not None:
            evidenced = {row.get("technique_id") for row in evidence}
            if mapped != evidenced:
                errors.append(
                    f"{label}: technique_evidence must cover exactly the mapped IDs")

        result = {"advisory_id": advisory_id, "title": title, "url": url}
        if online and url:
            official_title, body = extract_official_advisory(fetcher(url))
            digest = source_sha256(official_title, body)
            result.update({"official_title": official_title, "source_sha256": digest})
            if normalize(official_title).casefold() != title.casefold():
                errors.append(
                    f"{label}: official title {official_title!r} != stored {title!r}")
            if entry.get("source_sha256") != digest:
                errors.append(
                    f"{label}: official content hash {digest} != stored hash")
        checked.append(result)

    if errors:
        raise ValueError("CERT-In sequence validation failed:\n- " + "\n- ".join(errors))
    return checked


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online", action="store_true",
                        help="fetch official CERT-In pages and verify titles/hashes")
    args = parser.parse_args()
    entries = json.loads(SEQUENCES.read_text(encoding="utf-8"))
    checked = validate(entries, online=args.online)
    mode = "online" if args.online else "offline"
    print(f"CERT-In sequences valid ({mode}): {len(checked)} unique advisories")
    if args.online:
        for row in checked:
            print(f"  {row['advisory_id']}  {row['source_sha256']}  {row['official_title']}")


if __name__ == "__main__":
    main()
