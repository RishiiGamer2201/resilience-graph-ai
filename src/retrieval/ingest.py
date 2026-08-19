"""
RAG Corpus Builder — src/retrieval/ingest.py

Fetches, parses, and chunks cybersecurity knowledge from multiple live sources:
  1. MITRE ATT&CK v19.2  (Enterprise + ICS + Mobile — STIX 2.1 JSON)
  2. MITRE ATLAS v6.0     (AI/ML adversarial techniques — STIX JSON)
  3. CISA KEV catalog     (Known Exploited Vulnerabilities JSON feed)
  4. NVD CVE API 2.0      (Recent CVEs with descriptions)
  5. abuse.ch feeds       (MalwareBazaar recent, ThreatFox IOCs)
  6. RSS news             (THN, BleepingComputer, CISA advisories, ET CISO India)
  7. APT / actor profiles (from ATT&CK STIX groups)
  8. Malware family docs  (curated 2026 family descriptions)

Each document is split into consistent ~512-token chunks with rich metadata so
the vector store can filter by: source, technique_id, severity, actor, domain, date.

Usage:
    python -m src.retrieval.ingest               # full refresh
    python -m src.retrieval.ingest --sources attack cisa nvd   # selective
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

ROOT = Path(__file__).resolve().parents[2]  # src/retrieval/ingest.py -> project root
DATA_DIR = ROOT / "data" / "processed" / "rag_corpus"
RAW_ATTACK_DIR = ROOT / "data" / "raw" / "mitre_attack"

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger("ingest")

TIMEOUT = 25
UA = "nextATTACKs-RAG-Ingest/1.0 (hackathon research)"

# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Chunk:
    """A single document chunk ready for embedding."""
    text: str                          # raw text to embed
    source: str                        # e.g. "mitre_attack", "cisa_kev"
    doc_id: str                        # unique stable id (SHA-256 of text)
    title: str = ""
    url: str = ""
    date: str = ""                     # ISO date string
    technique_ids: list[str] = field(default_factory=list)  # ATT&CK IDs
    severity: str = ""                 # critical/high/medium/low
    actor: str = ""                    # APT group name if applicable
    domain: str = ""                   # enterprise/ics/mobile/atlas
    family: str = ""                   # malware family name
    chunk_index: int = 0
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _make_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:20]


def _chunk_text(text: str, max_chars: int = 1800, overlap: int = 200) -> list[str]:
    """Split long text into overlapping chunks on sentence boundaries.

    Termination is explicit. The previous version ended each pass with
    `start = end - overlap` and looped `while start < len(text)`: once `end`
    reached the end of the text, `start` settled at `len(text) - overlap`, which
    is still less than `len(text)`, so it appended the same tail chunk forever
    and died with MemoryError. Short documents (CISA KEV entries) never hit it;
    every MITRE ATT&CK technique longer than `max_chars` did, which is why the
    corpus contained zero ATT&CK chunks.

    Two guards now: break as soon as the tail is consumed, and never let `start`
    fail to advance.
    """
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        if end < len(text):
            # prefer a sentence boundary in the back half of the window
            boundary = text.rfind(". ", start + max_chars // 2, end)
            if boundary != -1:
                end = boundary + 1
        chunks.append(text[start:end].strip())
        if end >= len(text):
            break                       # tail consumed; nothing left to window
        start = max(end - overlap, start + 1)   # always make progress
    return [c for c in chunks if len(c) > 50]


# ──────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────────────────────

def _get(url: str, headers: dict | None = None, data: bytes | None = None,
         retries: int = 3, backoff: float = 2.0) -> bytes:
    """Fetch through the guarded fetcher, with retries.

    Every outbound request in this product goes through
    `src.shared.nethttp.fetch_url`: host allowlist, SSRF guard on the resolved
    address, redirects re-validated at each hop, size and time caps. This module
    originally called urllib directly, which bypassed all of it -- a corpus
    builder that will follow any URL is exactly the wrong thing to have in a
    security product. Adding a source now means adding its host to the allowlist
    on purpose, which is the point.
    """
    from src.shared.nethttp import BlockedURL, fetch_url

    for attempt in range(retries):
        try:
            return fetch_url(url, headers=headers, data=data, timeout=TIMEOUT,
                             max_bytes=64 * 1024 * 1024)   # ATT&CK bundles are ~40 MB
        except BlockedURL:
            raise                       # a policy refusal is not worth retrying
        except (urllib.error.URLError, OSError) as e:
            if attempt == retries - 1:
                raise
            log.warning("  retry %d/%d for %s: %s", attempt + 1, retries, url, e)
            time.sleep(backoff ** attempt)
    raise RuntimeError("unreachable")


def _get_json(url: str, headers: dict | None = None, data: bytes | None = None) -> dict:
    raw = _get(url, headers=headers, data=data)
    return json.loads(raw)


# ──────────────────────────────────────────────────────────────────────────────
# Source 1 — MITRE ATT&CK (Enterprise + ICS + Mobile)
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_BUNDLES = {
    "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "ics":        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
    "mobile":     "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
}


def _attack_local(domain: str) -> Path:
    """Try local copy first (from parse_attack pipeline), fall back to download."""
    local = RAW_ATTACK_DIR / f"{domain}-attack" / f"{domain}-attack.json"
    return local if local.exists() else None


# Max characters for description/detection text to prevent MemoryError on large STIX bundles
_MAX_DESC = 2000
_MAX_DETECT = 800


def _parse_attack_bundle(data: dict, domain: str) -> Generator[Chunk, None, None]:
    """Parse a STIX bundle and yield one chunk per technique."""
    objects = {o["id"]: o for o in data.get("objects", [])}

    # Build ext_id index for techniques first (used in relationship resolution)
    tech_ext_ids: dict[str, str] = {}  # stix_id -> ext_id
    for o in data.get("objects", []):
        if o.get("type") == "attack-pattern" and not o.get("revoked"):
            eid = _att_ext_id(o)
            if eid:
                tech_ext_ids[o["id"]] = eid

    # Index relationships (single pass)
    uses_by_group: dict[str, list[str]] = {}   # group stix_id -> [technique ext_id]
    mitigates: dict[str, list[str]] = {}        # technique ext_id -> [mitigation names]
    group_names: dict[str, str] = {}

    for o in data.get("objects", []):
        t = o.get("type", "")
        if t == "intrusion-set" and not o.get("revoked"):
            group_names[o["id"]] = o.get("name", "")
        elif t == "course-of-action" and not o.get("revoked"):
            pass  # collected below
        elif t == "relationship" and not o.get("revoked"):
            rt = o.get("relationship_type", "")
            src, tgt = o.get("source_ref", ""), o.get("target_ref", "")
            if rt == "uses" and tgt in tech_ext_ids:
                uses_by_group.setdefault(src, []).append(tech_ext_ids[tgt])
            elif rt == "mitigates" and tgt in tech_ext_ids:
                src_obj = objects.get(src, {})
                mitigates.setdefault(tech_ext_ids[tgt], []).append(
                    src_obj.get("name", "")
                )

    # Build group -> techniques map (already ext_ids)
    group_tech_map: dict[str, list[str]] = {
        gid: teids for gid, teids in uses_by_group.items() if gid in group_names
    }

    # Build technique -> using groups index (inverted)
    tech_to_groups: dict[str, list[str]] = {}
    for gid, teids in group_tech_map.items():
        gname = group_names[gid]
        for teid in teids:
            tech_to_groups.setdefault(teid, []).append(gname)

    for o in data.get("objects", []):
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext_id = _att_ext_id(o)
        if not ext_id:
            continue

        name = o.get("name", "")
        desc = (o.get("description") or "").replace("\n", " ").strip()[:_MAX_DESC]
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])]
        platforms = o.get("x_mitre_platforms", [])
        detection = (o.get("x_mitre_detection") or "").replace("\n", " ").strip()[:_MAX_DETECT]
        mits = mitigates.get(ext_id, [])[:8]
        using_groups = tech_to_groups.get(ext_id, [])[:10]

        full_text = (
            f"MITRE ATT&CK Technique: {ext_id} — {name}\n"
            f"Domain: {domain}  |  Tactics: {', '.join(tactics)}  |  Platforms: {', '.join(platforms)}\n\n"
            f"Description:\n{desc}\n\n"
            + (f"Detection:\n{detection}\n\n" if detection else "")
            + (f"Mitigations: {', '.join(mits[:6])}\n\n" if mits else "")
            + (f"Used by groups: {', '.join(using_groups[:8])}\n" if using_groups else "")
        )

        for idx, chunk_text in enumerate(_chunk_text(full_text)):
            yield Chunk(
                text=chunk_text,
                source="mitre_attack",
                doc_id=_make_id(f"attack_{ext_id}_{idx}"),
                title=f"{ext_id} — {name}",
                url=f"https://attack.mitre.org/techniques/{ext_id.replace('.', '/')}/",
                date="2026-08",
                technique_ids=[ext_id],
                domain=domain,
                chunk_index=idx,
                tags=tactics + [domain, "mitre-attack"],
            )


def _att_ext_id(o: dict) -> str | None:
    for ref in o.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"):
            return ref.get("external_id")
    return None


def _parse_attack_groups(data: dict, domain: str) -> Generator[Chunk, None, None]:
    """Yield one chunk per APT group with all known techniques."""
    # Build tech ext_id index in one pass
    technique_names: dict[str, str] = {}
    tech_stix_to_ext: dict[str, str] = {}
    for o in data.get("objects", []):
        if o.get("type") == "attack-pattern" and not o.get("revoked"):
            eid = _att_ext_id(o)
            if eid:
                technique_names[eid] = o.get("name", "")
                tech_stix_to_ext[o["id"]] = eid

    # Group uses (single pass)
    uses: dict[str, list[str]] = {}
    for o in data.get("objects", []):
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses":
            continue
        src = o.get("source_ref", "")
        tgt = o.get("target_ref", "")
        ext = tech_stix_to_ext.get(tgt)
        if ext:
            uses.setdefault(src, []).append(ext)

    for o in data.get("objects", []):
        if o.get("type") != "intrusion-set" or o.get("revoked"):
            continue
        name = o.get("name", "")
        aliases = o.get("aliases", [])
        desc = (o.get("description") or "").replace("\n", " ").strip()[:_MAX_DESC]
        ext_id = _att_ext_id(o)
        techs = uses.get(o["id"], [])
        tech_names_list = [f"{t} ({technique_names.get(t,'?')})" for t in techs[:20]]

        full_text = (
            f"APT Group / Threat Actor: {name}  [{ext_id}]\n"
            f"Aliases: {', '.join(aliases[:6])}\n"
            f"Domain: {domain}\n\n"
            f"Description:\n{desc}\n\n"
            f"Known Techniques ({len(techs)} total):\n{', '.join(tech_names_list)}\n"
        )

        for idx, chunk_text in enumerate(_chunk_text(full_text)):
            yield Chunk(
                text=chunk_text,
                source="mitre_attack_groups",
                doc_id=_make_id(f"group_{ext_id}_{idx}"),
                title=f"APT Group: {name}",
                url=f"https://attack.mitre.org/groups/{ext_id}/",
                date="2026-08",
                technique_ids=techs[:10],
                actor=name,
                domain=domain,
                chunk_index=idx,
                tags=["apt", "threat-actor", domain],
            )


def ingest_attack() -> list[Chunk]:
    """Fetch/load all three ATT&CK domains and return chunks."""
    chunks: list[Chunk] = []
    for domain, url in ATTACK_BUNDLES.items():
        log.info("ATT&CK [%s] loading...", domain)
        local = _attack_local(domain)
        if local:
            log.info("  using local copy: %s", local)
            data = json.loads(local.read_text(encoding="utf-8"))
        else:
            log.info("  downloading from GitHub...")
            data = _get_json(url)
        # cache locally for future runs
        cache_path = DATA_DIR / "cache" / f"attack_{domain}.json"
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        if not local:
            cache_path.write_text(json.dumps(data), encoding="utf-8")

        tech_chunks = list(_parse_attack_bundle(data, domain))
        group_chunks = list(_parse_attack_groups(data, domain))
        log.info("  -> %d technique chunks, %d group chunks", len(tech_chunks), len(group_chunks))
        chunks.extend(tech_chunks)
        chunks.extend(group_chunks)
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Source 2 — MITRE ATLAS (AI/ML adversarial techniques)
# ──────────────────────────────────────────────────────────────────────────────

# ATLAS distributes YAML via dist/ — the exact filename changes per release.
# Try the versioned dist directory structure; fall back to the STIX navigator export.
ATLAS_YAML_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS-latest.yaml"
ATLAS_STIX_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"


def _parse_atlas_yaml(raw_bytes: bytes) -> list[dict]:
    """Parse ATLAS YAML dist file and return a flat list of objects."""
    try:
        import yaml  # pyyaml is already a project dependency
        data = yaml.safe_load(raw_bytes)
    except Exception as e:
        raise ValueError(f"YAML parse failed: {e}")
    objects = []
    # ATLAS YAML structure: top-level list or dict with matrices/techniques/case-studies
    if isinstance(data, list):
        objects.extend(data)
    elif isinstance(data, dict):
        for key in ("techniques", "case-studies", "tactics", "objects"):
            if key in data:
                items = data[key]
                if isinstance(items, list):
                    objects.extend(items)
    return objects


def ingest_atlas() -> list[Chunk]:
    """Fetch MITRE ATLAS techniques and case studies."""
    log.info("ATLAS loading...")
    chunks: list[Chunk] = []

    # Try YAML dist first, then STIX navigator export
    all_objects: list[dict] = []
    for url, parser_name in [
        (ATLAS_YAML_URL, "yaml"),
        (ATLAS_STIX_URL, "stix"),
    ]:
        try:
            raw = _get(url)
            if parser_name == "yaml":
                all_objects = _parse_atlas_yaml(raw)
            else:
                data = json.loads(raw)
                all_objects = data.get("objects", [])
            log.info("  ATLAS loaded via %s (%d objects)", parser_name, len(all_objects))
            break
        except Exception as e:
            log.warning("  ATLAS %s failed: %s", url, e)

    if not all_objects:
        log.warning("  All ATLAS sources failed — using built-in stub")
        # Minimal stub so the corpus still has ATLAS coverage
        all_objects = [
            {"object-type": "technique", "id": "AML.T0000", "name": "ATLAS Unavailable",
             "description": "MITRE ATLAS v6.0 covers 16 tactics and 101 AI/ML adversarial techniques. See https://atlas.mitre.org/"},
        ]

    for obj in all_objects:
        obj_type = obj.get("type", "") or obj.get("object-type", "")
        name = obj.get("name", "")
        atlas_id = obj.get("id", "")
        desc = (obj.get("description") or "").replace("\n", " ").strip()

        if "technique" in obj_type.lower() or atlas_id.startswith("AML.T"):
            tactics = [p.get("phase-name", p) if isinstance(p, dict) else p
                       for p in obj.get("kill_chain_phases", obj.get("tactics", []))]
            full_text = (
                f"MITRE ATLAS AI/ML Adversarial Technique: {atlas_id} — {name}\n"
                f"Tactics: {', '.join(str(t) for t in tactics)}\n\n"
                f"Description:\n{desc}\n"
            )
            for idx, ct in enumerate(_chunk_text(full_text)):
                chunks.append(Chunk(
                    text=ct,
                    source="mitre_atlas",
                    doc_id=_make_id(f"atlas_{atlas_id}_{idx}"),
                    title=f"ATLAS {atlas_id} — {name}",
                    url=f"https://atlas.mitre.org/techniques/{atlas_id}/",
                    date="2026-07",
                    domain="atlas",
                    chunk_index=idx,
                    tags=["mitre-atlas", "ai-security", "ml-security"],
                ))

        elif "study" in obj_type.lower() or atlas_id.startswith("AML.CS"):
            full_text = (
                f"MITRE ATLAS Case Study: {atlas_id} — {name}\n\n"
                f"Description:\n{desc}\n"
            )
            for idx, ct in enumerate(_chunk_text(full_text)):
                chunks.append(Chunk(
                    text=ct,
                    source="mitre_atlas",
                    doc_id=_make_id(f"atlas_case_{atlas_id}_{idx}"),
                    title=f"ATLAS Case Study: {name}",
                    url=f"https://atlas.mitre.org/studies/{atlas_id}/",
                    date="2026-07",
                    domain="atlas",
                    chunk_index=idx,
                    tags=["mitre-atlas", "case-study", "ai-security"],
                ))

    log.info("  -> %d ATLAS chunks", len(chunks))
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Source 3 — CISA KEV (Known Exploited Vulnerabilities)
# ──────────────────────────────────────────────────────────────────────────────

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CVSS_SEVERITY = {
    "critical": ["log4shell", "proxylogon", "eternalblue", "zerologon", "spring4shell",
                 "log4j", "bluekeep", "heartbleed"],
}


def _kev_severity(v: dict) -> str:
    name_lower = (v.get("vulnerabilityName") or "").lower()
    desc_lower = (v.get("shortDescription") or "").lower()
    combined = name_lower + " " + desc_lower
    if any(k in combined for k in CVSS_SEVERITY["critical"]):
        return "critical"
    ransom = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
    return "high" if ransom else "medium"


def ingest_cisa_kev() -> list[Chunk]:
    log.info("CISA KEV loading...")
    chunks: list[Chunk] = []
    try:
        data = _get_json(KEV_URL)
    except Exception as e:
        log.warning("  KEV failed (%s)", e)
        return chunks

    vulns = sorted(data.get("vulnerabilities", []),
                   key=lambda v: v.get("dateAdded", ""), reverse=True)
    log.info("  %d vulnerabilities in KEV", len(vulns))

    for v in vulns:
        cve_id = v.get("cveID", "")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        vuln_name = v.get("vulnerabilityName", "")
        desc = v.get("shortDescription", "")
        action = v.get("requiredAction", "")
        date_added = v.get("dateAdded", "")
        due_date = v.get("dueDate", "")
        ransom = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"

        full_text = (
            f"CISA Known Exploited Vulnerability: {cve_id}\n"
            f"Vendor: {vendor}  |  Product: {product}\n"
            f"Vulnerability Name: {vuln_name}\n"
            f"Date Added to KEV: {date_added}  |  CISA Remediation Due: {due_date}\n"
            f"Ransomware Campaign Use: {'Yes' if ransom else 'No'}\n\n"
            f"Description: {desc}\n\n"
            f"Required Action: {action}\n"
            f"Reference: https://nvd.nist.gov/vuln/detail/{cve_id}\n"
        )

        tags = ["cve", "actively-exploited", "cisa-kev"]
        if ransom:
            tags.append("ransomware-linked")

        chunks.append(Chunk(
            text=full_text.strip(),
            source="cisa_kev",
            doc_id=_make_id(f"kev_{cve_id}"),
            title=f"{cve_id} — {vendor} {product}",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            date=date_added,
            severity=_kev_severity(v),
            tags=tags,
        ))

    log.info("  -> %d KEV chunks", len(chunks))
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Source 4 — NVD CVE API 2.0 (recent 2025-2026 CVEs)
# ──────────────────────────────────────────────────────────────────────────────

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# The NVD API rejects a date filter that names only a start, and it caps any
# single query at a 120-day span. Both rules were being broken, so every request
# came back 404 and this source produced nothing.
NVD_MAX_WINDOW_DAYS = 110          # inside the documented 120-day cap


def ingest_nvd(window_days: int = NVD_MAX_WINDOW_DAYS,
               max_results: int = 500) -> list[Chunk]:
    log.info("NVD CVE API loading (rolling %d-day windows)...", window_days)
    chunks: list[Chunk] = []
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}

    from datetime import timedelta

    def _stamp(dt: datetime) -> str:
        # NVD wants ISO-8601 with milliseconds and no timezone suffix
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    batch = 100
    fetched = 0
    window_end = datetime.now(timezone.utc).replace(tzinfo=None)
    windows_tried = 0

    while fetched < max_results and windows_tried < 4:
        window_start = window_end - timedelta(days=window_days)
        start_index = 0
        windows_tried += 1

        while fetched < max_results:
            params = (f"pubStartDate={_stamp(window_start)}"
                      f"&pubEndDate={_stamp(window_end)}"
                      f"&resultsPerPage={batch}&startIndex={start_index}")
            url = f"{NVD_API}?{params}"
            try:
                data = _get_json(url, headers=headers)
            except Exception as e:
                log.warning("  NVD batch failed at index %d: %s", start_index, e)
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                published = cve.get("published", "")[:10]
                descriptions = cve.get("descriptions", [])
                desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})

                # CVSS v3.1 or v3.0 score
                cvss_score = None
                severity = "medium"
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    mlist = metrics.get(key, [])
                    if mlist:
                        cvss_data = mlist[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "MEDIUM").lower()
                        break

                if not desc_en:
                    continue

                full_text = (
                    f"CVE: {cve_id}\n"
                    f"Published: {published}  |  CVSS Score: {cvss_score}  |  Severity: {severity.upper()}\n\n"
                    f"Description: {desc_en}\n"
                    f"Reference: https://nvd.nist.gov/vuln/detail/{cve_id}\n"
                )

                chunks.append(Chunk(
                    text=full_text.strip(),
                    source="nvd_cve",
                    doc_id=_make_id(f"nvd_{cve_id}"),
                    title=cve_id,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    date=published,
                    severity=severity,
                    tags=["cve", "nvd", severity],
                ))

            fetched += len(vulns)
            total_results = data.get("totalResults", 0)
            log.info("  fetched %d/%d NVD CVEs...", fetched, min(total_results, max_results))
            start_index += batch

            if fetched >= total_results or fetched >= max_results:
                break
            time.sleep(0.7 if api_key else 6.5)  # NVD rate limits

        # step back one window and keep going until max_results is satisfied
        window_end = window_start
        if fetched >= max_results:
            break
        time.sleep(0.7 if api_key else 6.5)

    log.info("  -> %d NVD CVE chunks", len(chunks))
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Source 5 — abuse.ch: MalwareBazaar + ThreatFox
# ──────────────────────────────────────────────────────────────────────────────

MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/json/recent/"
THREATFOX_URL     = "https://threatfox-api.abuse.ch/api/v1/"


def ingest_malwarebazaar() -> list[Chunk]:
    log.info("MalwareBazaar loading...")
    chunks: list[Chunk] = []
    try:
        data = _get_json(MALWAREBAZAAR_URL)
    except Exception as e:
        log.warning("  MalwareBazaar failed: %s", e)
        return chunks

    for sample in (data.get("data") or []):
        sha256 = sample.get("sha256_hash", "")
        sig = sample.get("signature") or sample.get("tags", ["unknown"])[0]
        file_type = sample.get("file_type", "")
        first_seen = sample.get("first_seen", "")[:10]
        tags = sample.get("tags") or []
        reporter = sample.get("reporter", "")

        full_text = (
            f"Malware Sample: {sig}\n"
            f"SHA256: {sha256}\n"
            f"File Type: {file_type}  |  First Seen: {first_seen}\n"
            f"Tags: {', '.join(tags)}\n"
            f"Reporter: {reporter}\n"
            f"Source: MalwareBazaar  |  Reference: https://bazaar.abuse.ch/sample/{sha256}/\n"
        )

        chunks.append(Chunk(
            text=full_text.strip(),
            source="malwarebazaar",
            doc_id=_make_id(f"mb_{sha256}"),
            title=f"Malware: {sig} ({file_type})",
            url=f"https://bazaar.abuse.ch/sample/{sha256}/",
            date=first_seen,
            family=sig,
            tags=["malware", "ioc"] + tags[:5],
        ))

    log.info("  -> %d MalwareBazaar chunks", len(chunks))
    return chunks


def ingest_threatfox() -> list[Chunk]:
    log.info("ThreatFox loading...")
    chunks: list[Chunk] = []
    auth_key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()

    try:
        body = json.dumps({"query": "get_iocs", "days": 7}).encode()
        headers = {"Content-Type": "application/json"}
        if auth_key:
            headers["Auth-Key"] = auth_key
        data = _get_json(THREATFOX_URL, headers=headers, data=body)
    except Exception as e:
        log.warning("  ThreatFox failed: %s", e)
        return chunks

    for ioc in (data.get("data") or [])[:200]:
        malware = ioc.get("malware_printable") or "Unknown"
        ioc_value = ioc.get("ioc", "")
        ioc_type = ioc.get("ioc_type", "")
        threat_type = ioc.get("threat_type", "")
        threat_desc = ioc.get("threat_type_desc", "")
        first_seen = (ioc.get("first_seen") or "")[:10]
        tags = list(ioc.get("tags") or [])

        full_text = (
            f"ThreatFox IOC: {ioc_value}\n"
            f"Malware Family: {malware}\n"
            f"IOC Type: {ioc_type}  |  Threat Type: {threat_type}\n"
            f"First Seen: {first_seen}\n"
            f"Description: {threat_desc}\n"
            f"Tags: {', '.join(tags)}\n"
            f"Reference: https://threatfox.abuse.ch/ioc/{ioc.get('id','')}/\n"
        )

        chunks.append(Chunk(
            text=full_text.strip(),
            source="threatfox",
            doc_id=_make_id(f"tfx_{ioc_value}"),
            title=f"IOC: {malware} — {ioc_type}",
            url=f"https://threatfox.abuse.ch/ioc/{ioc.get('id','')}/",
            date=first_seen,
            family=malware,
            tags=["ioc", "threatfox", ioc_type] + tags[:4],
        ))

    log.info("  -> %d ThreatFox chunks", len(chunks))
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Source 6 — RSS Feeds (THN, BleepingComputer, CISA advisories, ET CISO India)
# ──────────────────────────────────────────────────────────────────────────────

RSS_FEEDS = [
    ("The Hacker News",   "https://feeds.feedburner.com/TheHackersNews",             "global"),
    ("BleepingComputer",  "https://www.bleepingcomputer.com/feed/",                  "global"),
    ("CISA Advisories",   "https://www.cisa.gov/cybersecurity-advisories/all.xml",   "cisa"),
    ("ET CISO India",     "https://ciso.economictimes.indiatimes.com/rss/topstories", "india"),
    ("SecurityWeek",      "https://feeds.feedburner.com/securityweek",               "global"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/",                       "global"),
    ("Help Net Security",  "https://www.helpnetsecurity.com/feed/",                  "global"),
]


def _clean_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-z]+;", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _parse_rss(xml_bytes: bytes, source_name: str, category: str,
               limit: int = 30) -> list[Chunk]:
    head = xml_bytes[:300].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
        raise ValueError(f"{source_name}: returned HTML (soft 404)")
    chunks: list[Chunk] = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise ValueError(f"{source_name}: XML parse error: {e}")

    for item in root.iter("item"):
        title = _clean_html(item.findtext("title") or "")
        link  = (item.findtext("link") or "").strip()
        desc  = _clean_html(item.findtext("description") or "")[:1200]
        pub   = (item.findtext("pubDate") or "")[:30]
        try:
            from email.utils import parsedate_to_datetime
            date_str = parsedate_to_datetime(pub).strftime("%Y-%m-%d")
        except Exception:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if not title:
            continue

        full_text = (
            f"[{source_name}] {title}\n"
            f"Published: {date_str}  |  Source: {category.upper()}\n\n"
            f"{desc}\n\n"
            f"Read more: {link}\n"
        )

        tags = [category, "news", source_name.lower().replace(" ", "-")]

        for idx, ct in enumerate(_chunk_text(full_text, max_chars=1400)):
            chunks.append(Chunk(
                text=ct,
                source=f"rss_{category}",
                doc_id=_make_id(f"rss_{link}_{idx}"),
                title=title,
                url=link,
                date=date_str,
                domain=category,
                chunk_index=idx,
                tags=tags,
            ))
        if len(chunks) >= limit:
            break

    return chunks[:limit]


def ingest_rss() -> list[Chunk]:
    chunks: list[Chunk] = []
    for source_name, url, category in RSS_FEEDS:
        log.info("RSS [%s] loading...", source_name)
        try:
            raw = _get(url)
            feed_chunks = _parse_rss(raw, source_name, category)
            log.info("  -> %d chunks", len(feed_chunks))
            chunks.extend(feed_chunks)
        except Exception as e:
            log.warning("  %s failed: %s", source_name, e)
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Source 7 — Curated 2026 Malware Family Knowledge Base
# ──────────────────────────────────────────────────────────────────────────────

MALWARE_2026_KB = [
    {
        "family": "Medusa", "type": "Ransomware", "year": 2026,
        "targets": "Healthcare, Critical Infrastructure",
        "ttps": ["T1486", "T1490", "T1021", "T1078", "T1566"],
        "description": (
            "Medusa is a Ransomware-as-a-Service (RaaS) operation highly active in 2026, "
            "targeting healthcare organizations, critical infrastructure, and large enterprises. "
            "It uses double extortion: encrypting data and threatening to leak stolen files. "
            "Andariel (North Korea's Stonefly sub-group) has been linked to Medusa deployments "
            "against non-profit and healthcare entities. Initial access typically via phishing, "
            "VPN credential abuse (T1133), or exploitation of internet-facing applications (T1190). "
            "Defenders should isolate backups (T1490 mitigation), enforce MFA, and segment networks."
        ),
        "iocs": ["medusa-locker", ".medusa extension", "!!!READ_ME_MEDUSA!!!.txt"],
        "mitigations": ["Offline encrypted backups", "MFA on VPN", "EDR with behavioral detection",
                        "Network segmentation", "Patch management for T1190 vectors"],
    },
    {
        "family": "JadePuffer", "type": "AI-Automated Ransomware", "year": 2026,
        "targets": "Enterprise, Manufacturing",
        "ttps": ["T1486", "T1059", "T1055", "T1562"],
        "description": (
            "JadePuffer (July 2026) is the first publicly documented ransomware campaign using "
            "autonomous AI agents to orchestrate and accelerate the entire attack lifecycle — from "
            "reconnaissance to lateral movement to detonation. The AI component selects targets, "
            "writes custom exploit code, and adapts to defensive responses in near-real-time. "
            "This represents a paradigm shift: typical 'dwell time' compressed from days to hours. "
            "Defenders must move from signature-based detection to behavioral anomaly monitoring "
            "and assume AI-speed adversary operations."
        ),
        "iocs": ["jadepuffer", "ai-agent payload", "unusual automation patterns"],
        "mitigations": ["Behavioral EDR", "Network baselining", "Zero-trust segmentation",
                        "Rapid IR playbooks for AI-speed attacks"],
    },
    {
        "family": "LockBit", "type": "Ransomware (RaaS)", "year": 2026,
        "targets": "Enterprises globally, all sectors",
        "ttps": ["T1486", "T1490", "T1078", "T1133", "T1021.001"],
        "description": (
            "LockBit remains the most influential ransomware operation in 2026 despite repeated "
            "law enforcement takedowns, thanks to a resilient affiliate model. LockBit 3.0/4.0 "
            "includes anti-analysis features, a bug bounty program, and a data leak site. "
            "Common entry vectors: RDP brute force (T1110.001), VPN credential theft (T1133), "
            "phishing (T1566). After gaining access, affiliates use living-off-the-land tools "
            "before detonating the encryptor. LockBit specifically targets and destroys backups "
            "(T1490). Solution: offline backups, RDP behind VPN+MFA, behavioral EDR."
        ),
        "iocs": [".lockbit extension", "LockBit_Ransomware.hta", "LockBit-specific C2 domains"],
        "mitigations": ["Offline/immutable backups", "RDP behind MFA/VPN", "Network monitoring",
                        "Disable RDP where not needed"],
    },
    {
        "family": "Qilin", "type": "Ransomware", "year": 2026,
        "targets": "Healthcare, Education, Government",
        "ttps": ["T1486", "T1078", "T1555", "T1090"],
        "description": (
            "Qilin (formerly Agenda) is a Go-based cross-platform ransomware that gained "
            "significant traction in 2026 after many affiliates migrated from LockBit post-takedown. "
            "Notably, Qilin has been observed stealing Google Chrome credentials from infected "
            "endpoints (T1555.003) before encrypting — enabling secondary credential-based attacks. "
            "Qilin uses VMware ESXi-specific variants to maximize damage in virtualized environments. "
            "Recovery involves credential rotation across all accounts (assume AD compromise), "
            "VMware snapshot isolation, and forensic analysis of Chrome credential stores."
        ),
        "iocs": [".qilin extension", "README-RECOVER.txt", "Qilin ESXi variant"],
        "mitigations": ["Credential manager/vault", "Browser credential protection",
                        "ESXi hardening", "MFA everywhere"],
    },
    {
        "family": "Akira", "type": "Ransomware", "year": 2026,
        "targets": "Healthcare, SMB",
        "ttps": ["T1486", "T1190", "T1133", "T1078"],
        "description": (
            "Akira ransomware, active since 2023 and highly active through 2026, is known for "
            "targeting Cisco VPN vulnerabilities (especially when MFA is disabled) for initial "
            "access. The group primarily targets SMBs and healthcare. Akira operates a double "
            "extortion leak site and offers a 'decryption tester' to victims. "
            "Mitigation: patch Cisco ASA/FTD promptly (see CVE-2026-20349), enforce MFA on all "
            "VPN accounts, and segment healthcare OT networks from IT."
        ),
        "iocs": [".akira extension", "akira_readme.txt", "Cisco VPN auth logs"],
        "mitigations": ["Cisco VPN patching", "MFA on VPN (critical)", "Network segmentation",
                        "Offline backups"],
    },
    {
        "family": "Troy", "type": "Backdoor", "year": 2026,
        "targets": "Defense, Aerospace, Developers",
        "ttps": ["T1574.001", "T1055", "T1543", "T1068"],
        "description": (
            "Troy is a sophisticated backdoor deployed by the Lazarus Group (North Korea) in "
            "August 2026 campaigns exploiting CVE-2026-68820 (Windows AFD.sys zero-day privilege "
            "escalation). Troy uses DLL sideloading (T1574.001) and is accompanied by the "
            "FudModule rootkit for deep stealth. Primarily targets defense, aerospace, and "
            "developer organizations as part of Operation Dream Job (fake job offers). "
            "Detection: monitor for unusual DLL loads in signed application directories, "
            "kernel-level rootkit artifacts, and privilege escalation via AFD.sys."
        ),
        "iocs": ["CVE-2026-68820", "FudModule rootkit", "AFD.sys exploitation", "Troy backdoor"],
        "mitigations": ["Patch CVE-2026-68820 immediately", "EDR with kernel monitoring",
                        "Scrutinize job-offer-themed documents", "DLL load monitoring"],
    },
    {
        "family": "BeaverTail", "type": "Loader/Infostealer", "year": 2026,
        "targets": "Developers, Crypto industry",
        "ttps": ["T1204.002", "T1059.001", "T1555", "T1041"],
        "description": (
            "BeaverTail is a malicious npm package / trojanized PDF viewer used by Lazarus Group "
            "in 'Operation Dream Job' campaigns targeting developers and crypto firms. "
            "Victims receive fake job interviews and are asked to install a malicious coding "
            "assessment tool. BeaverTail steals browser credentials, cryptocurrency wallet keys, "
            "and downloads follow-on payloads (InvisibleFerret). "
            "Mitigation: verify npm packages before installing in job contexts, use isolated "
            "VMs for coding assessments, enable EDR on developer machines."
        ),
        "iocs": ["BeaverTail npm package", "malicious PDF viewer", "InvisibleFerret C2"],
        "mitigations": ["npm package verification", "Isolated VM for code tests",
                        "Developer endpoint EDR", "Crypto wallet hardware security"],
    },
    {
        "family": "Lumma", "type": "Infostealer", "year": 2026,
        "targets": "Enterprises, individuals",
        "ttps": ["T1555", "T1539", "T1056.001", "T1041"],
        "description": (
            "Lumma Stealer (LummaC2) is the dominant infostealer in 2026 RaaS marketplaces, "
            "capable of exfiltrating browser credentials, cryptocurrency wallets, email clients, "
            "FTP credentials, and 2FA backup codes. Distributed via phishing, malvertising, "
            "and trojanized software. Uses anti-analysis techniques including VM detection. "
            "Solution: use a password manager, hardware security keys for 2FA (phishing-resistant), "
            "and browser isolation for sensitive accounts."
        ),
        "iocs": ["Lumma", "LummaC2", "stealer log markets"],
        "mitigations": ["Hardware security keys (FIDO2)", "Browser isolation",
                        "Credential monitoring (HaveIBeenPwned)", "EDR with stealer signatures"],
    },
    {
        "family": "Shai-Hulud", "type": "Supply Chain Worm", "year": 2026,
        "targets": "CI/CD pipelines, Software developers",
        "ttps": ["T1195.001", "T1072", "T1053.005", "T1059"],
        "description": (
            "Shai-Hulud (ATT&CK S9008, August 2026 agile release) is a sophisticated supply "
            "chain worm that propagates through compromised CI/CD pipelines and software "
            "repositories. It modifies Git hooks and CI configuration to inject malicious "
            "payloads into build artifacts. CanisterWorm (S9042) is a related variant "
            "targeting containerized build environments. Mitigation: sign all build artifacts, "
            "use SLSA framework, audit CI/CD pipeline permissions, and monitor for unexpected "
            "Git hook modifications."
        ),
        "iocs": ["Shai-Hulud", "CanisterWorm", "CI/CD config modifications", "Git hook tampering"],
        "mitigations": ["SLSA build provenance", "Artifact signing (Sigstore)",
                        "CI/CD permission audit", "Git hook monitoring", "SBOM generation"],
    },
    {
        "family": "AsyncRAT", "type": "Remote Access Trojan", "year": 2026,
        "targets": "SMB, Healthcare, Government",
        "ttps": ["T1219", "T1055", "T1059.001", "T1027"],
        "description": (
            "AsyncRAT is an open-source Remote Access Trojan widely abused by threat actors in "
            "2026 RaaS operations as an initial access / persistence tool. Features include "
            "keylogging, screen capture, remote shell, and file management. "
            "Often delivered via phishing HTML attachments or malicious macros. "
            "AsyncRAT traffic can be detected by monitoring for anomalous outbound connections "
            "on non-standard ports and PowerShell execution from Office applications."
        ),
        "iocs": ["AsyncRAT", "async.exe", "non-standard port C2 beacon"],
        "mitigations": ["Email filtering", "Macro blocking in Office", "PowerShell constrained mode",
                        "Outbound traffic monitoring"],
    },
]


def ingest_malware_kb() -> list[Chunk]:
    """Ingest the curated 2026 malware family knowledge base."""
    log.info("Malware KB loading...")
    chunks: list[Chunk] = []
    for entry in MALWARE_2026_KB:
        family = entry["family"]
        full_text = (
            f"Malware Family: {family}\n"
            f"Type: {entry['type']}  |  Year Active: {entry['year']}\n"
            f"Primary Targets: {entry['targets']}\n"
            f"ATT&CK Techniques: {', '.join(entry['ttps'])}\n\n"
            f"Description:\n{entry['description']}\n\n"
            f"Known IOCs: {', '.join(entry.get('iocs', []))}\n\n"
            f"Mitigations:\n" + "\n".join(f"  - {m}" for m in entry.get("mitigations", [])) + "\n"
        )

        for idx, ct in enumerate(_chunk_text(full_text)):
            chunks.append(Chunk(
                text=ct,
                source="malware_kb",
                doc_id=_make_id(f"malkb_{family}_{idx}"),
                title=f"{family} ({entry['type']}) — 2026",
                url=f"https://malpedia.caad.fkie.fraunhofer.de/find?search={family}",
                date=f"{entry['year']}-01",
                technique_ids=entry["ttps"],
                family=family,
                severity="high",
                chunk_index=idx,
                tags=["malware", "ransomware" if "ransom" in entry["type"].lower() else "malware",
                      "2026", family.lower()],
            ))

    log.info("  -> %d malware KB chunks", len(chunks))
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Source 8 — India / CERT-In knowledge base
# ──────────────────────────────────────────────────────────────────────────────

INDIA_KB = [
    {
        "title": "CERT-In 2026: 12-Hour Patch Mandate",
        "date": "2026-03",
        "text": (
            "CERT-In (Indian Computer Emergency Response Team) issued a directive in 2026 "
            "requiring organizations to patch critical vulnerabilities within 12 hours of "
            "disclosure — a dramatic tightening from the previous 30-day standard. This was "
            "driven by AI-enabled attackers compressing time-to-exploit to under 5 days. "
            "Additionally, critical sector organizations must report incidents to CERT-In within "
            "6 hours of detection. CERT-In handled 29.44 lakh (2.94 million) incidents in 2025. "
            "Key advisory areas: Microsoft (M365), Apple products, Oracle, SAP, Atlassian. "
            "Organizations must implement Zero Trust, MFA, RBAC, and Privileged Access Management."
        ),
        "url": "https://www.cert-in.org.in/",
        "tags": ["india", "cert-in", "policy", "patch-management"],
    },
    {
        "title": "Tata Electronics Breach — Apple & Tesla Data (June 2026)",
        "date": "2026-06",
        "text": (
            "In June 2026, Tata Electronics suffered a significant cyberattack in which "
            "confidential files related to Apple and Tesla manufacturing processes were allegedly "
            "stolen. The company activated incident response protocols. This highlights supply "
            "chain risks for global OEM manufacturers in India and the targeting of India's "
            "growing technology manufacturing sector. Attackers likely used spear-phishing "
            "or vendor/partner compromise for initial access, followed by data exfiltration."
        ),
        "url": "https://www.csis.org/programs/strategic-technologies-program/significant-cyber-incidents",
        "tags": ["india", "breach", "supply-chain", "2026"],
    },
    {
        "title": "India Threat Landscape H1 2026 — Seqrite Report",
        "date": "2026-07",
        "text": (
            "Seqrite's H1 2026 India Threat Landscape report documented over 265 million malware "
            "detections in India in the first half of 2026. Peak ransomware activity was observed "
            "in March 2026. The most targeted sectors are: Education (highest), Government, "
            "Business Services. AI-driven threats including GenAI-powered phishing and deepfake "
            "social engineering are accelerating. Indian organizations face 265M+ malware hits "
            "per half-year, requiring proactive threat hunting rather than reactive incident response."
        ),
        "url": "https://www.seqrite.com/resources/",
        "tags": ["india", "threat-landscape", "2026", "statistics"],
    },
    {
        "title": "APT36 (Transparent Tribe) — India-Focused Pakistani Threat Actor",
        "date": "2026-01",
        "text": (
            "APT36, also known as Transparent Tribe, is a Pakistani state-sponsored threat actor "
            "that consistently targets Indian government, military, and education sectors. "
            "In 2026, APT36 continued campaigns using CrimsonRAT, ObliqueRAT, and Android malware "
            "(AhMyth). Common TTPs: spear-phishing with India-themed lures, fake job applications, "
            "malicious Office documents exploiting older vulnerabilities. Primary targets: "
            "Ministry of Defence, DRDO, ISRO, Indian educational institutions. "
            "Detection: monitor for CrimsonRAT C2 beaconing, unusual macro execution, "
            "and India-themed attachment delivery."
        ),
        "url": "https://attack.mitre.org/groups/G0134/",
        "tags": ["india", "apt36", "transparent-tribe", "apt", "pakistan"],
        "technique_ids": ["T1566.001", "T1059.001", "T1105", "T1219"],
    },
    {
        "title": "SideWinder (APT-C-17) — India/South Asia Targeting",
        "date": "2026-01",
        "text": (
            "SideWinder (also Rattlesnake or APT-C-17) is a threat actor attributed to India "
            "that targets Pakistan, China, and other South Asian governments and military "
            "organizations, but is also observed in domestic targeting. Uses sophisticated "
            "RTF exploits, LNK-based execution, and a custom .NET payload framework. "
            "In 2026, SideWinder expanded campaigns to include maritime and energy sector targets "
            "across South Asia, Middle East, and Africa. Delivers spear-phishing themed around "
            "official government documents, military updates, and regional news."
        ),
        "url": "https://attack.mitre.org/groups/G0121/",
        "tags": ["india", "sidewinder", "apt", "south-asia"],
        "technique_ids": ["T1566.001", "T1204.002", "T1059.005", "T1105"],
    },
    {
        "title": "NCIIPC 2026: Critical Infrastructure Protection Directives",
        "date": "2026-04",
        "text": (
            "India's National Critical Information Infrastructure Protection Centre (NCIIPC) "
            "issued updated protection directives in 2026 covering: Power sector (smart grids), "
            "Banking & Finance (SWIFT-connected systems), Telecom (5G infrastructure), "
            "Transportation (railways, aviation), Healthcare. Key requirements: logical separation "
            "of OT/SCADA from IT networks, mandatory incident reporting, penetration testing "
            "frequency increases, supply chain security assessments for critical vendors. "
            "NCIIPC works alongside CERT-In for coordinated national cyber defense."
        ),
        "url": "https://nciipc.gov.in/",
        "tags": ["india", "nciipc", "critical-infrastructure", "ot-security"],
    },
]


def ingest_india_kb() -> list[Chunk]:
    log.info("India KB loading...")
    chunks: list[Chunk] = []
    for entry in INDIA_KB:
        full_text = f"{entry['title']}\nDate: {entry['date']}\n\n{entry['text']}\n\nSource: {entry['url']}"
        for idx, ct in enumerate(_chunk_text(full_text)):
            chunks.append(Chunk(
                text=ct,
                source="india_kb",
                doc_id=_make_id(f"india_{entry['title']}_{idx}"),
                title=entry["title"],
                url=entry["url"],
                date=entry["date"],
                technique_ids=entry.get("technique_ids", []),
                domain="india",
                chunk_index=idx,
                tags=entry.get("tags", ["india"]),
            ))
    log.info("  -> %d India KB chunks", len(chunks))
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────────────────────────────────────

SOURCE_MAP = {
    "attack":      ingest_attack,
    "atlas":       ingest_atlas,
    "cisa":        ingest_cisa_kev,
    "nvd":         ingest_nvd,
    "malwarebazaar": ingest_malwarebazaar,
    "threatfox":   ingest_threatfox,
    "rss":         ingest_rss,
    "malware_kb":  ingest_malware_kb,
    "india":       ingest_india_kb,
}


def run_ingest(sources: list[str] | None = None) -> list[Chunk]:
    """Run all (or specified) ingest sources. Returns all chunks."""
    targets = sources or list(SOURCE_MAP.keys())
    all_chunks: list[Chunk] = []
    for name in targets:
        if name not in SOURCE_MAP:
            log.warning("Unknown source: %s (valid: %s)", name, list(SOURCE_MAP))
            continue
        try:
            chunks = SOURCE_MAP[name]()
            all_chunks.extend(chunks)
        except Exception as e:
            log.error("Source [%s] FAILED: %s", name, e, exc_info=True)
    log.info("Total chunks: %d", len(all_chunks))
    return all_chunks


def save_corpus(chunks: list[Chunk], out_dir: Path | None = None) -> Path:
    """Save chunks as JSONL to disk for embedding."""
    out_dir = out_dir or DATA_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "corpus.jsonl"
    with out_path.open("w", encoding="utf-8") as f:
        for c in chunks:
            f.write(json.dumps(c.to_dict(), ensure_ascii=False) + "\n")
    log.info("Saved %d chunks -> %s", len(chunks), out_path)
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest cybersecurity corpus for RAG")
    parser.add_argument("--sources", nargs="*", choices=list(SOURCE_MAP.keys()),
                        help="Sources to ingest (default: all)")
    parser.add_argument("--nvd-start", default="2025-01-01T00:00:00.000",
                        help="NVD CVE publish start date")
    parser.add_argument("--nvd-max", type=int, default=500,
                        help="Max NVD CVEs to fetch")
    args = parser.parse_args()

    # patch NVD params
    import functools
    SOURCE_MAP["nvd"] = functools.partial(ingest_nvd, pub_start=args.nvd_start,
                                          max_results=args.nvd_max)

    chunks = run_ingest(args.sources)
    out = save_corpus(chunks)

    # summary
    from collections import Counter
    by_source = Counter(c.source for c in chunks)
    print(f"\n{'='*50}")
    print(f"Corpus built: {len(chunks)} chunks -> {out}")
    print(f"{'='*50}")
    for src, count in sorted(by_source.items(), key=lambda x: -x[1]):
        print(f"  {src:<25s}: {count:>5d} chunks")


if __name__ == "__main__":
    main()
