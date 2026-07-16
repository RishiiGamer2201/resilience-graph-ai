"""
Threat Radar — external OSINT/CTI intake.

Pulls from LEGITIMATE, free, purpose-built threat-intel sources (no social-media
scraping: it violates platform terms, is aggressively blocked, and person-level
attribution from posts would be irresponsible). Each item is mapped to real MITRE
ATT&CK techniques and can be cross-referenced against the current incident, so the
SOC sees "the outside world" in terms of its own attack chain.

Sources (all free):
  CISA KEV        no key   actively-exploited vulnerabilities (highest signal)
  CISA advisories no key   official advisory RSS
  The Hacker News no key   security news RSS
  BleepingComputer no key  security news RSS
  AlienVault OTX  free key optional (env OTX_API_KEY) — skipped if absent
  ThreatFox       free key optional (env ABUSECH_AUTH_KEY) — skipped if absent

Stdlib-only HTTP/XML (urllib + xml.etree) so the deploy image needs no new deps.
Every fetcher is isolated: one dead feed never breaks the radar.

    from src.shared.osint import collect
    radar = collect(limit=40)
"""
from __future__ import annotations

import json
import os
import pickle
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"

TIMEOUT = 15
UA = "ResilienceGraphAI-ThreatRadar/1.0 (hackathon research; contact: repo owner)"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RSS_FEEDS = [
    ("CISA advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
]
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Curated phrase -> technique aliases. Every ID is validated against the real
# ATT&CK lookups before use, so a typo here can never invent a technique.
ALIASES: dict[str, str] = {
    "ransomware": "T1486",
    "data encrypted for impact": "T1486",
    "phishing": "T1566",
    "spearphishing attachment": "T1566.001",
    "spearphishing link": "T1566.002",
    "credential dumping": "T1003",
    "pass the hash": "T1550.002",
    "pass-the-hash": "T1550.002",
    "valid accounts": "T1078",
    "powershell": "T1059.001",
    "command and scripting": "T1059",
    "exploit public-facing": "T1190",
    "public-facing application": "T1190",
    "remote code execution": "T1190",
    "supply chain": "T1195",
    "lateral movement": "T1021",
    "remote services": "T1021",
    "remote desktop": "T1021.001",
    "privilege escalation": "T1068",
    "exploitation for privilege escalation": "T1068",
    "data exfiltration": "T1041",
    "exfiltration over c2": "T1041",
    "command and control": "T1071",
    "web protocols": "T1071.001",
    "ingress tool transfer": "T1105",
    "scheduled task": "T1053",
    "brute force": "T1110",
    "password spraying": "T1110.003",
    "denial of service": "T1498",
    "inhibit system recovery": "T1490",
    "obfuscated files": "T1027",
    "masquerading": "T1036",
    "external remote services": "T1133",
    "vpn": "T1133",
    "sql injection": "T1190",
    "zero-day": "T1190",
    "improper privilege management": "T1068",
    "elevation of privilege": "T1068",
    "code injection": "T1055",
    "webshell": "T1505.003",
    "web shell": "T1505.003",
    # vulnerability phrasing common in KEV/advisories -> the exploit technique
    "cross-site scripting": "T1059.007",
    "command injection": "T1059",
    "server-side request forgery": "T1190",
    "ssrf": "T1190",
    "authentication bypass": "T1190",
    "path traversal": "T1190",
    "directory traversal": "T1190",
    "deserialization": "T1190",
    "file upload vulnerability": "T1190",
    "hard-coded credentials": "T1078",
    "buffer overflow": "T1203",
    "use-after-free": "T1203",
    "type confusion": "T1203",
    # malware/news phrasing
    "infostealer": "T1555",
    "information stealer": "T1555",
    "credential stealer": "T1555",
    "backdoor": "T1505",
    "wiper": "T1485",
    "data destruction": "T1485",
    "cryptojacking": "T1496",
    "cryptomining": "T1496",
    "resource hijacking": "T1496",
    "ddos": "T1498",
    "keylogger": "T1056.001",
    "dll sideloading": "T1574.001",     # this ATT&CK version folds side-loading into "DLL"
    "dll side-loading": "T1574.001",
    "living off the land": "T1218",
    "trojanized": "T1204.002",
    "malicious attachment": "T1566.001",
    "botnet": "T1584.005",
}

_state: dict = {}


# --------------------------------------------------------------------------- #
# lookups                                                                      #
# --------------------------------------------------------------------------- #
def _lookups() -> dict:
    if "lk" not in _state:
        with LOOKUPS.open("rb") as f:
            _state["lk"] = pickle.load(f)
    return _state["lk"]


def _valid_ids() -> set[str]:
    if "valid" not in _state:
        _state["valid"] = set(_lookups()["technique_to_name"])
    return _state["valid"]


def _name_index() -> list[tuple[str, str]]:
    """(lowercased technique name, id) for keyword matching, longest first.

    Precision over recall — a wrong technique on screen is worse than none:
      * Reconnaissance / resource-development techniques are excluded. Their names
        are generic English nouns ("Software", "Credentials", "Vulnerabilities",
        "Artificial Intelligence") that match ordinary prose and produced obvious
        false positives (an AI news piece -> "Obtain Capabilities: AI").
      * Only multi-word, reasonably long names are matched, for the same reason.
    Explicit T#### mentions and the curated ALIASES carry the high-confidence load.
    """
    if "names" not in _state:
        tac = _lookups().get("technique_to_tactics", {})
        skip = {"reconnaissance", "resource-development"}
        pairs = []
        for t, n in _lookups()["technique_to_name"].items():
            if skip & set(tac.get(t, [])):
                continue
            low = n.lower()
            if len(low) >= 12 and " " in low.strip():
                pairs.append((low, t))
        _state["names"] = sorted(pairs, key=lambda p: -len(p[0]))
    return _state["names"]


# --------------------------------------------------------------------------- #
# HTTP                                                                         #
# --------------------------------------------------------------------------- #
def _get(url: str, headers: dict | None = None, data: bytes | None = None) -> bytes:
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def _iso(dt: datetime | None) -> str:
    return (dt or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- #
# ATT&CK mapping                                                               #
# --------------------------------------------------------------------------- #
def map_item(text: str) -> list[str]:
    """Map free text to real ATT&CK technique IDs.

    1. explicit T#### mentions (feeds/pulses often tag them) — highest confidence
    2. exact technique-name matches, then curated aliases
    Every candidate is validated against attack_lookups (never invent an ID).
    """
    valid = _valid_ids()
    low = (text or "").lower()
    found: list[str] = []

    for tid in TECHNIQUE_RE.findall(text or ""):
        if tid in valid and tid not in found:
            found.append(tid)

    for name, tid in _name_index():
        if tid in found or tid not in valid:
            continue
        if re.search(r"\b" + re.escape(name) + r"\b", low):
            found.append(tid)

    for phrase, tid in ALIASES.items():
        if tid in found or tid not in valid:
            continue
        if re.search(r"\b" + re.escape(phrase) + r"\b", low):
            found.append(tid)

    return found[:6]


def technique_names(ids: list[str]) -> dict[str, str]:
    names = _lookups()["technique_to_name"]
    return {t: names.get(t, t) for t in ids}


# --------------------------------------------------------------------------- #
# relevance vs the current incident                                            #
# --------------------------------------------------------------------------- #
def tactics_of(ids: list[str]) -> set[str]:
    tac = _lookups().get("technique_to_tactics", {})
    return {t for i in ids for t in tac.get(i, [])}


def relevance(item: dict, incident_techniques: list[str] | None = None,
              actors: list[str] | None = None) -> dict:
    """Score an item against the incident we're investigating.

    Three transparent, separately-reported signals (same spirit as attribution —
    the analyst sees WHY, and a weak match is never dressed up as a strong one):
      * exact technique overlap  — strongest
      * same ATT&CK tactic       — weaker, but the realistic hit: news rarely names
                                   a sub-technique like T1550.002 while still being
                                   about lateral movement
      * attributed actor named in the item's text/tags — supporting evidence
    """
    inc = set(incident_techniques or [])
    item_tids = item.get("techniques", [])
    matched = [t for t in item_tids if t in inc]

    inc_tactics = tactics_of(sorted(inc)) if inc else set()
    item_tactics = tactics_of(item_tids)
    matched_tactics = sorted(inc_tactics & item_tactics) if inc_tactics else []

    text = f"{item.get('title','')} {item.get('text','')} {' '.join(item.get('tags', []))}".lower()
    matched_actors = [a for a in (actors or []) if a and a.lower() in text]

    score = 0.0
    if inc:
        score += 0.6 * (len(matched) / max(1, len(inc)))
    if inc_tactics:
        score += 0.2 * (len(matched_tactics) / max(1, len(inc_tactics)))
    score += 0.2 if matched_actors else 0.0
    return {"score": round(min(score, 1.0), 3),
            "matched_techniques": matched,
            "matched_tactics": matched_tactics,
            "matched_actors": matched_actors}


# --------------------------------------------------------------------------- #
# fetchers — each returns (items, status)                                      #
# --------------------------------------------------------------------------- #
def fetch_kev(limit: int = 15) -> list[dict]:
    raw = json.loads(_get(KEV_URL))
    # The catalog is ordered by vendor, NOT by date — sort explicitly so the radar
    # shows what CISA added most recently.
    vulns = sorted(raw.get("vulnerabilities", []),
                   key=lambda v: v.get("dateAdded", ""), reverse=True)[:limit]
    items = []
    for v in vulns:
        text = f"{v.get('vulnerabilityName','')}. {v.get('shortDescription','')}"
        ransom = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        items.append({
            "source": "CISA KEV",
            "title": f"{v.get('cveID')} — {v.get('vendorProject')} {v.get('product')}",
            "published": v.get("dateAdded", ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
            "text": text.strip(),
            # 'ransomware' is a CISA flag about campaign USE — shown as a tag, but
            # deliberately NOT fed to map_item: the vuln's technique is the exploit
            # itself, not Data Encrypted for Impact.
            "tags": ["actively-exploited"] + (["ransomware-linked"] if ransom else []),
            "iocs": [v.get("cveID", "")],
            "techniques": map_item(text),
        })
    return items


def _parse_rss(xml_bytes: bytes, source: str, limit: int) -> list[dict]:
    root = ET.fromstring(xml_bytes)
    out = []
    for it in root.iter("item"):
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        desc = re.sub(r"<[^>]+>", " ", it.findtext("description") or "")
        desc = re.sub(r"\s+", " ", desc).strip()[:600]
        pub = it.findtext("pubDate") or ""
        try:
            published = _iso(parsedate_to_datetime(pub))
        except Exception:
            published = _iso(None)
        blob = f"{title}. {desc}"
        out.append({
            "source": source, "title": title, "published": published, "url": link,
            "text": desc, "tags": [], "iocs": [],
            "techniques": map_item(blob),
        })
        if len(out) >= limit:
            break
    return out


def fetch_rss(source: str, url: str, limit: int = 10) -> list[dict]:
    return _parse_rss(_get(url), source, limit)


def fetch_otx(limit: int = 15) -> list[dict]:
    """AlienVault OTX subscribed pulses. Needs a FREE key in OTX_API_KEY."""
    key = os.environ.get("OTX_API_KEY", "").strip()
    if not key:
        raise RuntimeError("no OTX_API_KEY set")
    raw = json.loads(_get(OTX_URL, headers={"X-OTX-API-KEY": key}))
    items = []
    for p in raw.get("results", [])[:limit]:
        text = (p.get("description") or "")[:600]
        tags = list(p.get("tags") or [])
        adversary = p.get("adversary") or ""
        if adversary:
            tags.append(adversary)
        blob = f"{p.get('name','')}. {text} {' '.join(tags)}"
        tids = [t for t in (p.get("attack_ids") or []) if t in _valid_ids()]
        items.append({
            "source": "AlienVault OTX",
            "title": p.get("name", "(untitled pulse)"),
            "published": (p.get("modified") or p.get("created") or "")[:10],
            "url": f"https://otx.alienvault.com/pulse/{p.get('id','')}",
            "text": text, "tags": tags,
            "iocs": [i.get("indicator", "") for i in (p.get("indicators") or [])[:5]],
            "techniques": tids or map_item(blob),
        })
    return items


def fetch_threatfox(limit: int = 15) -> list[dict]:
    """abuse.ch ThreatFox IOCs. Needs a FREE key in ABUSECH_AUTH_KEY (they now
    require an account; without it the API returns 401)."""
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        raise RuntimeError("no ABUSECH_AUTH_KEY set")
    body = json.dumps({"query": "get_iocs", "days": 2}).encode()
    raw = json.loads(_get(THREATFOX_URL, headers={"Content-Type": "application/json",
                                                  "Auth-Key": key}, data=body))
    items = []
    for d in (raw.get("data") or [])[:limit]:
        malware = d.get("malware_printable") or "unknown malware"
        text = f"{malware} indicator ({d.get('ioc_type','')}) — {d.get('threat_type_desc','')}"
        items.append({
            "source": "ThreatFox",
            "title": f"{malware}: {d.get('ioc','')[:60]}",
            "published": (d.get("first_seen") or "")[:10],
            "url": f"https://threatfox.abuse.ch/ioc/{d.get('id','')}/",
            "text": text, "tags": list(d.get("tags") or []) + [malware],
            "iocs": [d.get("ioc", "")],
            "techniques": map_item(text),
        })
    return items


# --------------------------------------------------------------------------- #
# collect                                                                      #
# --------------------------------------------------------------------------- #
def collect(limit: int = 40) -> dict:
    """Fetch every source, map to ATT&CK, return the radar payload.

    Sources that fail or lack an optional free key are reported in `sources`
    rather than breaking the radar.
    """
    items: list[dict] = []
    status: list[dict] = []

    def run(name: str, fn):
        try:
            got = fn()
            items.extend(got)
            status.append({"source": name, "ok": True, "items": len(got)})
        except Exception as e:                       # one dead feed != dead radar
            status.append({"source": name, "ok": False, "items": 0,
                           "note": str(e)[:120]})

    run("CISA KEV", fetch_kev)
    for src, url in RSS_FEEDS:
        run(src, lambda s=src, u=url: fetch_rss(s, u))
    run("AlienVault OTX", fetch_otx)
    run("ThreatFox", fetch_threatfox)

    items.sort(key=lambda i: i.get("published", ""), reverse=True)
    items = items[:limit]
    names = technique_names(sorted({t for i in items for t in i["techniques"]}))

    return {
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "items": items,
        "technique_names": names,
        "sources": status,
        "note": "Free, purpose-built CTI sources only (CISA KEV/advisories, security "
                "news RSS, optional OTX/ThreatFox with free keys). No social-media "
                "scraping. Intel is enrichment — alerts are simulated and human-gated.",
    }


if __name__ == "__main__":
    r = collect()
    print(json.dumps(r["sources"], indent=2))
    print(f"{len(r['items'])} items, {len(r['technique_names'])} techniques mapped")
    for i in r["items"][:5]:
        print(f"  [{i['source']}] {i['published']} {i['title'][:60]} -> {i['techniques']}")
