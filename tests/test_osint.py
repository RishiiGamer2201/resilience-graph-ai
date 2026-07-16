"""
Self-checks for the Threat Radar OSINT layer. No network — fixtures only.

Locks in the mapping-precision rules and the two real bugs found while building:
KEV date ordering, and the ransomware flag leaking into technique mapping.

    ./.venv/Scripts/python.exe -m pytest tests/test_osint.py -q
"""
import json
from unittest.mock import patch

from src.shared import osint

KEV_FIXTURE = json.dumps({
    "vulnerabilities": [
        {"cveID": "CVE-2020-0001", "vendorProject": "Zyxel", "product": "Firewall",
         "vulnerabilityName": "Zyxel Hard-Coded Credentials Vulnerability",
         "shortDescription": "Uses hard-coded credentials.", "dateAdded": "2020-01-01",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2026-9999", "vendorProject": "Acme", "product": "Portal",
         "vulnerabilityName": "Acme Portal Authentication Bypass Vulnerability",
         "shortDescription": "Allows remote code execution.", "dateAdded": "2026-07-15",
         "knownRansomwareCampaignUse": "Known"},
    ]
}).encode()

RSS_FIXTURE = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>New ransomware encrypts victim networks</title>
<link>https://example.com/a</link><pubDate>Wed, 15 Jul 2026 10:00:00 +0000</pubDate>
<description>&lt;p&gt;A ransomware crew deployed a wiper too.&lt;/p&gt;</description></item>
<item><title>AI can find bugs, researchers say</title>
<link>https://example.com/b</link><pubDate>Wed, 15 Jul 2026 09:00:00 +0000</pubDate>
<description>Artificial intelligence and software vulnerabilities research.</description></item>
</channel></rss>"""


# --- mapping ---------------------------------------------------------------
def test_explicit_technique_ids_extracted():
    assert "T1550.002" in osint.map_item("Actor used T1550.002 to move laterally")


def test_invented_ids_rejected():
    # T9999 is not a real technique — must never surface (standing honesty rule)
    assert "T9999" not in osint.map_item("Mitigation for T9999 released")


def test_aliases_all_map_to_real_techniques():
    valid = osint._valid_ids()
    bad = {p: t for p, t in osint.ALIASES.items() if t not in valid}
    assert not bad, f"alias IDs missing from ATT&CK lookups: {bad}"


def test_alias_match():
    assert "T1486" in osint.map_item("A new ransomware family encrypts files")
    assert "T1550.002" in osint.map_item("They used pass-the-hash against the domain")


def test_generic_recon_names_do_not_false_positive():
    """Regression: 'artificial intelligence'/'vulnerabilities' are ATT&CK recon /
    resource-development technique NAMES; ordinary prose must not map to them."""
    got = osint.map_item("Artificial intelligence research finds software vulnerabilities")
    assert "T1588.007" not in got and "T1588.006" not in got and "T1592.002" not in got


# --- KEV -------------------------------------------------------------------
def test_kev_sorted_by_date_desc():
    """Regression: the catalog is vendor-ordered, not date-ordered."""
    with patch.object(osint, "_get", return_value=KEV_FIXTURE):
        items = osint.fetch_kev(limit=5)
    assert items[0]["published"] == "2026-07-15", "newest KEV entry must come first"


def test_kev_ransomware_flag_is_a_tag_not_a_technique():
    """Regression: knownRansomwareCampaignUse describes campaign USE of the vuln.
    It must not make an auth-bypass CVE map to T1486 (Data Encrypted for Impact)."""
    with patch.object(osint, "_get", return_value=KEV_FIXTURE):
        items = osint.fetch_kev(limit=5)
    ransom_item = next(i for i in items if i["title"].startswith("CVE-2026-9999"))
    assert "ransomware-linked" in ransom_item["tags"]
    assert "T1486" not in ransom_item["techniques"]


# --- RSS -------------------------------------------------------------------
def test_rss_parsing_and_mapping():
    with patch.object(osint, "_get", return_value=RSS_FIXTURE):
        items = osint.fetch_rss("Test Feed", "http://x")
    assert len(items) == 2
    assert items[0]["published"] == "2026-07-15 10:00 UTC"   # RSS carries a time
    assert items[0]["url"] == "https://example.com/a"
    assert "<p>" not in items[0]["text"]              # HTML stripped
    assert "T1486" in items[0]["techniques"]
    assert items[1]["techniques"] == []               # AI story maps to nothing


# --- relevance -------------------------------------------------------------
def test_relevance_technique_tactic_actor():
    item = {"title": "Actor uses pass the hash", "text": "lateral movement seen",
            "tags": ["Ember Bear"], "techniques": ["T1550.002"]}
    r = osint.relevance(item, ["T1550.002", "T1110"], ["Ember Bear"])
    assert r["matched_techniques"] == ["T1550.002"]
    assert "lateral-movement" in r["matched_tactics"]
    assert r["matched_actors"] == ["Ember Bear"]
    assert r["score"] > 0.5


def test_relevance_unrelated_item_scores_zero():
    item = {"title": "Patch released", "text": "", "tags": [], "techniques": ["T1486"]}
    r = osint.relevance(item, ["T1550.002"], ["Ember Bear"])
    assert r["score"] == 0 and not r["matched_techniques"]


# --- resilience ------------------------------------------------------------
def test_collect_survives_dead_feed():
    with patch.object(osint, "_get", side_effect=OSError("network down")):
        radar = osint.collect()
    assert radar["items"] == []
    assert all(s["ok"] is False for s in radar["sources"])   # reported, not crashed
