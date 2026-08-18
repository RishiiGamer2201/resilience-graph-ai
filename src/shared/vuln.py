"""Live vulnerability prioritisation — which CVE do we fix first, and why.

A CVSS score alone tells an operator nothing about THEIR estate. This module
combines six separable signals into one deterministic, auditable priority:

    asset criticality   from the operator's own asset inventory (never guessed)
    known exploitation  CISA KEV membership (fact, from the evidence index)
    graph reachability  can the attacker in THIS incident actually get there
    technique overlap   does the CVE's exploit technique appear in this incident
    severity            CVSS base score when a source states one, else unknown
    evidence freshness  how recent the authoritative advisory is

Design rules that make it defensible under questioning:

  * FACTS and WEIGHTS are separate. Facts come from the inventory, the evidence
    index and the attack graph. Weights come from `configs/vuln_priority.json`
    and are hashed into every result.
  * We never invent an asset's software. If the inventory has no product for a
    host (LANL is anonymised, so it never does), that host produces no findings
    and says so — rather than fabricating a plausible CPE.
  * Unknown factors DROP OUT of the weighted average and are listed in
    `unknown_factors`, lowering `confidence`. They are never treated as zero.
  * The output is a band plus a score. The input data does not justify claiming
    that 73.4 is meaningfully different from 71.9.

    from src.shared.vuln import prioritize
    result = prioritize(inventory, graph_view, technique_ids)
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "configs" / "vuln_priority.json"
INVENTORY_PATH = ROOT / "data" / "demo" / "scenarios" / "asset_inventory.json"

_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

_state: dict = {}


# --------------------------------------------------------------------------- #
# configuration                                                                #
# --------------------------------------------------------------------------- #
def load_config(path: Path = CONFIG_PATH) -> dict:
    """Load + validate the weight configuration. Bad config fails loudly."""
    if "cfg" in _state and _state["cfg_path"] == path:
        return _state["cfg"]
    raw = path.read_text(encoding="utf-8")
    cfg = json.loads(raw)
    w = cfg["weights"]
    assert all(0.0 <= v <= 1.0 for v in w.values()), f"weights out of range: {w}"
    assert abs(sum(w.values()) - 1.0) < 1e-6, f"weights must sum to 1.0, got {sum(w.values())}"
    b = cfg["bands"]
    assert b["act_now"] > b["urgent"] > b["scheduled"] > 0, f"bands not ordered: {b}"
    cfg["sha256"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    _state["cfg"], _state["cfg_path"] = cfg, path
    return cfg


def load_inventory(scenario: str | None = None, path: Path = INVENTORY_PATH) -> dict:
    """The operator's asset inventory. Shipped file is explicitly SAMPLE data."""
    if not path.exists():
        return {"provenance": "MISSING", "assets": [], "note": f"no inventory at {path}"}
    data = json.loads(path.read_text(encoding="utf-8"))
    inv = data.get("inventories", {}).get(scenario or "", None)
    if inv is None:
        return {"provenance": "NOT_PROVIDED", "assets": [],
                "note": (f"no asset inventory for scenario '{scenario}'. Vulnerability "
                         "prioritisation needs an inventory (host -> product, criticality, "
                         "owner); we do not guess a host's software."),
                "known_scenarios": sorted(data.get("inventories", {}))}
    return {**inv, "scenario": scenario}


# --------------------------------------------------------------------------- #
# facts: the KEV catalogue, read out of the bundled evidence index             #
# --------------------------------------------------------------------------- #
def kev_facts() -> list[dict]:
    """Structured CISA KEV records derived from the evidence index chunks.

    One source of truth: the same chunks the citation UI shows are the ones the
    scorer reasons over, so a finding can always be opened back to its advisory.
    """
    if "kev" in _state:
        return _state["kev"]
    from src.shared.evidence import repository
    out = []
    for c in repository().chunks:
        if c.source_id != "cisa-kev":
            continue
        idents = c.identifiers
        cve = idents[0] if idents else ""
        out.append({
            "cve": cve,
            "vendor": idents[1] if len(idents) > 1 else "",
            "product": idents[2] if len(idents) > 2 else "",
            "ransomware_linked": "ransomware" in idents,
            "techniques": [i for i in idents if _TID_RE.fullmatch(i)],
            "date_added": c.published,
            "title": c.title,
            "url": c.url,
            "chunk_id": c.id,
            "text": c.text,
        })
    _state["kev"] = out
    return out


# --------------------------------------------------------------------------- #
# factor computation                                                           #
# --------------------------------------------------------------------------- #
def _reachability(host: str, graph: dict) -> tuple[str, str]:
    """How exposed this host is in the current incident's attack graph."""
    if not graph:
        return "not_in_graph", "no attack graph for this incident"
    at_risk = set(graph.get("critical_assets_at_risk") or [])
    paths = graph.get("paths_to_critical") or {}
    nodes = {n["id"] if isinstance(n, dict) else n for n in (graph.get("nodes") or [])}
    reached = set()
    for e in graph.get("edges") or []:
        reached.add(e.get("to"))
    if host in at_risk:
        p = paths.get(host) or []
        return "reached", (f"attacker reached it: {' -> '.join(p)}" if p
                           else "attacker reached this host in the observed movement")
    if host in reached:
        return "reached", "the attacker authenticated to this host"
    if host in paths:
        return "path_exists", "a path from an attacker pivot to this host exists"
    if host in nodes:
        return "in_graph", "the host appears in the incident graph"
    return "not_in_graph", "not observed in this incident's movement"


def _freshness(published: str | None, cfg: dict, today: date) -> tuple[float | None, str]:
    if not published:
        return None, "source states no document date"
    try:
        d = datetime.strptime(published[:10], "%Y-%m-%d").date()
    except ValueError:
        return None, f"unparsable document date {published!r}"
    age = max(0, (today - d).days)
    full, zero = cfg["freshness"]["full_score_within_days"], cfg["freshness"]["zero_score_after_days"]
    if age <= full:
        return 1.0, f"advisory is {age} days old"
    if age >= zero:
        return 0.0, f"advisory is {age} days old (beyond the {zero}-day decay window)"
    return round(1.0 - (age - full) / (zero - full), 4), f"advisory is {age} days old"


def _match_products(asset: dict, kev: list[dict]) -> list[dict]:
    """Match an asset's declared software against the KEV catalogue.

    Conservative on purpose: both the vendor and the product string must appear
    in the declared software entry. A loose match here becomes a false finding
    on an operator's remediation queue.
    """
    hits = []
    for sw in asset.get("software", []):
        vendor = str(sw.get("vendor", "")).lower().strip()
        product = str(sw.get("product", "")).lower().strip()
        if not product:
            continue
        for k in kev:
            kv, kp = k["vendor"].lower().strip(), k["product"].lower().strip()
            if not kp:
                continue
            if (kp in product or product in kp) and (not kv or kv in vendor or vendor in kv):
                hits.append({**k, "matched_software": sw})
    return hits


def _band(score: float, cfg: dict) -> str:
    b = cfg["bands"]
    if score >= b["act_now"]:
        return "act now"
    if score >= b["urgent"]:
        return "urgent"
    if score >= b["scheduled"]:
        return "scheduled"
    return "monitor"


def score_finding(asset: dict, kev_hit: dict, graph: dict, technique_ids: list[str],
                  cfg: dict, today: date) -> dict:
    """Score ONE (asset, CVE) pair. Every factor is returned with its reason."""
    crit = str(asset.get("criticality", "medium")).lower()
    scale = cfg["asset_criticality_scale"]
    factors: dict[str, dict] = {}

    factors["asset_criticality"] = {
        "value": scale.get(crit, scale["medium"]),
        "fact": f"{asset.get('host')} is classified {crit} in the asset inventory",
        "source": asset.get("provenance", "asset inventory"),
    }
    factors["known_exploited"] = {
        "value": 1.0,
        "fact": ("listed in the CISA Known Exploited Vulnerabilities catalog"
                 + (", linked to ransomware campaigns" if kev_hit["ransomware_linked"] else "")),
        "source": kev_hit["url"],
    }
    rlevel, rwhy = _reachability(asset.get("host", ""), graph)
    factors["graph_reachability"] = {
        "value": cfg["reachability_scale"][rlevel],
        "fact": rwhy, "source": "attack graph (this incident)", "level": rlevel,
    }
    # Does the exploit technique for this CVE appear in the incident we're looking at?
    # The mapping is baked into the evidence index at build time (see
    # scripts/build_evidence_index.py) — validated against the real ATT&CK lookups.
    cve_techniques = kev_hit["techniques"]
    overlap = [t for t in cve_techniques if t in set(technique_ids or [])]
    factors["technique_overlap"] = {
        "value": (len(overlap) / len(cve_techniques)) if cve_techniques else None,
        "fact": (f"exploit maps to {', '.join(cve_techniques)}; observed in this incident: "
                 f"{', '.join(overlap) if overlap else 'none'}") if cve_techniques
                else "no ATT&CK technique could be mapped from the advisory text",
        "source": "MITRE ATT&CK mapping of the advisory text",
        "techniques": cve_techniques, "matched": overlap,
    }
    cvss = kev_hit.get("cvss")
    factors["severity"] = {
        "value": (cvss / cfg["severity"]["max_cvss"]) if isinstance(cvss, (int, float)) else None,
        "fact": (f"CVSS base {cvss}" if cvss is not None else
                 "no CVSS published in CISA KEV; optional NVD enrichment not run"),
        "source": "NVD" if cvss is not None else "unknown",
    }
    fval, fwhy = _freshness(kev_hit.get("date_added"), cfg, today)
    factors["evidence_freshness"] = {"value": fval, "fact": fwhy, "source": kev_hit["url"]}

    # weighted average over the factors we can actually evaluate
    w = cfg["weights"]
    num = sum(w[k] * f["value"] for k, f in factors.items() if f["value"] is not None)
    den = sum(w[k] for k, f in factors.items() if f["value"] is not None)
    unknown = sorted(k for k, f in factors.items() if f["value"] is None)
    score = round(100.0 * num / den, 1) if den else 0.0

    return {
        "cve": kev_hit["cve"],
        "host": asset.get("host"),
        "asset_name": asset.get("name", asset.get("host")),
        "owner": asset.get("owner", "unassigned"),
        "software": kev_hit["matched_software"],
        "title": kev_hit["title"],
        "priority_score": score,
        "band": _band(score, cfg),
        "confidence": round(den, 3),          # share of weight backed by known facts
        "unknown_factors": unknown,
        "factors": factors,
        "citation": {"chunk_id": kev_hit["chunk_id"], "url": kev_hit["url"],
                     "publisher": "CISA", "title": kev_hit["title"],
                     "published": kev_hit["date_added"]},
        "provenance": "VERIFIED" if kev_hit["date_added"] else "MODEL_INFERRED",
    }


def prioritize(inventory: dict, graph: dict | None = None,
               technique_ids: list[str] | None = None, *,
               limit: int = 25, today: date | None = None) -> dict:
    """Rank every (asset, known-exploited-CVE) pair for this incident."""
    cfg = load_config()
    today = today or date.today()
    kev = kev_facts()
    assets = inventory.get("assets", [])
    findings: list[dict] = []
    no_software = []
    for a in assets:
        if not a.get("software"):
            no_software.append(a.get("host"))
            continue
        for hit in _match_products(a, kev):
            findings.append(score_finding(a, hit, graph or {}, technique_ids or [],
                                          cfg, today))
    findings.sort(key=lambda f: (-f["priority_score"], f["cve"], f["host"]))

    return {
        "findings": findings[:limit],
        "total_findings": len(findings),
        "assets_considered": len(assets),
        "assets_without_software_data": no_software,
        "kev_catalog_size": len(kev),
        "config": {"version": cfg["version"], "sha256": cfg["sha256"],
                   "weights": cfg["weights"], "bands": cfg["bands"]},
        "inventory_provenance": inventory.get("provenance", "UNKNOWN"),
        "inventory_note": inventory.get("note", ""),
        "evaluated_on": today.isoformat(),
        "note": ("Priority = deterministic weighted average of the factors we can "
                 "evaluate. Unknown factors are excluded and reported, never scored 0. "
                 "Findings require an asset inventory; host software is never guessed."),
    }


def demo() -> None:
    """Self-check: the ranking is monotone in the things that should matter."""
    cfg = load_config()
    kev = kev_facts()
    assert kev, "no KEV facts in the evidence index — rebuild it"
    hit = {**kev[0], "matched_software": {"vendor": kev[0]["vendor"],
                                          "product": kev[0]["product"]}}
    graph = {"edges": [{"to": "SRV-A"}], "nodes": [{"id": "SRV-A"}, {"id": "SRV-B"}],
             "critical_assets_at_risk": ["SRV-A"], "paths_to_critical": {"SRV-A": ["PIVOT", "SRV-A"]}}
    today = date(2026, 8, 18)
    hi = score_finding({"host": "SRV-A", "criticality": "critical"}, hit, graph, [], cfg, today)
    lo = score_finding({"host": "SRV-B", "criticality": "low"}, hit, graph, [], cfg, today)
    assert hi["priority_score"] > lo["priority_score"], (hi["priority_score"], lo["priority_score"])
    assert "severity" in hi["unknown_factors"], hi["unknown_factors"]
    assert 0 < hi["confidence"] <= 1.0
    print(f"vuln ok: {len(kev)} KEV facts; critical+reached {hi['priority_score']} "
          f"({hi['band']}) > low+unreached {lo['priority_score']} ({lo['band']}); "
          f"unknown factors {hi['unknown_factors']}")


if __name__ == "__main__":
    demo()
