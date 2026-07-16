"""
Milestone 1 · Task 0.3 — Parse MITRE ATT&CK STIX into reusable lookup tables.

Reads the Enterprise + ICS STIX bundles from data/raw/mitre_attack/ and writes
a single pickle of plain dicts to data/processed/mitre_attack/attack_lookups.pkl.

Feeds Engine 2 (sequences, embeddings, attribution) and the shared ATT&CK mapper.
No model training here — just correct, queryable lookups.

Lookups produced:
    technique_to_name        T#### -> "Valid Accounts"
    technique_to_desc        T#### -> description text
    technique_to_tactics     T#### -> ["credential-access", ...]
    technique_to_mitigations T#### -> ["Multi-factor Authentication", ...]
    group_to_techniques      "APT29" -> ["T1078", ...]
    group_id_to_name         "G0016" -> "APT29"
    campaign_to_techniques   "SolarWinds Compromise" -> ["T1078", ...]
    tactics_order            canonical kill-chain tactic order

Run:
    ./.venv/Scripts/python.exe -m src.shared.parse_attack
"""
from __future__ import annotations

import json
import pickle
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw" / "mitre_attack"
BUNDLES = [
    RAW / "enterprise-attack" / "enterprise-attack.json",
    RAW / "ics-attack" / "ics-attack.json",
    RAW / "mobile-attack" / "mobile-attack.json",   # India's threat mix is mobile-heavy
]
OUT_DIR = ROOT / "data" / "processed" / "mitre_attack"
OUT_PKL = OUT_DIR / "attack_lookups.pkl"
REPORT = ROOT / "reports" / "attack_lookups.md"

# Canonical Enterprise ATT&CK kill-chain tactic order (used to order sequences).
TACTICS_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def _ext_id(obj: dict) -> str | None:
    """Return the ATT&CK external id (T####, G####, etc.) for a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack"):
            return ref.get("external_id")
    return None


def _alive(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def build_lookups() -> tuple[dict, dict]:
    # stix_id -> ext_id, for each object type we care about
    tech_id, tech_name, tech_desc, tech_tactics = {}, {}, {}, {}
    group_id, campaign_id, mitig_name = {}, {}, {}
    uses, mitigates = [], []

    for bundle_path in BUNDLES:
        data = json.loads(bundle_path.read_text(encoding="utf-8"))
        for o in data["objects"]:
            t = o.get("type")
            if t == "attack-pattern" and _alive(o):
                eid = _ext_id(o)
                if not eid:
                    continue
                tech_id[o["id"]] = eid
                tech_name[eid] = o.get("name", "")
                tech_desc[eid] = o.get("description", "")
                tech_tactics[eid] = [p["phase_name"] for p in o.get("kill_chain_phases", [])]
            elif t == "intrusion-set" and _alive(o):
                group_id[o["id"]] = (_ext_id(o), o.get("name", ""))
            elif t == "campaign" and _alive(o):
                campaign_id[o["id"]] = o.get("name", "")
            elif t == "course-of-action" and _alive(o):
                mitig_name[o["id"]] = o.get("name", "")
            elif t == "relationship" and _alive(o):
                rt = o.get("relationship_type")
                if rt == "uses":
                    uses.append((o["source_ref"], o["target_ref"]))
                elif rt == "mitigates":
                    mitigates.append((o["source_ref"], o["target_ref"]))

    # group / campaign -> techniques (via 'uses' where target is a technique)
    group_to_techniques = defaultdict(set)
    campaign_to_techniques = defaultdict(set)
    group_id_to_name = {}
    for src, tgt in uses:
        if tgt not in tech_id:
            continue
        teid = tech_id[tgt]
        if src in group_id:
            gid, gname = group_id[src]
            group_to_techniques[gname].add(teid)
            group_id_to_name[gid] = gname
        elif src in campaign_id:
            campaign_to_techniques[campaign_id[src]].add(teid)

    # technique -> mitigations (via 'mitigates')
    technique_to_mitigations = defaultdict(set)
    for src, tgt in mitigates:
        if tgt in tech_id and src in mitig_name:
            technique_to_mitigations[tech_id[tgt]].add(mitig_name[src])

    def _order(teids: set) -> list:
        # order a technique set by kill-chain tactic order (heuristic for sequences)
        def key(teid):
            tacs = tech_tactics.get(teid, [])
            idx = min((TACTICS_ORDER.index(t) for t in tacs if t in TACTICS_ORDER),
                      default=len(TACTICS_ORDER))
            return (idx, teid)
        return sorted(teids, key=key)

    lookups = {
        "technique_to_name": tech_name,
        "technique_to_desc": tech_desc,
        "technique_to_tactics": tech_tactics,
        "technique_to_mitigations": {k: sorted(v) for k, v in technique_to_mitigations.items()},
        "group_to_techniques": {k: _order(v) for k, v in group_to_techniques.items()},
        "group_id_to_name": group_id_to_name,
        "campaign_to_techniques": {k: _order(v) for k, v in campaign_to_techniques.items()},
        "tactics_order": TACTICS_ORDER,
    }
    stats = {
        "techniques": len(tech_name),
        "groups": len(group_to_techniques),
        "campaigns": len(campaign_to_techniques),
        "mitigations": len(mitig_name),
        "techniques_with_mitigations": len(technique_to_mitigations),
    }
    return lookups, stats


def _selftest(lk: dict) -> list[str]:
    """A few manual sanity queries — must pass or the parse is wrong."""
    out = []
    apt29 = lk["group_to_techniques"].get("APT29", [])
    out.append(f"APT29 techniques: {len(apt29)} (expect >0) -> {apt29[:5]}")
    t1078 = lk["technique_to_name"].get("T1078")
    out.append(f"T1078 name: {t1078!r} (expect 'Valid Accounts')")
    mit = lk["technique_to_mitigations"].get("T1078", [])
    out.append(f"T1078 mitigations: {len(mit)} (expect >0) -> {mit[:3]}")
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    lookups, stats = build_lookups()
    with OUT_PKL.open("wb") as f:
        pickle.dump(lookups, f)

    checks = _selftest(lookups)
    lines = ["# MITRE ATT&CK lookups", "",
             f"- Techniques: **{stats['techniques']}**",
             f"- Groups (with techniques): **{stats['groups']}**",
             f"- Campaigns (with techniques): **{stats['campaigns']}**",
             f"- Mitigations: **{stats['mitigations']}** · techniques with mitigations: {stats['techniques_with_mitigations']}",
             "", "## Self-test queries"] + [f"- {c}" for c in checks]
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print("ATT&CK lookups built.")
    for k, v in stats.items():
        print(f"  {k:28s}: {v}")
    print("  self-test:")
    for c in checks:
        print(f"    - {c}")
    print(f"  -> {OUT_PKL.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
