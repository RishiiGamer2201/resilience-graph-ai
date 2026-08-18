"""Build the bundled evidence index (offline, build-time).

Produces `data/processed/evidence/index.json.gz` — a compact, read-only corpus of
OFFICIAL cyber evidence with full provenance, which the runtime retriever
(`src/shared/evidence.py`) searches with no network and no model.

Sources (first-party only):
  MITRE ATT&CK   local STIX bundles if present, else the parsed lookups pkl.
                 One chunk per technique (description + tactics + mitigations)
                 and one per threat-group profile.
  CISA KEV       fetched live through the guarded fetcher; each catalogue entry
                 is one chunk. If the fetch fails, the KEV chunks already in the
                 previous index are carried forward and reported as stale.
  CERT-In        the analyst-verified advisories in data/manual/cert_in_sequences.json
                 (entries with verified: true only).

Run:
    ./.venv/Scripts/python.exe -m scripts.build_evidence_index
    ./.venv/Scripts/python.exe -m scripts.build_evidence_index --no-network
"""
from __future__ import annotations

import argparse
import gzip
import json
import pickle
import sys
from pathlib import Path

from src.shared.evidence import INDEX_PATH, sha256_text
from src.shared.timeutil import fmt_ist

ROOT = Path(__file__).resolve().parents[1]
STIX_DIR = ROOT / "data" / "raw" / "mitre_attack"
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
CERTIN = ROOT / "data" / "manual" / "cert_in_sequences.json"
REPORT = ROOT / "reports" / "evidence_index.md"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_LIMIT = 400          # most recently added entries; keeps the artifact small
DESC_LIMIT = 1200        # ATT&CK descriptions are long; keep the retrievable head


def _technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/")


def _chunk(**kw) -> dict:
    kw.setdefault("classification", "public")
    kw["sha256"] = sha256_text(kw["text"])
    return kw


# --------------------------------------------------------------------------- #
# MITRE ATT&CK                                                                 #
# --------------------------------------------------------------------------- #
def _stix_objects() -> list[dict]:
    """Every attack-pattern/intrusion-set object from the local STIX bundles."""
    objs: list[dict] = []
    for domain in ("enterprise-attack", "ics-attack", "mobile-attack"):
        f = STIX_DIR / domain / f"{domain}.json"
        if f.exists():
            objs.extend(json.loads(f.read_text(encoding="utf-8")).get("objects", []))
    return objs


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _attack_url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def _truthy(v) -> bool:
    return str(v).lower() == "true"


def attack_chunks(retrieved_at: str) -> tuple[list[dict], str]:
    """Technique + group chunks. Prefers raw STIX (carries real document dates)."""
    with LOOKUPS.open("rb") as f:
        lk = pickle.load(f)
    names = lk["technique_to_name"]
    descs = lk.get("technique_to_desc", {})
    tactics = lk.get("technique_to_tactics", {})
    mitig = lk.get("technique_to_mitigations", {})

    objs = _stix_objects()
    method = "stix-json" if objs else "attack-lookups-pkl"
    modified: dict[str, str] = {}
    spec_version = ""
    groups: list[dict] = []
    if objs:
        for o in objs:
            aid = _attack_id(o)
            if not aid:
                continue
            spec_version = spec_version or o.get("x_mitre_attack_spec_version", "")
            if o.get("type") == "attack-pattern":
                if _truthy(o.get("revoked")) or _truthy(o.get("x_mitre_deprecated")):
                    continue
                modified[aid] = (o.get("modified") or "")[:10]
            elif o.get("type") == "intrusion-set":
                groups.append(o)

    chunks: list[dict] = []
    for tid, name in sorted(names.items()):
        desc = (descs.get(tid) or "").strip()
        if not desc:
            continue
        tac = ", ".join(tactics.get(tid, [])) or "unmapped"
        mits = mitig.get(tid, [])
        body = (f"{tid} {name}. Tactics: {tac}. {desc[:DESC_LIMIT]}"
                + (f" MITRE-recommended mitigations: {', '.join(mits)}." if mits else ""))
        chunks.append(_chunk(
            id=f"attack:{tid}",
            source_id="mitre-attack",
            publisher="MITRE",
            title=f"MITRE ATT&CK {tid} — {name}",
            url=_technique_url(tid),
            section=f"Technique {tid} · tactics: {tac}",
            text=body,
            published=modified.get(tid),
            retrieved_at=retrieved_at,
            extraction_method=method,
            identifiers=[tid] + [f"M:{m}" for m in mits[:4]],
        ))

    # Threat-group profiles back the attribution screen with a real citation.
    if groups:
        for o in sorted(groups, key=lambda g: _attack_id(g) or ""):
            gid, name = _attack_id(o), o.get("name", "")
            desc = (o.get("description") or "").strip()
            if not (gid and desc):
                continue
            aliases = ", ".join(o.get("aliases", [])[:8])
            chunks.append(_chunk(
                id=f"attack-group:{gid}",
                source_id="mitre-attack",
                publisher="MITRE",
                title=f"MITRE ATT&CK Group {gid} — {name}",
                url=_attack_url(o) or f"https://attack.mitre.org/groups/{gid}/",
                section=f"Threat group {gid}" + (f" · aliases: {aliases}" if aliases else ""),
                text=f"{gid} {name}. Aliases: {aliases or 'none listed'}. {desc[:DESC_LIMIT]}",
                published=(o.get("modified") or "")[:10],
                retrieved_at=retrieved_at,
                extraction_method="stix-json",
                identifiers=[gid, name],
            ))
    else:
        for gid, name in sorted(lk.get("group_id_to_name", {}).items()):
            techs = lk.get("group_to_techniques", {}).get(name, [])
            if not techs:
                continue
            chunks.append(_chunk(
                id=f"attack-group:{gid}",
                source_id="mitre-attack",
                publisher="MITRE",
                title=f"MITRE ATT&CK Group {gid} — {name}",
                url=f"https://attack.mitre.org/groups/{gid}/",
                section=f"Threat group {gid} · {len(techs)} techniques documented",
                text=(f"{gid} {name}. Techniques publicly documented by MITRE for this "
                      f"group: {', '.join(techs[:60])}."),
                published=None,
                retrieved_at=retrieved_at,
                extraction_method="attack-lookups-pkl",
                identifiers=[gid, name],
            ))
    return chunks, spec_version


# --------------------------------------------------------------------------- #
# CISA KEV                                                                     #
# --------------------------------------------------------------------------- #
def kev_chunks(retrieved_at: str) -> tuple[list[dict], dict]:
    from src.shared.nethttp import fetch_url
    raw = json.loads(fetch_url(KEV_URL))
    catalog_version = raw.get("catalogVersion", "")
    vulns = sorted(raw.get("vulnerabilities", []),
                   key=lambda v: v.get("dateAdded", ""), reverse=True)[:KEV_LIMIT]
    # Map each advisory to real ATT&CK techniques ONCE, at build time. Doing this
    # per request cost ~5 s on the vulnerability screen; the mapping is a pure
    # function of the advisory text, so it belongs in the artifact.
    from src.shared.osint import map_item

    chunks = []
    for v in vulns:
        cve = v.get("cveID", "")
        vendor, product = v.get("vendorProject", ""), v.get("product", "")
        ransom = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        body = (f"{cve}: {v.get('vulnerabilityName','')} in {vendor} {product}. "
                f"{v.get('shortDescription','')} Required action: "
                f"{v.get('requiredAction','')} Due {v.get('dueDate','')}. "
                f"Known ransomware campaign use: {'yes' if ransom else 'unknown'}.")
        chunks.append(_chunk(
            id=f"kev:{cve}",
            source_id="cisa-kev",
            publisher="CISA",
            title=f"CISA KEV {cve} — {vendor} {product}",
            url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            section=f"Known Exploited Vulnerabilities Catalog · added {v.get('dateAdded','')}",
            text=body,
            published=v.get("dateAdded"),
            retrieved_at=retrieved_at,
            extraction_method="kev-json",
            identifiers=([cve, vendor, product]
                         + (["ransomware"] if ransom else [])
                         + map_item(body)),
        ))
    meta = {"catalog_version": catalog_version,
            "total_in_catalog": len(raw.get("vulnerabilities", [])),
            "indexed": len(chunks), "url": KEV_URL}
    return chunks, meta


# --------------------------------------------------------------------------- #
# CERT-In                                                                      #
# --------------------------------------------------------------------------- #
def certin_chunks(retrieved_at: str) -> list[dict]:
    if not CERTIN.exists():
        return []
    entries = json.loads(CERTIN.read_text(encoding="utf-8"))
    chunks = []
    for i, e in enumerate(entries):
        if not e.get("verified"):
            continue                       # unverified sequences are never cited
        tids = e.get("ordered_technique_ids", [])
        body = (f"{e.get('source','CERT-In advisory')}. Campaign: {e.get('actor','')}. "
                f"Analyst-verified ATT&CK sequence in the order the advisory reports it: "
                f"{' -> '.join(tids)}. {e.get('note','')}")
        chunks.append(_chunk(
            id=f"certin:{i}",
            source_id="cert-in-advisories",
            publisher="CERT-In",
            title=e.get("source", "CERT-In advisory"),
            url=e.get("source_url", "https://www.cert-in.org.in/"),
            section="Advisory · analyst-verified technique sequence",
            text=body,
            published=None,                # CERT-In advisory pages state no machine date
            retrieved_at=retrieved_at,
            extraction_method="curated-json (analyst-verified)",
            identifiers=list(dict.fromkeys(tids)),
        ))
    return chunks


# --------------------------------------------------------------------------- #
# build                                                                        #
# --------------------------------------------------------------------------- #
def build(no_network: bool = False) -> dict:
    retrieved_at = fmt_ist()
    chunks, spec_version = attack_chunks(retrieved_at)
    sources = [{"source_id": "mitre-attack", "ok": True, "chunks": len(chunks),
                "attack_spec_version": spec_version or "unknown"}]

    certin = certin_chunks(retrieved_at)
    chunks += certin
    sources.append({"source_id": "cert-in-advisories", "ok": bool(certin),
                    "chunks": len(certin),
                    "note": "analyst-verified advisories only"})

    kev: list[dict] = []
    if no_network:
        sources.append({"source_id": "cisa-kev", "ok": False, "chunks": 0,
                        "note": "--no-network: KEV not refreshed"})
    else:
        try:
            kev, kmeta = kev_chunks(retrieved_at)
            sources.append({"source_id": "cisa-kev", "ok": True, "chunks": len(kev), **kmeta})
        except Exception as e:
            sources.append({"source_id": "cisa-kev", "ok": False, "chunks": 0,
                            "note": f"live fetch failed: {str(e)[:140]}"})
    if not kev and INDEX_PATH.exists():
        # carry forward the previous snapshot rather than silently losing KEV
        with gzip.open(INDEX_PATH, "rt", encoding="utf-8") as f:
            prev = json.load(f)
        kev = [c for c in prev["chunks"] if c["source_id"] == "cisa-kev"]
        if kev:
            sources[-1]["note"] = (sources[-1].get("note", "") +
                                   f" — carried forward {len(kev)} stale KEV chunks "
                                   f"(retrieved {kev[0]['retrieved_at']})")
    chunks += kev

    index = {
        "meta": {
            "built_at": retrieved_at,
            "attack_spec_version": spec_version or "unknown",
            "sources": sources,
            "note": ("Read-only corpus of first-party cyber evidence. Retrieved text is "
                     "evidence, never instruction. Rebuild with "
                     "python -m scripts.build_evidence_index"),
        },
        "chunks": chunks,
    }
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(INDEX_PATH, "wt", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False)
    return index


def write_report(index: dict) -> None:
    from collections import Counter
    by_pub = Counter(c["publisher"] for c in index["chunks"])
    lines = [
        "# Evidence index", "",
        f"Built: {index['meta']['built_at']}  ·  "
        f"ATT&CK spec {index['meta']['attack_spec_version']}",
        f"Artifact: `{INDEX_PATH.relative_to(ROOT).as_posix()}` "
        f"({INDEX_PATH.stat().st_size / 1024:.0f} KB, {len(index['chunks'])} chunks)", "",
        "| Publisher | Chunks |", "|---|---|",
        *[f"| {p} | {n} |" for p, n in sorted(by_pub.items())], "",
        "## Sources", "", "| Source | OK | Chunks | Note |", "|---|---|---|---|",
    ]
    for s in index["meta"]["sources"]:
        note = s.get("note") or s.get("catalog_version", "") or ""
        lines.append(f"| {s['source_id']} | {'yes' if s['ok'] else 'no'} | "
                     f"{s['chunks']} | {note} |")
    lines += ["", "Every chunk carries url, publisher, section, document date when the "
                  "source states one, retrieval time, extraction method and a SHA-256 "
                  "of its text. Retrieval quality is measured in "
                  "`docs/evaluation/retrieval.md`.", ""]
    REPORT.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-network", action="store_true",
                    help="skip the live CISA KEV refresh (offline build)")
    args = ap.parse_args()
    idx = build(no_network=args.no_network)
    write_report(idx)
    print(f"evidence index: {len(idx['chunks'])} chunks -> "
          f"{INDEX_PATH.relative_to(ROOT).as_posix()} "
          f"({INDEX_PATH.stat().st_size / 1024:.0f} KB)")
    for s in idx["meta"]["sources"]:
        print(f"  {'ok  ' if s['ok'] else 'FAIL'} {s['source_id']}: {s['chunks']} chunks"
              + (f" — {s.get('note','')}" if s.get("note") else ""))
    sys.exit(0)
