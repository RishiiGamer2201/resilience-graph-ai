"""Verified real-incident case files, kept separate from the synthetic scenarios.

A shipped scenario is generated data with a realistic shape. A case file is what
official sources actually established about a real incident. Conflating the two
is the easiest way for a security demo to mislead, so they are different objects
with different provenance and the UI shows both.

The AIIMS Delhi 2022 case file is the worked example the research asks for
(`research/codex/it_ot_attack_detection_digital_twin_research.md` §11): the
Government established `T1486 Data Encrypted for Impact` and one control
weakness. It did not establish the initial access vector, the ransomware family,
any lateral-movement technique, whether data was exfiltrated, or who did it.

    from src.shared.casefile import load_casefile
    cf = load_casefile("aiims_ransomware")
    cf["claims"][0]["status"]      # "confirmed"
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASEFILE_DIR = ROOT / "data" / "manual"

# scenario name -> case file. Only scenarios styled after a real, documented
# incident get one; the rest correctly have none.
SCENARIO_CASEFILES = {
    "aiims_ransomware": "aiims_2022_casefile.json",
}

_cache: dict = {}


def available_for(scenario: str | None) -> bool:
    return bool(scenario and scenario in SCENARIO_CASEFILES)


def _raw(scenario: str) -> dict:
    if scenario not in _cache:
        path = CASEFILE_DIR / SCENARIO_CASEFILES[scenario]
        _cache[scenario] = json.loads(path.read_text(encoding="utf-8"))
    return _cache[scenario]


def load_casefile(scenario: str | None) -> dict | None:
    """The verified record for the real incident a scenario is styled after.

    Returns None when a scenario is purely synthetic, which is the honest answer
    for most of them.
    """
    if not available_for(scenario):
        return None
    raw = _raw(scenario)
    sources = {s["id"]: s for s in raw["sources"]}

    claims = [_build_claim(c, sources) for c in raw["attack_claims"]]
    confirmed = [c for c in claims if c["status"] == "confirmed"]

    return {
        "case_id": raw["case_id"],
        "title": raw["title"],
        "provenance": raw["provenance"],
        "verified_on": raw["verified_on"],
        "verification_method": raw["verification_method"],
        "sources": raw["sources"],
        "sources_verified": sum(1 for s in raw["sources"] if s.get("verified")),
        "established_facts": raw["established_facts"],
        "claims": claims,
        "confirmed_techniques": [c["external_id"] for c in confirmed],
        "hypothesis_techniques": [c["external_id"] for c in claims
                                  if c["status"] != "confirmed"],
        "control_weaknesses": raw["control_weaknesses"],
        "not_established": raw["not_established"],
        "why_this_matters": raw["why_this_matters"],
        "relationship_to_scenario": raw["relationship_to_scenario"],
        "summary": (f"{len(confirmed)} technique confirmed by official sources, "
                    f"{len(claims) - len(confirmed)} hypothesis, "
                    f"{len(raw['not_established'])} things not publicly established"),
    }


def _build_claim(spec: dict, sources: dict) -> dict:
    """Turn a case-file entry into the same Claim shape the live pipeline emits.

    Same object, same confidence arithmetic, same actionable rule — so a judge
    comparing the real incident with a live analysis is reading one vocabulary.
    """
    from src.shared.claims import Claim, ClaimStatus, Evidence

    claim = Claim(
        subject=f"incident:{spec.get('tactic', 'unknown')}",
        predicate="MAPS_TO",
        object=spec["technique"],
        external_id=spec["technique_id"],
        status=ClaimStatus(spec["status"]),
        mapper="analyst-verified parliamentary record",
        missing_evidence=list(spec.get("missing_evidence", [])),
        alternatives=list(spec.get("alternatives", [])),
        note=spec["rationale"],
    )
    for sid in spec.get("source_ids", []):
        src = sources.get(sid, {})
        claim.add_evidence(Evidence(
            id=sid,
            kind="parliamentary-answer",
            source=f"{src.get('chamber', '?')} {src.get('question_no', sid)}",
            # One group on purpose: two answers from the same Government record
            # about the same incident are not independent corroboration.
            independence_group=spec.get("independence_group", "parliamentary-record"),
            strength=float(spec["strength"]),
            reliability=1.0 if src.get("verified") else 0.4,
            detail=(f"{src.get('ministry', '')}, answered "
                    f"{src.get('answered_on', 'unknown date')}"),
        ))
    out = claim.as_dict()
    out["tactic"] = spec.get("tactic", "")
    out["source_ids"] = spec.get("source_ids", [])
    return out


def demo() -> None:
    """Self-check: one technique confirmed, the rest honestly unestablished."""
    cf = load_casefile("aiims_ransomware")
    assert cf is not None
    assert cf["confirmed_techniques"] == ["T1486"], cf["confirmed_techniques"]
    assert "T1021" in cf["hypothesis_techniques"]

    t1486 = next(c for c in cf["claims"] if c["external_id"] == "T1486")
    assert t1486["actionable"] is True
    assert t1486["confidence"] >= 0.9, t1486["confidence"]

    t1021 = next(c for c in cf["claims"] if c["external_id"] == "T1021")
    assert t1021["actionable"] is False
    assert t1021["confidence"] < 0.45, t1021["confidence"]
    assert t1021["missing_evidence"] and t1021["alternatives"]

    # every quoted fact must name the source it came from
    ids = {s["id"] for s in cf["sources"]}
    for f in cf["established_facts"]:
        assert f["source_id"] in ids, f
        assert f["quote"]

    assert load_casefile("cbse_exam_breach") is None, "synthetic scenarios have no case file"
    assert load_casefile(None) is None

    print(f"casefile ok: {cf['case_id']} — {cf['summary']}; "
          f"T1486 confirmed at {t1486['confidence']}, "
          f"T1021 hypothesis at {t1021['confidence']}")


if __name__ == "__main__":
    demo()
