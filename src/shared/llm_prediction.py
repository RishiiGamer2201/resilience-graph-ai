"""Grounded, on-demand LLM technique-association explanation.

The model is allowed to rank only ATT&CK techniques supplied in a bounded
candidate set and may cite only campaign names present in the bundled ATT&CK
artifact. This keeps the association ranking useful without allowing it to
invent technique IDs or historical incidents.
"""
from __future__ import annotations

import json
import pickle
import re
from pathlib import Path

from src.shared import llm, predictor


ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
SYSTEM = (
    "You are a cybersecurity investigation advisor. Select exactly three MITRE ATT&CK "
    "techniques to investigate from the supplied association candidates. They co-occur "
    "in tactic-sorted ATT&CK profiles; do not say they happen next or provide a future "
    "probability. Ground every reason in the observed techniques, candidate description, "
    "and supplied historical ATT&CK profiles. Never invent "
    "a technique ID, campaign name, fact, or probability. Return only the requested JSON."
)
CHRONOLOGICAL_CLAIM = re.compile(
    r"\b(next|likely next|will|expected to|follows?|continuation|forecast)\b",
    re.IGNORECASE,
)

SCHEMA = {
    "type": "object",
    "properties": {
        "predictions": {
            "type": "array", "minItems": 3, "maxItems": 3,
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "reason": {"type": "string"},
                    "previous_attacks": {
                        "type": "array", "minItems": 1, "maxItems": 2,
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "brief": {"type": "string"},
                            },
                            "required": ["name", "brief"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["technique_id", "reason", "previous_attacks"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["predictions"],
    "additionalProperties": False,
}


def _lookups() -> dict:
    with LOOKUPS.open("rb") as handle:
        return pickle.load(handle)


def _campaign_examples(campaigns: dict[str, list[str]], observed: list[str],
                       candidate_ids: set[str], limit: int = 12) -> list[dict]:
    observed_set = set(observed)
    ranked = []
    for name, techniques in campaigns.items():
        technique_set = set(techniques)
        predicted = technique_set & candidate_ids
        if not predicted:
            continue
        observed_overlap = technique_set & observed_set
        score = 3 * len(observed_overlap) + len(predicted)
        ranked.append((score, len(observed_overlap), name, techniques))
    ranked.sort(key=lambda row: (-row[0], -row[1], row[2]))
    relevant_ids = observed_set | candidate_ids
    return [
        {"name": name,
         "technique_ids": [tid for tid in techniques if tid in relevant_ids][:24]}
        for _, _, name, techniques in ranked[:limit]
    ]


def _parse(text: str) -> dict:
    value = text.strip()
    if value.startswith("```"):
        value = value.split("\n", 1)[1] if "\n" in value else value
        value = value.rsplit("```", 1)[0]
    return json.loads(value)


def generate(technique_ids: list[str], k: int = 3) -> dict:
    """Ask the configured LLM to explain three grounded associations."""
    data = _lookups()
    names = data["technique_to_name"]
    descriptions = data["technique_to_desc"]
    top, transition_source = predictor.rank_associations(technique_ids, 20)
    raw_candidates = [tid for tid, _ in top if tid not in set(technique_ids)]
    campaigns_data = data.get("campaign_to_techniques", {})
    campaign_techniques = {t for techs in campaigns_data.values() for t in techs}
    candidates = [tid for tid in raw_candidates if tid in campaign_techniques][:15]
    if len(candidates) < 3:
        raise RuntimeError("fewer than three grounded technique associations are available")

    candidate_rows = [
        {"technique_id": tid, "name": names.get(tid, tid),
         "description": str(descriptions.get(tid, ""))[:500]}
        for tid in candidates
    ]
    examples = _campaign_examples(campaigns_data, technique_ids, set(candidates), limit=20)
    evidenced = {tid for row in examples for tid in row["technique_ids"]}
    candidates = [tid for tid in candidates if tid in evidenced]
    candidate_rows = [row for row in candidate_rows if row["technique_id"] in set(candidates)]
    if len(candidates) < 3:
        raise RuntimeError("fewer than three candidates have documented ATT&CK campaign examples")
    context = json.dumps({
        "observed_chain": [
            {"technique_id": tid, "name": names.get(tid, tid)} for tid in technique_ids
        ],
        "candidate_techniques": candidate_rows,
        "documented_campaigns": examples,
        "candidate_generation": transition_source,
        "data_basis": predictor.temporal_prediction_status().get("data_basis"),
        "required_output_schema": SCHEMA,
    }, ensure_ascii=False)
    prompt = llm.render(
        SYSTEM, context=context,
        untrusted=(
            "For each association, explain why it is worth investigating alongside this "
            "incident's observed techniques. Do not describe chronology or a next move. "
            "Use one or two documented_campaigns that contain that technique. Write each "
            "campaign brief in 2-3 concise sentences using only the supplied technique list."
        ),
    )
    result = llm.complete(SYSTEM, prompt, schema=SCHEMA, max_tokens=1400)
    if not result.ok:
        raise RuntimeError(result.error or "the configured language model did not answer")

    try:
        payload = _parse(result.text)
        raw_predictions = payload["predictions"]
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"the language model returned invalid prediction JSON: {exc}") from exc

    campaigns = {row["name"]: set(row["technique_ids"]) for row in examples}
    allowed = set(candidates)
    seen: set[str] = set()
    predictions = []
    for raw in raw_predictions:
        tid = str(raw.get("technique_id") or "")
        if tid not in allowed or tid in seen:
            raise RuntimeError(f"the language model selected an invalid or duplicate technique: {tid}")
        reason = str(raw.get("reason") or "").strip()
        if not reason:
            raise RuntimeError(f"the language model gave no reason for {tid}")
        if CHRONOLOGICAL_CLAIM.search(reason):
            raise RuntimeError(
                f"the language model used unvalidated chronological language for {tid}")
        prior = []
        for attack in raw.get("previous_attacks") or []:
            name = str(attack.get("name") or "").strip()
            brief = str(attack.get("brief") or "").strip()
            if name not in campaigns or tid not in campaigns[name] or not brief:
                continue
            prior.append({"name": name, "brief": brief})
        if not prior:
            raise RuntimeError(f"the language model gave no grounded campaign example for {tid}")
        seen.add(tid)
        predictions.append({
            "rank": len(predictions) + 1, "technique_id": tid,
            "name": names.get(tid, tid), "reason": reason,
            "previous_attacks": prior[:2],
        })
        if len(predictions) == min(3, k):
            break

    if len(predictions) != min(3, k):
        raise RuntimeError("the language model did not return three valid grounded predictions")
    return {
        "given": technique_ids, "predictions": predictions,
        "mode": "association-only",
        "temporal_prediction": predictor.temporal_prediction_status(),
        "source": f"llm:{result.provider}", "provider": result.provider,
        "model": result.model, "authoritative": False,
        "disclaimer": ("LLM-explained ATT&CK profile associations; not detections, "
                       "chronological next moves, or future probabilities."),
    }
