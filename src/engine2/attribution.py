"""Milestone 3 · E2.5 — transparent ATT&CK actor attribution.

Ranks ATT&CK intrusion sets from an observed technique sequence.  This is
profile retrieval, not a trained actor classifier: group technique profiles
come directly from the parsed ATT&CK STIX data and semantic support comes from
the real technique-description embeddings produced by ``build_embeddings``.

Run after E2.2/E2.3 (and optionally E2.4):
    python -m src.engine2.attribution
"""
from __future__ import annotations

import math
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
EMBEDDINGS = ROOT / "data" / "processed" / "engine2" / "technique_embeddings.pkl"
REPORT = ROOT / "reports" / "attribution_eval.md"


@dataclass(frozen=True)
class ActorProfile:
    """A group's public ATT&CK technique profile and semantic centroid."""

    actor: str
    techniques: frozenset[str]
    centroid: np.ndarray


@dataclass(frozen=True)
class AttributionCalibration:
    """Thresholds measured on independently labelled incident telemetry.

    The repository does not ship such a benchmark yet, so production passes no
    calibration and the decision gate abstains. This type prevents a profile
    self-retrieval result from being mistaken for incident calibration later.
    """

    source: str
    independent_incidents: int
    minimum_observed_techniques: int
    minimum_exact_matches: int
    minimum_score: float
    minimum_margin: float

    def __post_init__(self) -> None:
        if not self.source.strip() or self.independent_incidents <= 0:
            raise ValueError("attribution calibration needs a source and independent incidents")
        if self.minimum_observed_techniques < SAFETY_MIN_OBSERVED:
            raise ValueError("calibration cannot weaken the observed-technique safety floor")
        if self.minimum_exact_matches < SAFETY_MIN_EXACT_MATCHES:
            raise ValueError("calibration cannot weaken the exact-match safety floor")
        if not 0.0 <= self.minimum_score <= 1.0:
            raise ValueError("minimum_score must be between zero and one")
        if not 0.0 <= self.minimum_margin <= 1.0:
            raise ValueError("minimum_margin must be between zero and one")


SAFETY_MIN_OBSERVED = 2
SAFETY_MIN_EXACT_MATCHES = 2


def _normalise(vector: np.ndarray) -> np.ndarray:
    norm = float(np.linalg.norm(vector))
    return vector / norm if norm else vector


def _known_ids(ids: Iterable[str], embeddings: dict[str, np.ndarray]) -> list[str]:
    """De-duplicate IDs and discard values not represented by the real artifacts."""
    return sorted({str(technique) for technique in ids if str(technique) in embeddings})


def build_profiles(
    groups: dict[str, list[str]], embeddings: dict[str, np.ndarray]
) -> dict[str, ActorProfile]:
    """Build profile sets and embedding centroids for ATT&CK groups only."""
    profiles: dict[str, ActorProfile] = {}
    for actor, techniques in groups.items():
        known = _known_ids(techniques, embeddings)
        if not known:
            continue
        matrix = np.vstack([np.asarray(embeddings[technique], dtype="float32") for technique in known])
        profiles[actor] = ActorProfile(actor, frozenset(known), _normalise(matrix.mean(axis=0)))
    return profiles


def rank_actors(
    observed_techniques: Iterable[str],
    profiles: dict[str, ActorProfile],
    embeddings: dict[str, np.ndarray],
    predicted_techniques: Iterable[str] = (),
    *,
    predicted_weight: float = 0.20,
) -> list[dict]:
    """Return a transparent ranking for an observed technique sequence.

    The score weights exact observed coverage most heavily, then Jaccard
    overlap and semantic similarity.  Markov predictions, if supplied, are
    supporting evidence only and cannot dominate the observed sequence.
    """
    observed = set(_known_ids(observed_techniques, embeddings))
    predicted = set(_known_ids(predicted_techniques, embeddings)) - observed
    if not observed:
        raise ValueError("No observed technique IDs are present in the embedding artifact.")

    observed_centroid = _normalise(
        np.vstack([np.asarray(embeddings[technique], dtype="float32") for technique in sorted(observed)]).mean(axis=0)
    )
    results: list[dict] = []
    for profile in profiles.values():
        matched = observed & profile.techniques
        coverage = len(matched) / len(observed)
        union = observed | profile.techniques
        jaccard = len(matched) / len(union)
        semantic = max(0.0, float(observed_centroid @ profile.centroid))
        predicted_matches = predicted & profile.techniques
        predicted_support = len(predicted_matches) / len(predicted) if predicted else 0.0
        score = 0.55 * coverage + 0.20 * jaccard + 0.25 * semantic
        # Predictions are optional evidence.  Do not reduce all scores merely
        # because the caller did not supply a next-technique model result.
        if predicted:
            score = (1.0 - predicted_weight) * score + predicted_weight * predicted_support
        results.append(
            {
                "actor": profile.actor,
                "score": float(score),
                "observed_techniques": sorted(observed),
                "observed_matches": sorted(matched),
                "observed_count": len(observed),
                "profile_size": len(profile.techniques),
                "coverage": float(coverage),
                "jaccard": float(jaccard),
                "semantic_similarity": float(semantic),
                "predicted_matches": sorted(predicted_matches),
                "predicted_count": len(predicted),
            }
        )
    results.sort(key=lambda row: (-row["score"], row["actor"]))
    for rank, result in enumerate(results, start=1):
        result["rank"] = rank
        result["justification"] = make_justification(result)
    return results


def make_justification(result: dict) -> str:
    """Create an auditable explanation without claiming causal attribution."""
    text = (
        f"{result['actor']} matches {len(result['observed_matches'])}/{result['observed_count']} "
        f"observed techniques (profile coverage {result['coverage']:.0%}; "
        f"semantic similarity {result['semantic_similarity']:.2f})."
    )
    if result["predicted_count"]:
        text += f" Supporting predicted-technique matches: {len(result['predicted_matches'])}/{result['predicted_count']}."
    return text


def decide_actor_attribution(
    ranked_profiles: list[dict],
    *,
    calibration: AttributionCalibration | None = None,
) -> dict:
    """Return an explicit attributed/unattributed decision with negative evidence.

    Ranking public ATT&CK profiles and identifying an incident's actor are
    different tasks. Zero exact overlap and one-technique evidence always
    abstain. Even stronger overlap remains only a similar profile until score
    and margin thresholds have been calibrated on independently labelled
    incidents rather than partial copies of the same ATT&CK profiles.
    """
    top = ranked_profiles[0] if ranked_profiles else None
    second = ranked_profiles[1] if len(ranked_profiles) > 1 else None
    observed_count = int(top.get("observed_count", 0)) if top else 0
    exact_matches = len(top.get("observed_matches", [])) if top else 0
    score = float(top["score"]) if top else None
    margin = (float(top["score"] - second["score"])
              if top is not None and second is not None else None)
    unmatched = (sorted(set(top.get("observed_techniques", []))
                        - set(top.get("observed_matches", []))) if top else [])

    alternatives = [{
        "rank": int(row.get("rank", index + 1)),
        "actor": row["actor"],
        "score": round(float(row["score"]), 6),
        "exact_match_count": len(row.get("observed_matches", [])),
        "observed_matches": list(row.get("observed_matches", [])),
    } for index, row in enumerate(ranked_profiles[:3])]

    calibrated = bool(
        calibration is not None
        and calibration.independent_incidents > 0
        and calibration.source.strip()
    )
    gate = {
        "calibrated": calibrated,
        "calibration_source": calibration.source if calibrated else None,
        "independent_incident_count": (
            calibration.independent_incidents if calibrated else 0),
        "safety_floor": {
            "minimum_observed_techniques": SAFETY_MIN_OBSERVED,
            "minimum_exact_matches": SAFETY_MIN_EXACT_MATCHES,
        },
        "calibrated_thresholds": ({
            "minimum_observed_techniques": calibration.minimum_observed_techniques,
            "minimum_exact_matches": calibration.minimum_exact_matches,
            "minimum_score": calibration.minimum_score,
            "minimum_margin": calibration.minimum_margin,
        } if calibrated else None),
    }

    reason = None
    if top is None:
        reason = "No ATT&CK group profile could be compared with the observed techniques."
    elif exact_matches == 0:
        reason = (
            "No observed technique exactly matches the highest-ranked public ATT&CK "
            "group profile; semantic similarity alone cannot attribute an actor.")
    elif observed_count < SAFETY_MIN_OBSERVED:
        reason = (
            f"Only {observed_count} observed technique is available. A single common "
            "technique cannot identify a threat actor.")
    elif exact_matches < SAFETY_MIN_EXACT_MATCHES:
        reason = (
            f"Only {exact_matches} observed technique exactly matches the leading "
            "profile; at least two exact matches are required even before calibration.")
    elif not calibrated:
        reason = (
            "Actor attribution is disabled because score and margin thresholds have "
            "not been calibrated on independently labelled incidents. The names below "
            "are similar public ATT&CK profiles only.")
    else:
        minimum_observed = max(
            SAFETY_MIN_OBSERVED, calibration.minimum_observed_techniques)
        minimum_exact = max(SAFETY_MIN_EXACT_MATCHES, calibration.minimum_exact_matches)
        if observed_count < minimum_observed:
            reason = (
                f"The calibration requires {minimum_observed} observed techniques; "
                f"this incident has {observed_count}.")
        elif exact_matches < minimum_exact:
            reason = (
                f"The calibration requires {minimum_exact} exact matches; the leading "
                f"profile has {exact_matches}.")
        elif score < calibration.minimum_score:
            reason = (
                f"The leading score {score:.3f} is below the independently calibrated "
                f"threshold {calibration.minimum_score:.3f}.")
        elif margin is None or margin < calibration.minimum_margin:
            shown_margin = "not available" if margin is None else f"{margin:.3f}"
            reason = (
                f"The top-two margin {shown_margin} does not meet the independently "
                f"calibrated threshold {calibration.minimum_margin:.3f}.")

    attributed = None if reason else {
        "actor": top["actor"],
        "score": round(score, 6),
        "exact_match_count": exact_matches,
        "justification": top["justification"],
    }
    return {
        "status": "attributed" if attributed else "unattributed",
        "attributed_actor": attributed,
        "evidence_count": observed_count,
        "exact_match_count": exact_matches,
        "score": round(score, 6) if score is not None else None,
        "margin": round(margin, 6) if margin is not None else None,
        "alternatives": alternatives,
        "abstention_reason": reason,
        "negative_evidence": {
            "unmatched_observed_techniques": unmatched,
            "zero_exact_overlap": exact_matches == 0,
            "single_technique_only": observed_count < SAFETY_MIN_OBSERVED,
            "independent_calibration_missing": not calibrated,
        },
        "gate": gate,
    }


def evaluate_profiles(
    profiles: dict[str, ActorProfile], embeddings: dict[str, np.ndarray]
) -> dict:
    """Evaluate on real ATT&CK group profiles by withholding 40% per group.

    This measures only whether a public ATT&CK profile can be retrieved from a
    partial version of itself; it must not be presented as an evaluation on
    independent incident telemetry.
    """
    ranks: list[int] = []
    for actor, profile in profiles.items():
        ordered = sorted(profile.techniques)
        if len(ordered) < 2:
            continue
        observed = ordered[: max(1, math.ceil(len(ordered) * 0.60))]
        ranked = rank_actors(observed, profiles, embeddings)
        ranks.append(next(item["rank"] for item in ranked if item["actor"] == actor))
    if not ranks:
        raise ValueError("No ATT&CK group profiles contain enough techniques to evaluate.")
    values = np.asarray(ranks)
    return {
        "groups_evaluated": int(len(values)),
        "top_1": float(np.mean(values <= 1)),
        "top_3": float(np.mean(values <= 3)),
        "mrr": float(np.mean(1.0 / values)),
    }


def load_artifacts() -> tuple[dict[str, ActorProfile], dict[str, np.ndarray]]:
    missing = [path for path in (LOOKUPS, EMBEDDINGS) if not path.exists()]
    if missing:
        names = ", ".join(str(path.relative_to(ROOT)) for path in missing)
        raise FileNotFoundError(f"Missing required real artifact(s): {names}. Run the documented E2 setup first.")
    with LOOKUPS.open("rb") as handle:
        lookups = pickle.load(handle)
    with EMBEDDINGS.open("rb") as handle:
        embeddings = pickle.load(handle)
    vectors = {key: np.asarray(value, dtype="float32") for key, value in embeddings.items()}
    return build_profiles(lookups["group_to_techniques"], vectors), vectors


def main() -> None:
    profiles, embeddings = load_artifacts()
    metrics = evaluate_profiles(profiles, embeddings)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join([
        "# Engine 2.5 — ATT&CK actor-profile similarity and attribution gate",
        "",
        "This is transparent profile retrieval over public ATT&CK group technique usage, not a trained classifier or independent incident-telemetry benchmark.",
        "",
        f"- ATT&CK group profiles: **{len(profiles)}**",
        f"- Groups evaluated using a deterministic 60% observed / 40% withheld profile split: **{metrics['groups_evaluated']}**",
        f"- Top-1 retrieval: **{metrics['top_1']:.1%}**",
        f"- Top-3 retrieval: **{metrics['top_3']:.1%}**",
        f"- Mean reciprocal rank: **{metrics['mrr']:.3f}**",
        "",
        "## Runtime attribution decision",
        "",
        "- Independently labelled incident-attribution benchmark: **not available (0 incidents)**",
        "- Calibrated score and top-two-margin thresholds: **not available**",
        "- Runtime actor attribution: **disabled; returns `unattributed`**",
        "- Safety floors: zero exact overlap always abstains; one observed/common technique always abstains.",
        "- Ranked names are exposed only as **similar public ATT&CK profiles**, with the score, exact evidence count, margin, alternatives, negative evidence and abstention reason.",
        "",
        "The 100% self-profile retrieval result above cannot calibrate attribution: each test row is a partial copy of the same public profile being retrieved, not an independent incident with a verified actor label.",
        "",
        "Scores combine observed-technique coverage (55%), Jaccard overlap (20%), and embedding semantic similarity (25%). Optional Markov next-technique evidence is capped at 20% of the final score.",
    ]), encoding="utf-8")
    print(f"Built {len(profiles)} actor profiles; Top-3={metrics['top_3']:.1%}; -> {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
