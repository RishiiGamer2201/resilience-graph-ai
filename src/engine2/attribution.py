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
        "# Engine 2.5 — ATT&CK actor-profile attribution",
        "",
        "This is transparent profile retrieval over public ATT&CK group technique usage, not a trained classifier or independent incident-telemetry benchmark.",
        "",
        f"- ATT&CK group profiles: **{len(profiles)}**",
        f"- Groups evaluated using a deterministic 60% observed / 40% withheld profile split: **{metrics['groups_evaluated']}**",
        f"- Top-1 retrieval: **{metrics['top_1']:.1%}**",
        f"- Top-3 retrieval: **{metrics['top_3']:.1%}**",
        f"- Mean reciprocal rank: **{metrics['mrr']:.3f}**",
        "",
        "Scores combine observed-technique coverage (55%), Jaccard overlap (20%), and embedding semantic similarity (25%). Optional Markov next-technique evidence is capped at 20% of the final score.",
    ]), encoding="utf-8")
    print(f"Built {len(profiles)} actor profiles; Top-3={metrics['top_3']:.1%}; -> {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
