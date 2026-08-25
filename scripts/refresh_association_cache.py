"""Refresh only model-claim fields in the committed API cache.

The full cache build replays a large scenario and fetches live threat feeds. A
change to predictor semantics must not rewrite graph topology, OSINT timestamps,
or unrelated detector output. This targeted refresh preserves those values while
replacing stale chronological language with the artifact-gated association view.
"""
from __future__ import annotations

import json
from pathlib import Path

from scripts.build_cache import methodology
from src.shared import predictor
from src.shared.rollout import simulate_progression

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "api" / "cache"


def _read(name: str) -> dict:
    return json.loads((CACHE / f"{name}.json").read_text(encoding="utf-8"))


def _write(name: str, value: dict) -> None:
    (CACHE / f"{name}.json").write_text(
        json.dumps(value, indent=2), encoding="utf-8")
    print(f"refreshed api/cache/{name}.json")


def _refresh_tree(value):
    if isinstance(value, list):
        return [_refresh_tree(item) for item in value]
    if isinstance(value, str):
        return (value
                .replace("Next-technique (interpolated Markov)",
                         "Technique association (interpolated Markov)")
                .replace("Top prediction:", "Top association:")
                .replace("[orchestrator] Prediction ", "[orchestrator] Candidate ")
                .replace(" is not a plausible Markov transition from observed chain",
                         " is not a ranked ATT&CK profile association"))
    if not isinstance(value, dict):
        return value

    out = {key: _refresh_tree(item) for key, item in value.items()}
    source = out.get("source")
    if isinstance(source, str) and source.startswith("markov-interpolated-"):
        out["source"] = source.replace("markov-interpolated-", "profile-association-")
    if (str(out.get("source", "")).startswith("profile-association-")
            and "probability" in out):
        out["association_score"] = out.pop("probability")
    if out.get("confidence_flag") == "markov_inconsistent":
        out["confidence_flag"] = "profile_association_inconsistent"

    chain = out.get("technique_chain_used")
    predictions = out.get("predictions")
    if isinstance(chain, list) and isinstance(predictions, list) and "projection_narrative" in out:
        out["projection_narrative"] = predictor.generate_prediction_narrative(
            predictions, chain)
        out["mode"] = "association-only"
        out["temporal_prediction"] = predictor.temporal_prediction_status()

    forecast = out.get("progression_forecast")
    if isinstance(forecast, dict) and forecast.get("observed_chain"):
        out["progression_forecast"] = simulate_progression(
            forecast["observed_chain"], k_steps=forecast.get("k_steps", 5))
    return out


def main() -> None:
    overview = _refresh_tree(_read("overview"))
    report = _read("report")
    status = predictor.temporal_prediction_status()
    report["technique_association_basis"] = {
        "mode": "association-only",
        "data_basis": status.get("data_basis"),
        "temporal_prediction_enabled": status.get("enabled", False),
        "reason": status.get("reason"),
    }
    _write("overview", overview)
    _write("report", report)
    _write("metrics", json.loads(
        (ROOT / "reports" / "metrics.json").read_text(encoding="utf-8")))
    _write("methodology", methodology())


if __name__ == "__main__":
    main()
