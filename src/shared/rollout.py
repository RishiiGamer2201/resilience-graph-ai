"""Forward simulation: roll the attack forward K steps and say where it goes.

Everything before this module answers "what happened?". This one answers "what
happens next, and how sure are we as the horizon grows?" — by rolling the
learned transition model forward instead of predicting a single next step.

The transition model already exists and is already measured: the interpolated
Markov in `src/shared/predictor.py` estimates P(next | previous, last) over real
ATT&CK sequences, at 38.1% top-3 against a 7.1% kill-chain baseline
(`reports/prediction_eval.md`). This module does the part that was missing —
beam search over that distribution to produce a trajectory rather than a guess:

  * a per-step distribution over predicted techniques,
  * the most likely continuation paths with their path probabilities,
  * a cumulative probability of reaching an IMPACT-stage technique within K,
  * which crown jewels that trajectory would put in reach, from the real graph,
  * and the honest bit: confidence decays with horizon, and the module reports
    the decay instead of quoting step-8 probabilities as if they meant anything.

Deterministic: same chain, same graph, same output. No sampling, no model
opinion — the probabilities are the Markov's own transition estimates.

    from src.shared.rollout import simulate_progression
    sim = simulate_progression(["T1078", "T1021"], graph_view, k_steps=5)
    sim["infiltration_probability"][2]     # P(impact stage) within 3 steps
"""
from __future__ import annotations

import pickle
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"

# Tactics that mean the intrusion has achieved its objective. Reaching one of
# these is what "infiltration completed" means for the probability timeline.
IMPACT_TACTICS = {"impact", "exfiltration", "collection"}

# Beam search parameters. Small on purpose: the transition model is trained on
# 205 sequences, and a wide beam over a sparse model manufactures confident
# nonsense in the tail.
BEAM_WIDTH = 5
BRANCH_FACTOR = 3
MAX_HORIZON = 8

# Per-step confidence decay. A model measured at 38.1% top-3 for ONE step is not
# 38.1% accurate eight steps out; compounding uncertainty is the dominant term
# and pretending otherwise is the main way a forecast misleads.
STEP_DECAY = 0.62

# Below this horizon confidence a forecast is not worth quoting as a headline.
# The peak cumulative probability always sits at the LAST step, where confidence
# is lowest — reporting it would mean leading with the least reliable number the
# model produces ("99.7% chance of impact", at confidence 0.15).
RELIABLE_CONFIDENCE = 0.35

_state: dict = {}


def _lookups() -> dict:
    if "lk" not in _state:
        with LOOKUPS.open("rb") as f:
            _state["lk"] = pickle.load(f)
    return _state["lk"]


def _tactics_of(tid: str) -> list[str]:
    return _lookups().get("technique_to_tactics", {}).get(tid, [])


def _name_of(tid: str) -> str:
    return _lookups().get("technique_to_name", {}).get(tid, tid)


def _is_impact(tid: str) -> bool:
    return bool(set(_tactics_of(tid)) & IMPACT_TACTICS)


def _stage_of(tid: str) -> str:
    """The ATT&CK stage a predicted technique belongs to, for the timeline."""
    tac = _tactics_of(tid)
    return tac[0].replace("-", " ") if tac else "unmapped"


def simulate_progression(technique_ids: list[str], graph: dict | None = None,
                         k_steps: int = 5, *,
                         crown_jewels: list[str] | None = None) -> dict:
    """Roll the attack forward `k_steps` and describe the trajectory.

    `technique_ids` is the chain observed so far. `graph` is the incident's
    attack graph, used to say which crown jewels a predicted progression would
    actually put in reach — a technique the attacker cannot route to is a
    different risk from one they can.
    """
    from src.shared import predictor

    k_steps = max(1, min(int(k_steps), MAX_HORIZON))
    observed = [t for t in (technique_ids or []) if t and t != "-"]
    if not observed:
        return {
            "available": False,
            "reason": "no observed techniques yet, so there is nothing to roll forward",
            "k_steps": k_steps,
        }

    # beam of (path_suffix, cumulative_probability)
    beam: list[tuple[list[str], float]] = [([], 1.0)]
    steps: list[dict] = []
    reached_impact = 0.0
    cumulative: list[float] = []

    for step in range(1, k_steps + 1):
        next_beam: list[tuple[list[str], float]] = []
        step_mass: dict[str, float] = {}

        for suffix, p_path in beam:
            chain = observed + suffix
            try:
                ranked, source = predictor.rank_next(chain, BRANCH_FACTOR)
            except Exception:
                ranked, source = [], "unavailable"
            for tid, p in ranked:
                p_next = p_path * float(p)
                step_mass[tid] = step_mass.get(tid, 0.0) + p_next
                next_beam.append((suffix + [tid], p_next))

        if not next_beam:
            break

        next_beam.sort(key=lambda x: -x[1])
        beam = next_beam[:BEAM_WIDTH]

        # Normalise the step distribution before reading anything off it. Beam
        # search prunes, so the surviving paths' probabilities do not sum to 1;
        # taking the raw impact mass reported 0.4% when the real answer is "what
        # share of the modelled next states at this step are impact-stage".
        total_mass = sum(step_mass.values()) or 1.0
        step_mass = {tid: m / total_mass for tid, m in step_mass.items()}
        impact_now = sum(m for tid, m in step_mass.items() if _is_impact(tid))
        # cumulative "at least once by step k", treating steps as the model's
        # own successive estimates rather than independent trials
        reached_impact = reached_impact + (1.0 - reached_impact) * min(1.0, impact_now)
        confidence = round(STEP_DECAY ** (step - 1), 4)
        # Probability and confidence are reported SEPARATELY, per ADR 0006.
        # Multiplying them made the cumulative curve fall (17.7 -> 14.2 -> 9.2),
        # which is nonsense: the chance of having reached impact BY step k cannot
        # decrease as k grows. What decreases is how much the estimate is worth.
        cumulative.append(round(100 * reached_impact, 1))

        top = sorted(step_mass.items(), key=lambda x: (-x[1], x[0]))[:BRANCH_FACTOR]
        steps.append({
            "step": step,
            "horizon_confidence": confidence,
            "predictions": [{
                "technique_id": tid,
                "name": _name_of(tid),
                "stage": _stage_of(tid),
                "probability": round(mass, 4),
                "is_impact": _is_impact(tid),
            } for tid, mass in top],
            "impact_mass": round(impact_now, 4),
            "model_source": source,
        })

    paths = [{
        "path": observed + suffix,
        "predicted": suffix,
        "probability": round(p, 5),
        "stages": [_stage_of(t) for t in suffix],
        "reaches_impact": any(_is_impact(t) for t in suffix),
    } for suffix, p in beam[:BEAM_WIDTH]]

    exposure = _exposure_if_progressed(graph, crown_jewels)

    return {
        "available": True,
        "observed_chain": observed,
        "k_steps": k_steps,
        "steps": steps,
        "infiltration_probability": cumulative,
        "horizon_confidence": [s["horizon_confidence"] for s in steps],
        "peak_infiltration_probability": max(cumulative) if cumulative else 0.0,
        **_headline(steps, cumulative),
        "confidence_at_peak": (steps[cumulative.index(max(cumulative))]["horizon_confidence"]
                               if cumulative else 0.0),
        "most_likely_paths": paths,
        "reachable_crown_jewels": exposure,
        "method": {
            "model": "interpolated Markov over 205 real ATT&CK sequences",
            "search": f"beam search, width {BEAM_WIDTH}, branch {BRANCH_FACTOR}",
            "decay": (f"horizon confidence {STEP_DECAY}^(step-1): a model measured at "
                      f"38.1% top-3 for one step is not 38.1% accurate {k_steps} "
                      f"steps out, and the timeline says so"),
            "deterministic": True,
        },
        "honesty": (
            "These are the transition model's own probabilities rolled forward, not "
            "a simulation of an attacker's intent. Step 1 rests on a measured 38.1% "
            "top-3 accuracy; every step after that compounds the same uncertainty, "
            "which is why horizon confidence decays and the later steps are shown "
            "faded rather than quoted as forecasts."),
    }


def _headline(steps: list[dict], cumulative: list[float]) -> dict:
    """The number to lead with: the furthest step still worth quoting.

    Cumulative probability always peaks at the final step, where horizon
    confidence is lowest. Leading with the peak would mean leading with the
    least reliable figure in the forecast.
    """
    if not steps:
        return {"reliable_horizon": 0, "headline_probability": 0.0,
                "headline_confidence": 0.0,
                "headline": "no forecast could be produced"}
    idx = 0
    for i, st in enumerate(steps):
        if st["horizon_confidence"] >= RELIABLE_CONFIDENCE:
            idx = i
    horizon = steps[idx]["step"]
    prob = cumulative[idx]
    conf = steps[idx]["horizon_confidence"]
    stage = steps[idx]["predictions"][0]["stage"] if steps[idx]["predictions"] else "unknown"
    return {
        "reliable_horizon": horizon,
        "headline_probability": prob,
        "headline_confidence": conf,
        "headline": (f"{prob}% chance of reaching an impact stage within {horizon} "
                     f"step(s), at horizon confidence {conf}. Most likely next "
                     f"stage: {stage}."),
        "beyond_horizon_note": (
            f"Steps past {horizon} are shown but not quoted: horizon confidence "
            f"falls below {RELIABLE_CONFIDENCE} and the cumulative curve rises "
            f"toward 100% mainly because the model keeps rolling, not because "
            f"the outcome becomes certain."),
    }


def _exposure_if_progressed(graph: dict | None,
                            crown_jewels: list[str] | None) -> dict:
    """Which crown jewels the CURRENT graph already puts within reach.

    Deliberately conservative: this reports reachability the attack graph
    actually shows, not hosts a predicted technique might hypothetically unlock.
    Inventing future topology would be exactly the fabrication this codebase
    refuses elsewhere.
    """
    if not graph:
        return {"available": False,
                "reason": "no attack graph supplied with the rollout"}
    at_risk = list(graph.get("critical_assets_at_risk") or [])
    designated = sorted(set(crown_jewels or [])) or at_risk
    paths = graph.get("paths_to_critical") or {}
    return {
        "available": True,
        "designated": designated,
        "already_reachable": sorted(at_risk),
        "not_yet_reachable": sorted(set(designated) - set(at_risk)),
        "shortest_paths": {k: v for k, v in paths.items()},
        "note": ("Reachability is measured from the observed graph. A predicted "
                 "technique does not create new topology here — we do not invent "
                 "hosts the attacker has not touched."),
    }


def demo() -> None:
    """Self-check: a rollout produces a decaying, deterministic trajectory."""
    graph = {"critical_assets_at_risk": ["DB"],
             "paths_to_critical": {"DB": ["PC", "JUMP", "DB"]}}
    sim = simulate_progression(["T1078", "T1021"], graph, k_steps=5,
                               crown_jewels=["DB", "DC"])
    assert sim["available"], sim
    assert len(sim["steps"]) == 5, len(sim["steps"])

    # horizon confidence must strictly decay
    conf = [s["horizon_confidence"] for s in sim["steps"]]
    assert conf == sorted(conf, reverse=True) and conf[0] > conf[-1], conf

    # cumulative infiltration probability must be monotone non-decreasing:
    # the chance of having reached impact BY step k cannot fall as k grows
    cum = sim["infiltration_probability"]
    assert cum == sorted(cum), f"cumulative probability decreased: {cum}"

    # every predicted technique is a real ATT&CK id with a stage
    for s in sim["steps"]:
        for p in s["predictions"]:
            assert p["technique_id"].startswith("T"), p
            assert p["stage"], p

    # deterministic
    again = simulate_progression(["T1078", "T1021"], graph, k_steps=5,
                                 crown_jewels=["DB", "DC"])
    assert again == sim, "rollout is not deterministic"

    # nothing observed -> nothing forecast
    empty = simulate_progression([], graph, k_steps=3)
    assert empty["available"] is False

    ex = sim["reachable_crown_jewels"]
    assert ex["already_reachable"] == ["DB"] and ex["not_yet_reachable"] == ["DC"]

    assert sim["reliable_horizon"] >= 1
    assert sim["headline_confidence"] >= RELIABLE_CONFIDENCE
    assert sim["headline_probability"] <= sim["peak_infiltration_probability"]

    print(f"rollout ok: {len(sim['steps'])} steps, "
          f"headline {sim['headline_probability']}% @ step "
          f"{sim['reliable_horizon']} (conf {sim['headline_confidence']}), "
          f"peak {sim['peak_infiltration_probability']}%, "
          f"confidence {conf[0]} -> {conf[-1]}, "
          f"top path {sim['most_likely_paths'][0]['predicted']}")


if __name__ == "__main__":
    demo()
