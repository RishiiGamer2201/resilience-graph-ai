"""Forward simulation: roll the attack forward K steps and say where it goes.

Everything before this module answers "what happened?". This one answers "what
happens next, and how sure are we as the horizon grows?" -- by rolling the
learned transition model forward instead of predicting a single next step.

The transition model already exists and is already measured: the interpolated
Markov in `src/shared/predictor.py` estimates P(next | previous, last) over real
ATT&CK sequences, at 38.1% top-3 against a 7.1% kill-chain baseline
(`reports/prediction_eval.md`). This module does the part that was missing --
beam search over that distribution to produce a trajectory rather than a guess:

  * a per-step distribution over predicted techniques,
  * the most likely continuation paths with their path probabilities,
  * a cumulative probability of reaching an IMPACT-stage technique within K,
  * which crown jewels that trajectory would put in reach, from the real graph,
  * and the honest bit: confidence decays with horizon, and the module reports
    the decay instead of quoting step-8 probabilities as if they meant anything.
    The decay RATE is itself measured -- this module's own top-3 accuracy at each
    horizon, fitted and reproducible (`reports/rollout_decay.md`,
    `scripts/eval_rollout_decay.py`). It was a made-up 0.62 until that experiment
    was run. The fit is small (8 points, 1 parameter, from 544 prefixes in 29
    sequences) and the report states what it does and does not support.

Deterministic: same chain, same graph, same output. No sampling, no model
opinion -- the probabilities are the Markov's own transition estimates.

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

# Per-step confidence decay -- MEASURED, see `reports/rollout_decay.md`.
#
# A model measured at 38.1% top-3 for ONE step is not 38.1% accurate eight steps
# out, and compounding uncertainty is the main way a forecast misleads. That much
# was always true; the constant expressing it used to be 0.62, which no experiment
# produced. `scripts/eval_rollout_decay.py` is now that experiment: it rolls this
# module forward over held-out sequences and asks how often the technique that
# ACTUALLY came at offset h is in the top-3 rendered at step h.
#
#   step:  1      2      3      4      5      6      7      8
#   top-3: 45.0%  30.0%  22.4%  14.3%  15.1%  11.8%   9.9%   9.7%
#
# Fitting acc(h)/acc(1) = d^(h-1) gives d = 0.7726, shipped rounded to 0.77.
#
# Three different n's, none of them interchangeable -- the report used to print
# the middle one wherever a regression's n belongs, which overstated the fit 68x:
#   * 8   data points in the regression (one accuracy per horizon), 1 free
#     parameter. This is the fit's actual n. `fit_decay()` takes a list of 8
#     accuracies and nothing else.
#   * 544 held-out prefixes the 8 accuracies were averaged FROM. Not rows in the
#     least squares.
#   * 29  test sequences those 544 prefixes come from. Consecutive prefixes of one
#     sequence share 7 of their 8 targets and the top 5 sequences supply 57% of
#     the prefixes, so ~29 is far closer to the effective sample size than 544.
#     Resampling SEQUENCES puts the 95% interval on d at [0.720, 0.804].
#
# R^2 = 0.739 on the 7 decaying points. (0.870 if the r(1)=1 anchor is counted,
# which is what was reported before -- that point is (0, log(acc[0]/acc[0])) = 0
# by construction, so it cannot move the slope but does inflate ss_tot. It stays
# in the fit as a real constraint; it stays out of the quoted R^2.)
#
# Honest limits, in full in the report, and the last one is serious:
#   * A single geometric constant cannot express the real shape -- steep from step
#     1 to 2, then flattening -- so it under-states the early drop.
#   * Log space is a CHOICE. A linear-space fit on the same ratios gives d = 0.7407
#     and fits those ratios better (R^2 0.942 vs 0.914 on that scale). Log space is
#     kept because the constant is used multiplicatively, so relative error is what
#     matters -- but the fit space, not the data, is what decides the 2nd decimal.
#   * The held-out sequences are kill-chain-ordered, so part of the accuracy
#     retained at long horizons is that ordering being re-learned. On the 4
#     hand-verified CERT-In sequences (report-ordered, the only non-circular data
#     here) the rollout scores 5.6% at step 1 and 0.0% at steps 2-4. n = 18 is far
#     too small to fit anything, but it is large enough to be a warning: 0.77 is an
#     UPPER BOUND on how well this holds up, not a central estimate.
# This is a measured decay rate with a reproducible experiment behind it -- not a
# probability that any given forecast is right.
STEP_DECAY = 0.77

# Below this horizon confidence a forecast is not worth quoting as a headline.
# The peak cumulative probability always sits at the LAST step, where confidence
# is lowest -- reporting it would mean leading with the least reliable number the
# model produces ("99.7% chance of impact", at confidence 0.15).
#
# Left at 0.35 through the re-measurement above rather than retuned, because
# moving a threshold to preserve a conclusion is the thing this file exists to
# avoid. This threshold is a stated editorial line, not a measured one.
#
# Consequence worth knowing, WITH its sensitivity, because the two must be quoted
# together: the measured decay (0.77) is gentler than the made-up 0.62 it replaced,
# so the reliable horizon moved from step 3 to step 5 -- but that "5" is decided by
# a margin of 0.00084 and is not a robust finding.
#
#     step 5 is reliable iff d^4 >= 0.35, i.e. d >= 0.35^(1/4) = 0.769161
#     shipped d = 0.77  ->  0.77^4 = 0.35153  ->  clears by 0.00084
#
# Any d in [0.765, 0.780] is within 5% of the fit's minimum SSE, and that band
# straddles 0.769161. Of 2000 sequence-level bootstrap replicates, 52.5% give
# step 5 and 46.2% give step 4 -- as does the linear-space fit (d = 0.7407), and
# as would rounding one 2dp tick down to 0.76. The fit cannot resolve the side.
#
# So: the horizon moved somewhere NORTH OF 3. "3 to 5" is the point estimate, not
# an established result, and it must not be quoted as one -- the same report that
# ships this constant also says the fit does not earn four significant figures,
# and this conclusion turns on the fourth. See reports/rollout_decay.md.
#
# Callers were asking for exactly 5, which made the headline the LAST step and
# collapsed it onto the peak the guard exists to hold back. That was fixed by
# asking for more steps than we intend to quote (see FORECAST_HORIZON), not by
# lowering this number until the answer looked better -- and note that
# FORECAST_HORIZON = 8 leaves headroom whether the true horizon is 4 or 5.
RELIABLE_CONFIDENCE = 0.35

# How many steps callers roll. Deliberately further than the reliable horizon,
# which at STEP_DECAY 0.77 and RELIABLE_CONFIDENCE 0.35 is step 5 -- though see
# above: that 5 clears its threshold by 0.00084 and could as easily be 4. 8 leaves
# headroom either way, which is part of why it is not pinned to the horizon.
#
# `_headline` leads with the furthest step still worth quoting rather than the
# peak, and the peak is always the last step. That distinction only exists if
# there ARE steps beyond the reliable horizon, so a caller asking for exactly 5
# silently collapses the headline onto the peak and the guard stops guarding.
#
# It lives here, next to the decay it depends on, because it was previously a
# bare 5 written separately in workflow.py and enrich.py -- two magic numbers
# that had to agree and had nothing keeping them in agreement. A parity test
# caught them disagreeing the moment one changed.
FORECAST_HORIZON = 8

# Above this cumulative probability the headline stops quoting a precise figure.
#
# `infiltration_probability` is a noisy-OR across rollout branches, so it climbs
# toward 100 whenever a few steps carry real probability and it stays there. On
# the AIIMS scenario it runs 44.9, 91.2, 99.0, 99.5, 99.7 and then flat. The 99.7
# is a property of combining probabilities over five steps, not evidence that
# compromise is 99.7% likely, and printing it as a headline is exactly the kind
# of overclaim the rest of this file exists to prevent.
#
# `beyond_horizon_note` already said this about steps PAST the reliable horizon.
# It is just as true at the horizon itself, so the headline now says it there.
SATURATION = 95.0

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
    actually put in reach -- a technique the attacker cannot route to is a
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
                      f"steps out, and the timeline says so. {STEP_DECAY} is fitted, "
                      f"not chosen -- top-3 accuracy of this rollout measured at each "
                      f"of {MAX_HORIZON} horizons and fitted with 1 free parameter, so "
                      f"{MAX_HORIZON} points in the regression; those {MAX_HORIZON} "
                      f"accuracies were averaged over 544 held-out prefixes from 29 "
                      f"test sequences, which overlap heavily, so ~29 is nearer the "
                      f"effective sample size and a sequence-level bootstrap puts d in "
                      f"[0.720, 0.804]. R^2 0.739 on the decaying points (0.870 if the "
                      f"r(1)=1 anchor is counted, which explains nothing). A "
                      f"linear-space fit of the same ratios gives 0.7407. "
                      f"(reports/rollout_decay.md, reproduce with "
                      f"scripts/eval_rollout_decay.py)"),
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
    saturated = prob >= SATURATION
    return {
        "reliable_horizon": horizon,
        "headline_probability": prob,
        "headline_confidence": conf,
        "headline_saturated": saturated,
        "headline": (
            (f"Reaching an impact stage within {horizon} step(s) is near-certain "
             f"under this model ({prob}%), at horizon confidence {conf}. Treat the "
             f"figure as saturated rather than precise: the cumulative curve is a "
             f"noisy-OR over rollout branches and passes "
             f"{SATURATION}% by design once a few steps carry real probability. "
             f"The informative parts here are the horizon and the stage, not the "
             f"percentage. Most likely next stage: {stage}.")
            if saturated else
            (f"{prob}% chance of reaching an impact stage within {horizon} "
             f"step(s), at horizon confidence {conf}. Most likely next "
             f"stage: {stage}.")),
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
                 "technique does not create new topology here -- we do not invent "
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
