"""
Evaluate the network-state world model against the baselines that could
embarrass it.

The SIH problem statement asks for transition dynamics over network state and
for a forecast of attacker progression. A transition model is only worth
shipping if it beats the two things that need no model at all:

  persistence   S_t+1 = S_t. Network traffic is autocorrelated, so this is a
                strong baseline and the one most sequence models quietly lose to.
  marginal      ignore S_t entirely and predict the most common next state.

and, for the infiltration probability specifically:

  prevalence    always predict the training-set attack rate. Beating this on
                Brier score is the minimum bar for the forecast to mean anything.

Trained on Monday-Wednesday, tested on Thursday-Friday: a temporal split, so no
attack burst appears on both sides. Thursday is 0.6% attack and Friday is 26%,
so the test set is a genuinely different traffic mix from the training days.

    ./.venv/Scripts/python.exe -m scripts.eval_netstate
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from src.engine3.netstate import (
    MODEL,
    OnlineTracker,
    N_STATES,
    STATE_DIM,
    TEST_DAYS,
    TRAIN_DAYS,
    WINDOW,
    NetStateModel,
    build_observations,
    fit,
    load_flows,
)

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "netstate.md"
HORIZON = 5


def next_state_accuracy(model: NetStateModel, obs) -> dict:
    """Next-state accuracy for the counted matrix, the persistence-interpolated
    matrix, and the two baselines.

    All four are reported. The counted matrix loses to persistence on this
    split, which is exactly why the interpolated variant exists; reporting only
    the winner would hide the finding that motivated it.
    """
    marginal_top = int(model.transitions.mean(axis=0).argmax())
    raw, interp = model.transitions, model.transition_matrix()

    c = dict(raw1=0, raw3=0, int1=0, int3=0, persist=0, marg=0, total=0)
    for _, states, _ in obs:
        lat = model.encode(states)
        for a, b in zip(lat[:-1], lat[1:]):
            ro = np.argsort(raw[a])[::-1]
            io = np.argsort(interp[a])[::-1]
            c["raw1"] += int(ro[0] == b)
            c["raw3"] += int(b in ro[:3])
            c["int1"] += int(io[0] == b)
            c["int3"] += int(b in io[:3])
            c["persist"] += int(a == b)
            c["marg"] += int(marginal_top == b)
            c["total"] += 1
    n = c["total"]
    return {
        "n_transitions": n,
        "counted_top1": round(c["raw1"] / n, 4),
        "counted_top3": round(c["raw3"] / n, 4),
        "model_top1": round(c["int1"] / n, 4),
        "model_top3": round(c["int3"] / n, 4),
        "persistence_top1": round(c["persist"] / n, 4),
        "marginal_top1": round(c["marg"] / n, 4),
        "persistence_weight": model.persistence_weight,
    }


def online_accuracy(model: NetStateModel, obs) -> dict:
    """Causal online adaptation: predict the next state, then observe it.

    The tracker may count every transition strictly before the current window
    and nothing after. That is what a sensor genuinely has, it needs no labels,
    and it is the difference between the offline prior and the oracle.

    The oracle here is a first-order matrix counted on the TEST days and scored
    on them. It cheats on purpose: it is the ceiling for any first-order model
    over these latent states, so it says whether the remaining gap is model
    capacity or irreducible noise.
    """
    hit = tot = 0
    for _, states, _ in obs:
        lat = model.encode(states)
        if len(lat) < 2:
            continue
        t = OnlineTracker(model)
        t.observe(states[0])
        for i in range(1, len(lat)):
            hit += int(t.next_distribution().argmax() == lat[i])
            tot += 1
            t.observe(states[i])

    oracle_counts = _oracle_matrix(model, obs)
    oh = ot = 0
    arg = oracle_counts.argmax(axis=1)
    for _, states, _ in obs:
        lat = model.encode(states)
        for a, b in zip(lat[:-1], lat[1:]):
            oh += int(arg[a] == b)
            ot += 1

    return {
        "online_top1": round(hit / max(tot, 1), 4),
        "n_transitions": tot,
        "prior_strength": model.online_prior_strength,
        "oracle_top1": round(oh / max(ot, 1), 4),
    }


def _oracle_matrix(model: NetStateModel, obs) -> np.ndarray:
    """Deliberately counted on the evaluation data. Ceiling only, never shipped."""
    from src.engine3.netstate import LAPLACE
    K = model.n_states
    c = np.full((K, K), LAPLACE)
    for _, states, _ in obs:
        lat = model.encode(states)
        for a, b in zip(lat[:-1], lat[1:]):
            c[a, b] += 1
    return c / c.sum(axis=1, keepdims=True)


def second_order_check(model: NetStateModel, train_obs, test_obs) -> dict:
    """A second-order model was the obvious first thing to try. It is worse.

    Recorded rather than dropped, because 'we tried momentum and it lost' is
    information and a reader would otherwise reasonably ask why we did not.
    """
    from src.engine3.netstate import LAPLACE
    K = model.n_states
    c2 = np.full((K, K, K), LAPLACE)
    for _, states, _ in train_obs:
        lat = model.encode(states)
        for a, b, d in zip(lat[:-2], lat[1:-1], lat[2:]):
            c2[a, b, d] += 1
    P2 = c2 / c2.sum(axis=2, keepdims=True)

    hit = tot = 0
    for _, states, _ in test_obs:
        lat = model.encode(states)
        for a, b, d in zip(lat[:-2], lat[1:-1], lat[2:]):
            hit += int(P2[a, b].argmax() == d)
            tot += 1
    return {"order2_top1": round(hit / max(tot, 1), 4), "n": tot}


def forecast_calibration(model: NetStateModel, obs, *, horizon: int = HORIZON) -> dict:
    """Brier score of the k-step-ahead attack-rate forecast.

    Truth is the actual attack rate of the window k ahead, so this scores the
    forecast as a probability, not as a classification.

    TWO baselines, because one of them is easy and one is not:

      prevalence    always predict the training attack rate. Beating this is the
                    minimum bar for the forecast to mean anything at all.
      persistence   predict the CURRENT window's attack rate for the window k
                    ahead. Traffic is autocorrelated, so this is the hard one --
                    the same reason `next_state_accuracy` scores against
                    persistence rather than against a uniform guess. Reporting
                    only the prevalence baseline here while holding next-state
                    to persistence would be grading two parts of one model on
                    two different curves.
    """
    prior = float(model.state_attack_rate @ (model.state_support / model.state_support.sum()))

    per_step: list[dict] = []
    for k in range(1, horizon + 1):
        errs, base_errs, persist_errs, n = 0.0, 0.0, 0.0, 0
        for _, states, rates in obs:
            if len(states) <= k:
                continue
            lat = model.encode(states)
            Tk = np.linalg.matrix_power(model.transition_matrix(), k)
            pred = Tk[lat[:-k]] @ model.state_attack_rate
            truth = rates[k:]
            errs += float(((pred - truth) ** 2).sum())
            base_errs += float(((prior - truth) ** 2).sum())
            persist_errs += float(((rates[:-k] - truth) ** 2).sum())
            n += len(truth)
        if n:
            per_step.append({
                "step": k,
                "brier_model": round(errs / n, 5),
                "brier_prevalence_baseline": round(base_errs / n, 5),
                "brier_persistence_baseline": round(persist_errs / n, 5),
                "n": n,
            })
    return {"prior": round(prior, 5), "per_step": per_step}


def compromise_detection(model: NetStateModel, obs, *, threshold: float = 0.5) -> dict:
    """One-step-ahead: does the model warn before a compromised window arrives?

    A window counts as compromised when more than `threshold` of its flows carry
    an attack label. Reported as ROC-AUC so no operating point is smuggled in.

    Scored against PERSISTENCE, not against random. This function used to report
    ROC-AUC 0.9872 with 0.5 as the implied comparison, which is the wrong
    reference class and flattered the model by roughly the whole distance that
    matters. Traffic is autocorrelated and attacks arrive in bursts, so 'the
    current window is compromised' already predicts 'the next window is
    compromised' very well, and any forecaster has to beat that, not a coin.
    The same argument is why `next_state_accuracy` scores against persistence;
    it simply was never applied here.

    Two persistence variants, because they answer different questions:

      persistence_binary   score = 1 if the CURRENT window is compromised. This
                           is literally 'assume no change'.
      persistence_rate     score = the current window's attack rate, continuous.
                           A strictly stronger ranker than the binary form, and
                           therefore the harder baseline of the two.
    """
    preds, truths, cur_rates = [], [], []
    for _, states, rates in obs:
        if len(states) < 2:
            continue
        lat = model.encode(states)
        preds.extend(model.transition_matrix()[lat[:-1]] @ model.state_attack_rate)
        truths.extend((rates[1:] > threshold).astype(int))
        cur_rates.extend(rates[:-1])
    y, p, cur = np.array(truths), np.array(preds), np.array(cur_rates)
    if len(set(y.tolist())) < 2:
        return {"state": "not measured",
                "why": "the test windows contain only one class at this threshold"}
    from sklearn.metrics import average_precision_score, roc_auc_score

    persist_bin = (cur > threshold).astype(float)
    out = {
        "n_windows": int(len(y)),
        "compromised_windows": int(y.sum()),
        "roc_auc": round(float(roc_auc_score(y, p)), 4),
        "pr_auc": round(float(average_precision_score(y, p)), 4),
        "persistence_rate_roc_auc": round(float(roc_auc_score(y, cur)), 4),
        "persistence_rate_pr_auc": round(float(average_precision_score(y, cur)), 4),
        "persistence_binary_roc_auc": round(float(roc_auc_score(y, persist_bin)), 4),
        "threshold": threshold,
    }
    out["beats_persistence"] = out["roc_auc"] > out["persistence_rate_roc_auc"]
    out["roc_auc_lift_over_persistence"] = round(
        out["roc_auc"] - out["persistence_rate_roc_auc"], 4)
    return out


def sweep_state_count(train_obs, test_obs, counts=(8, 16, 24, 32, 48)) -> list[dict]:
    """K is a modelling choice; show it was measured rather than guessed.

    Selected on FORECAST quality, not on next-state top-1. Top-1 over K classes
    is not comparable across K -- fewer states is an easier prediction, so that
    metric monotonically prefers the smallest K and would keep preferring it all
    the way down to two states. Brier and ROC-AUC score the thing the model is
    for: how likely the next window is to be compromised.
    """
    out = []
    for k in counts:
        m = fit(train_obs, n_states=k, window=WINDOW)
        acc = next_state_accuracy(m, test_obs)
        cal = forecast_calibration(m, test_obs, horizon=1)
        det = compromise_detection(m, test_obs)
        out.append({"n_states": k,
                    "top1": acc["model_top1"],
                    "counted_top1": acc["counted_top1"],
                    "persistence_top1": acc["persistence_top1"],
                    "persistence_weight": acc["persistence_weight"],
                    "brier_1step": cal["per_step"][0]["brier_model"],
                    "roc_auc": det.get("roc_auc")})
    return out


def write_report(m: dict) -> None:
    acc, cal, det = m["next_state"], m["calibration"], m["compromise_detection"]
    beats = acc["model_top1"] > acc["persistence_top1"]
    step1 = cal["per_step"][0]
    cal_beats = step1["brier_model"] < step1["brier_prevalence_baseline"]

    verdict = []
    verdict.append(
        f"**The counted transition matrix LOSES to persistence: "
        f"{acc['counted_top1']:.1%} against {acc['persistence_top1']:.1%}.** "
        f"Network traffic is strongly autocorrelated and the transition "
        f"structure learned on the training days does not fully transfer to a "
        f"different traffic mix. That is the finding, not a footnote: a "
        f"transition matrix that cannot beat 'assume no change' is not a "
        f"forecaster yet."
    )
    on = m["online"]
    o2 = m["second_order"]
    online_gap = on["online_top1"] - acc["persistence_top1"]
    gap = acc["model_top1"] - acc["persistence_top1"]
    if gap > 0.01:
        standing = f"clears persistence by {gap * 100:.1f} points"
    elif gap >= -0.01:
        standing = (f"draws level with persistence, {abs(gap) * 100:.1f} points "
                    f"{'above' if gap >= 0 else 'below'} it")
    else:
        standing = f"is still {abs(gap) * 100:.1f} points behind persistence"

    verdict.append(
        f"**Interpolating the two closes most of that gap: {acc['model_top1']:.1%} "
        f"top-1 and {acc['model_top3']:.1%} top-3, which {standing}.** The weight "
        f"is {acc['persistence_weight']}, chosen by leave-one-day-out over the "
        f"training days -- count on two, score on the third -- because the real "
        f"difficulty is transferring to a day with a different attack mix, and a "
        f"holdout taken from inside a day never poses that question. Two weaker "
        f"protocols were tried first and both picked a weight that did not "
        f"transfer; `src/engine3/netstate.py` records what they were and why they "
        f"were wrong. The same interpolation is what made engine2's "
        f"next-technique predictor work."
    )
    if gap <= 0.01:
        verdict.append(
            "**Offline, then, the next-state forecast matches a persistence "
            "baseline rather than beating one.** Two things were tried before "
            f"concluding that. A second-order context, which is the obvious "
            f"candidate because an order-1 matrix cannot tell 'we have been "
            f"sitting in state B' from 'we just arrived in B from A': it scored "
            f"{o2['order2_top1']} alone against the order-1 matrix's "
            f"{acc['counted_top1']}, and leave-one-day-out gave it a weight of "
            f"zero. And an oracle first-order matrix, counted on the test days "
            f"themselves: {on['oracle_top1']}. The oracle beats persistence by "
            f"{(on['oracle_top1'] - acc['persistence_top1']) * 100:.1f} points, "
            f"so a first-order model over these latent states CAN win. Ours does "
            f"not. The limit is transfer between days, not model capacity."
        )
    verdict.append(
        f"**Adapting online closes {'most of' if online_gap > 0.01 else 'none of'} "
        f"that gap: {on['online_top1']:.1%} against persistence at "
        f"{acc['persistence_top1']:.1%}"
        + (f", {online_gap * 100:+.1f} points**." if online_gap > 0.01
           else "**.") +
        f" Transfer is fixable at deployment and needs no labels: traffic "
        f"arrives, you observe its transitions, so you may count them. "
        f"`OnlineTracker` predicts the next state and only then is told what "
        f"happened, blending the offline prior in as {on['prior_strength']} "
        f"pseudo-counts so it dominates early in a stream and hands over as "
        f"evidence accumulates. Strictly causal: nothing after the current "
        f"window contributes. That puts it "
        f"{(on['oracle_top1'] - on['online_top1']) * 100:.1f} points off the "
        f"cheating oracle. Hyperparameters were fitted leave-one-day-out on the "
        f"training days; a version read off the test days scored 0.4243, and the "
        f"smaller honest number is the one reported."
    )
    persist_beats = step1["brier_model"] < step1["brier_persistence_baseline"]
    verdict.append(
        f"**Infiltration forecast: the model {'beats' if cal_beats else 'LOSES to'} "
        f"the prevalence baseline at one step, and {'beats' if persist_beats else 'LOSES to'} "
        f"persistence.** Brier {step1['brier_model']} against "
        f"{step1['brier_prevalence_baseline']} for always predicting the training "
        f"attack rate of {cal['prior']:.4f}, and against "
        f"{step1['brier_persistence_baseline']} for predicting the current window's "
        f"attack rate unchanged. Persistence is the baseline that matters here: "
        f"traffic is autocorrelated, so carrying the last observation forward is "
        f"already a real forecaster."
    )
    if det.get("roc_auc") is not None:
        pr_roc = det["persistence_rate_roc_auc"]
        verdict.append(
            f"**One-step-ahead compromise warning: ROC-AUC {det['roc_auc']}, "
            f"against a persistence baseline of {pr_roc}.** "
            f"PR-AUC {det['pr_auc']} against {det['persistence_rate_pr_auc']}, over "
            f"{det['n_windows']:,} test windows of which "
            f"{det['compromised_windows']:,} were compromised. The model "
            f"{'beats' if det['beats_persistence'] else 'LOSES to'} persistence by "
            f"{det['roc_auc_lift_over_persistence']:+.4f} ROC-AUC. "
            f"This is the model warning about the NEXT window from the current one, "
            f"not classifying the window in front of it."
        )
        verdict.append(
            "**On the reference class.** An earlier version of this report compared "
            "the compromise warning against random, 0.5, which is the wrong baseline "
            "and made the result look far stronger than it is. Attacks arrive in "
            "bursts, so 'the current window is compromised' already predicts the next "
            "one well. Persistence is the honest comparison, and it is the same "
            "baseline next-state prediction is held to a few rows above."
        )

    lines = [
        "# Network-state world model", "",
        "A transition model over observed traffic state, `P(S_t+1 | S_t)`, as",
        "distinct from `src/engine2`, which learns transitions between ATT&CK",
        "techniques. Written for SIH 2026 requirement 2.", "",
        f"- Dataset: CIC-IDS2017, {m['n_flows_train']:,} training flows over "
        f"{', '.join(TRAIN_DAYS)} and {m['n_flows_test']:,} test flows over "
        f"{', '.join(TEST_DAYS)}",
        f"- State: {STATE_DIM} dimensions (mean and standard deviation of "
        f"{STATE_DIM // 2} flow features) per window of {WINDOW} consecutive flows",
        f"- Windows: {m['n_windows_train']:,} training, {m['n_windows_test']:,} test",
        f"- Model: {N_STATES} latent states, Laplace-smoothed transition matrix, "
        f"exact matrix rollout",
        "- Split: temporal. No day appears on both sides, so no attack burst is "
        "learned and then scored.", "",
        "## Results", "",
        "| Metric | Model | Best baseline | Baseline |",
        "|---|---|---|---|",
        f"| Next-state top-1, counted matrix | {acc['counted_top1']} | "
        f"{acc['persistence_top1']} | persistence |",
        f"| Next-state top-1, interpolated (shipped) | {acc['model_top1']} | "
        f"{max(acc['persistence_top1'], acc['marginal_top1'])} | "
        f"{'persistence' if acc['persistence_top1'] >= acc['marginal_top1'] else 'marginal'} |",
        f"| Next-state top-3, interpolated | {acc['model_top3']} | n/a | |",
        f"| Next-state top-1, marginal | {acc['marginal_top1']} | n/a | ignores S_t |",
        f"| **Next-state top-1, online adaptive** | **{m['online']['online_top1']}** | "
        f"{acc['persistence_top1']} | persistence |",
        f"| Next-state top-1, second order | {m['second_order']['order2_top1']} | "
        f"{acc['persistence_top1']} | persistence |",
        f"| Next-state top-1, ORACLE (cheats) | {m['online']['oracle_top1']} | "
        f"{acc['persistence_top1']} | ceiling for any order-1 model |",
        f"| Attack-rate Brier @ 1 step | {step1['brier_model']} | "
        f"{step1['brier_persistence_baseline']} | persistence (carry rate forward) |",
        f"| Attack-rate Brier @ 1 step | {step1['brier_model']} | "
        f"{step1['brier_prevalence_baseline']} | always predict prevalence |",
    ]
    if det.get("roc_auc") is not None:
        lines += [
            f"| **Next-window compromise ROC-AUC** | **{det['roc_auc']}** | "
            f"{det['persistence_rate_roc_auc']} | persistence (current attack rate) |",
            f"| Next-window compromise ROC-AUC | {det['roc_auc']} | "
            f"{det['persistence_binary_roc_auc']} | persistence (assume no change) |",
            f"| Next-window compromise PR-AUC | {det['pr_auc']} | "
            f"{det['persistence_rate_pr_auc']} | persistence (current attack rate) |",
        ]
    lines += ["", "## Verdict", ""] + [f"- {v}" for v in verdict] + [""]

    lines += ["## Forecast calibration by horizon", "",
              "| Steps ahead | Brier, model | Brier, persistence | Brier, prevalence | Windows |",
              "|---|---|---|---|---|"]
    for s in cal["per_step"]:
        lines.append(f"| {s['step']} | {s['brier_model']} | "
                     f"{s['brier_persistence_baseline']} | "
                     f"{s['brier_prevalence_baseline']} | {s['n']:,} |")

    best = min(m["state_sweep"], key=lambda r: r["brier_1step"])
    lines += ["", "## Choosing the number of latent states", "",
              "K was measured, not picked, and selected on **forecast quality**.",
              "Next-state top-1 is not comparable across K -- fewer states is an",
              "easier prediction, so that column falls monotonically and would keep",
              "recommending a smaller K down to two states, which forecasts nothing.",
              "Each row's top-1 is therefore shown against its own persistence",
              "baseline, which shifts with K for the same reason.", "",
              "| Latent states | Brier @ 1 step | Next-window ROC | Top-1 | Persistence top-1 | Weight |",
              "|---|---|---|---|---|---|"]
    for r in m["state_sweep"]:
        mark = " **(shipped)**" if r["n_states"] == N_STATES else ""
        lines.append(f"| {r['n_states']}{mark} | {r['brier_1step']} | {r['roc_auc']} | "
                     f"{r['top1']} | {r['persistence_top1']} | {r['persistence_weight']} |")
    lines += ["",
              f"Best Brier in the sweep is K={best['n_states']} at "
              f"{best['brier_1step']}; we ship K={N_STATES}"
              + ("." if best["n_states"] == N_STATES else
                 f" at {next(r['brier_1step'] for r in m['state_sweep'] if r['n_states'] == N_STATES)}. "
                 f"If the difference matters for your use, change N_STATES in "
                 f"src/engine3/netstate.py and re-run this script."),
              "",
              "Note that top-1 sits at or just under the persistence baseline at",
              "every K. That consistency is the point: it is a property of the",
              "traffic, not an artefact of one choice of K."]

    lines += ["", "## What the latent states mean", "",
              "The reason for quantising rather than fitting a black box: a state",
              "can be printed. Distinguishing features are in training standard",
              "deviations from the mean window.", ""]
    for s in m["example_states"]:
        feats = ", ".join(f"{f['feature']} {f['direction']} ({f['z_score']:+})"
                          for f in s["distinguishing_features"][:3])
        lines.append(f"- **State {s['state']}** — attack rate {s['attack_rate']}, "
                     f"{s['training_windows']:,} training windows. {feats}")

    lines += ["", "## What this does not do", "",
              "- **Not packet-level.** CIC-IDS2017 ships flow records. TTL variance,",
              "  fragment flags and retransmission counts are not in the data, so",
              "  SIH requirement 7 stays open.",
              "- **No addresses or ports.** This parquet carries flow statistics only,",
              "  so active-flow count and unique-port count are absent from the state",
              "  vector even though the problem statement names them.",
              "- **Not CTU-13 or CIC-IDS2018.** The problem statement lists CIC-IDS2017",
              "  as acceptable, but names the other two first.",
              "- **Flow order is assumed chronological.** It is the order CIC-IDS2017",
              "  ships and there is no timestamp column to verify it against. Windows",
              "  are never formed across a day boundary.", ""]
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    print("loading flows ...")
    df = load_flows(TRAIN_DAYS + TEST_DAYS)
    train_df = df[df["day"].isin(TRAIN_DAYS)]
    test_df = df[df["day"].isin(TEST_DAYS)]

    train_obs = build_observations(train_df, TRAIN_DAYS)
    test_obs = build_observations(test_df, TEST_DAYS)
    n_tr = sum(len(s) for _, s, _ in train_obs)
    n_te = sum(len(s) for _, s, _ in test_obs)
    print(f"  {n_tr:,} training windows, {n_te:,} test windows")

    print("fitting ...")
    model = fit(train_obs, trained_on=", ".join(TRAIN_DAYS))
    model.save()
    print(f"  wrote {MODEL.relative_to(ROOT)}")

    print("evaluating ...")
    acc = next_state_accuracy(model, test_obs)
    cal = forecast_calibration(model, test_obs)
    det = compromise_detection(model, test_obs)
    on = online_accuracy(model, test_obs)
    o2 = second_order_check(model, train_obs, test_obs)
    sweep = sweep_state_count(train_obs, test_obs)

    interesting = np.argsort(model.state_attack_rate)[::-1][:3].tolist()
    interesting += np.argsort(model.state_attack_rate)[:1].tolist()
    examples = [model.describe_state(int(s)) for s in interesting]

    m = {
        "dataset": "CIC-IDS2017",
        "train_days": TRAIN_DAYS, "test_days": TEST_DAYS,
        "n_flows_train": int(len(train_df)), "n_flows_test": int(len(test_df)),
        "n_windows_train": n_tr, "n_windows_test": n_te,
        "window": WINDOW, "n_states": N_STATES, "state_dim": STATE_DIM,
        "next_state": acc, "calibration": cal, "compromise_detection": det,
        "online": on, "second_order": o2,
        "state_sweep": sweep, "example_states": examples,
    }
    write_report(m)
    print(f"  wrote {REPORT.relative_to(ROOT)}")

    from src.shared.metrics_store import update
    update("engine3", "netstate", {
        "next_state_top1": acc["model_top1"],
        "next_state_top3": acc["model_top3"],
        "counted_matrix_top1": acc["counted_top1"],
        "persistence_weight": acc["persistence_weight"],
        "online_top1": on["online_top1"],
        "online_prior_strength": on["prior_strength"],
        "oracle_top1": on["oracle_top1"],
        "second_order_top1": o2["order2_top1"],
        "persistence_top1": acc["persistence_top1"],
        "marginal_top1": acc["marginal_top1"],
        "brier_1step": cal["per_step"][0]["brier_model"],
        "brier_1step_baseline": cal["per_step"][0]["brier_prevalence_baseline"],
        "brier_1step_persistence": cal["per_step"][0]["brier_persistence_baseline"],
        "compromise_roc_auc": det.get("roc_auc"),
        "compromise_pr_auc": det.get("pr_auc"),
        "compromise_persistence_roc_auc": det.get("persistence_rate_roc_auc"),
        "compromise_persistence_pr_auc": det.get("persistence_rate_pr_auc"),
        "compromise_beats_persistence": det.get("beats_persistence"),
        "compromise_lift_over_persistence": det.get("roc_auc_lift_over_persistence"),
        "n_states": N_STATES, "window": WINDOW, "state_dim": STATE_DIM,
        "n_windows_test": n_te,
    })
    print("  updated reports/metrics.json")

    print(f"\ntop-1 offline {acc['model_top1']:.4f} · online {on['online_top1']:.4f} "
          f"· persistence {acc['persistence_top1']:.4f} · oracle {on['oracle_top1']:.4f}"
          f" | brier {cal['per_step'][0]['brier_model']} vs "
          f"{cal['per_step'][0]['brier_prevalence_baseline']}"
          f" | next-window ROC {det.get('roc_auc')}")


if __name__ == "__main__":
    main()
