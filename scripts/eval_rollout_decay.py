"""Measure how rollout accuracy actually decays with horizon, and fit STEP_DECAY.

`src/shared/rollout.py` multiplies a per-step confidence `STEP_DECAY ** (step-1)`
into everything the UI renders. That constant used to be 0.62 with no experiment
behind it. This script is the experiment.

What is measured
----------------
Exactly what the UI renders: for a prefix of a held-out sequence, roll forward
with `simulate_progression` and ask whether the technique that ACTUALLY came at
offset h is in the top-3 the rollout shows at step h. That is top-3 accuracy at
horizon h -- the same metric, and the same top-3 shape, as the published one-step
already published in `reports/prediction_eval.md`.

Where the data comes from
-------------------------
`data/processed/engine2/sequences.json` is gitignored, but it is a pure
deterministic function of the COMMITTED `attack_lookups.pkl` plus a seeded
shuffle (SEED=42), so `build_sequences.build()` reconstructs the identical
train/val/test split the shipped model was trained against. That is verified
here, not assumed: `--verify` re-measures one-step accuracy and checks it lands
on the published numbers before any decay figure is reported.

Fixed population
----------------
Accuracy at every horizon is measured over the SAME set of prefixes -- only
those with at least MAX_H real techniques left to check. Letting the population
shrink with h would confound horizon decay with "long sequences behave
differently", which is a different effect wearing the same shape.

Fit
---
  acc(h) / acc(1) = d ** (h - 1)
least squares on log, anchored at r(1) = 1 (matching `STEP_DECAY ** (step-1)
== 1.0` at step 1). Two things about that anchor and this n are easy to
misreport, so they are computed explicitly here:

  * The REGRESSION has 8 data points (one accuracy per horizon) and 1 free
    parameter. The 544 held-out prefixes are what the 8 accuracies were
    averaged FROM; no prefix is a row in the least squares.
  * The anchor point enters as (0, log(acc[0]/acc[0])) = (0, 0.0). It cannot
    move the slope, but it does enlarge `ss_tot` and so inflates R^2.
    `fit_decay` therefore returns the R^2 over the DECAYING points and the
    inflated anchored one separately, and the report leads with the former.

A linear-space fit on the same ratios is computed alongside for comparison
(`fit_decay_linear`), because it fits those ratios better and picks a different
d -- a fact the report has to state rather than bury.

Because prefixes from one sequence overlap heavily (consecutive prefixes share
7 of their 8 targets), the uncertainty on d is estimated by resampling
SEQUENCES, not prefixes: `bootstrap_d` and `loso_d`.

Run:
    python3 scripts/eval_rollout_decay.py            # measure + write report
    python3 scripts/eval_rollout_decay.py --verify   # just the split check
"""
from __future__ import annotations

import math
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

REPORT = ROOT / "reports" / "rollout_decay.md"

MAX_H = 8          # rollout.MAX_HORIZON -- the furthest step the UI can render
TOP_K = 3          # rollout renders BRANCH_FACTOR=3 predictions per step

BOOT_REPS = 2000   # sequence-level bootstrap replicates
BOOT_SEED = 42     # fixed so the reported interval reproduces byte-identically

# The published one-step figures we must land on before trusting the split.
# top-3 is 38.2% in the report and 38.6% here: runtime ranking breaks model-weight
# ties by technique id, `build_predictor`'s ranker leaves ties in dict order.
# Three prediction points out of 777 land differently. Noted, not papered over.
PUBLISHED = {"n": 777, "oov": 45, "top1": 23.2, "top3": 38.2, "top5": 44.5}


def split():
    """Rebuild the exact train/val/test split the shipped model was trained on."""
    from src.engine2.build_sequences import build
    seqs, stats = build()
    return (
        [s["ordered_technique_ids"] for s in seqs if s["split"] == "train"],
        [s["ordered_technique_ids"] for s in seqs if s["split"] == "test"],
        [s["ordered_technique_ids"] for s in seqs if s.get("is_manual")],
        stats,
    )


def one_step(seqs, vocab) -> tuple[dict, int, int]:
    """Reproduce `build_predictor.eval_ranker`: OOV is a miss, kept in denominator."""
    from src.shared import predictor
    hits, n, oov = {1: 0, 3: 0, 5: 0}, 0, 0
    for s in seqs:
        for i in range(1, len(s)):
            n += 1
            if s[i] not in vocab:
                oov += 1
                continue
            ranked = [t for t, _ in predictor.rank_associations(s[:i], 5)[0]
                      if t in vocab]
            for k in hits:
                hits[k] += s[i] in ranked[:k]
    return {k: 100 * v / n for k, v in hits.items()}, n, oov


def accuracy_from(rows, max_h=MAX_H) -> list[float]:
    """Pool per-sequence [n_prefixes, hits-per-horizon] rows into accuracy per horizon."""
    n = sum(r[0] for r in rows)
    return [100 * sum(r[1][h] for r in rows) / n for h in range(max_h)] if n else []


def horizon_accuracy(seqs, vocab, max_h=MAX_H):
    """Top-3 accuracy of the rendered rollout at each horizon, one fixed population.

    Returns (accuracy per horizon in %, n prefixes, OOV per horizon, per-sequence
    rows). The per-sequence rows exist because the prefixes are NOT independent:
    two consecutive prefixes of one sequence are scored against 7 of the same 8
    ground-truth targets, so any interval on d has to resample sequences.
    """
    from src.shared import predictor
    from src.shared.rollout import simulate_progression
    oov = [0] * max_h
    rows = []
    # Production correctly fails closed because the independent timeline gate
    # is disabled. This historical diagnostic deliberately measures the dormant
    # rollout arithmetic and says so in its report, so open the gate only inside
    # this function and always restore the runtime policy afterwards.
    runtime_gate = predictor.temporal_prediction_status
    predictor.temporal_prediction_status = lambda: {
        "enabled": True,
        "mode": "evaluation-only-profile-rollout",
    }
    try:
        for s in seqs:
            s_hits, s_n = [0] * max_h, 0
            # only prefixes with a full max_h of real continuation to check against
            for i in range(1, len(s) - max_h + 1):
                sim = simulate_progression(s[:i], None, k_steps=max_h)
                if not sim["available"] or len(sim["steps"]) < max_h:
                    continue                 # model produced no trajectory at all
                s_n += 1
                for h in range(1, max_h + 1):
                    truth = s[i + h - 1]
                    if truth not in vocab:
                        oov[h - 1] += 1      # unpredictable; still in the denominator
                        continue
                    top = [p["technique_id"] for p in sim["steps"][h - 1]["predictions"]]
                    s_hits[h - 1] += truth in top[:TOP_K]
            if s_n:
                rows.append([s_n, s_hits])
    finally:
        predictor.temporal_prediction_status = runtime_gate
    return accuracy_from(rows, max_h), sum(r[0] for r in rows), oov, rows


def _r2(pts, log_d) -> float:
    ss_res = sum((y - log_d * h) ** 2 for h, y in pts)
    mean_y = sum(y for _, y in pts) / len(pts)
    ss_tot = sum((y - mean_y) ** 2 for _, y in pts)
    return (1 - ss_res / ss_tot) if ss_tot else float("nan")


def fit_decay(acc: list[float]) -> tuple[float, float, float]:
    """Least-squares d for acc(h)/acc(1) = d**(h-1), anchored at the origin on log scale.

    Returns (d, r2_decay, r2_anchored).

    The regression has ONE free parameter and one point per horizon -- 8 points
    for a full rollout, not one point per prefix. Horizons with zero accuracy
    carry no log and are dropped -- reported in the write-up, not imputed.

    `r2_anchored` includes the anchor (0, 0.0) that `r(1) = 1` contributes by
    construction. That point sits exactly on the line, so it adds nothing to
    `ss_res` while adding its full squared deviation to `ss_tot` -- it inflates
    R^2 without the curve having explained anything. `r2_decay` drops it and is
    the figure that describes how well the curve explains the DECAY. Report
    that one.
    """
    pts = [(h, math.log(a / acc[0])) for h, a in enumerate(acc) if a > 0]
    num = sum(h * y for h, y in pts)
    den = sum(h * h for h, _ in pts) or 1.0
    log_d = num / den
    decaying = pts[1:] if pts and pts[0][0] == 0 else pts
    return math.exp(log_d), _r2(decaying, log_d), _r2(pts, log_d)


def fit_decay_linear(acc: list[float], d_log: float) -> tuple[float, float, float]:
    """The same ratios fitted in LINEAR space instead of log space.

    Returns (d_linear, R^2 of d_linear, R^2 of d_log) -- both R^2 on the linear
    ratio scale, so they are comparable to each other and to nothing else.

    Log space and linear space are different loss functions, not different
    arithmetic for the same answer: log space weights a given RELATIVE error
    equally at every horizon, linear space lets the large early ratios dominate
    and all but ignores the tail. They disagree about d, so the report says so.
    """
    r = [a / acc[0] for a in acc]

    def sse(d):
        return sum((ri - d ** h) ** 2 for h, ri in enumerate(r))

    lo, hi = 0.5, 0.95                       # SSE is unimodal in d over this range
    for _ in range(200):                     # ternary search, deterministic
        a, b = lo + (hi - lo) / 3, hi - (hi - lo) / 3
        lo, hi = (lo, b) if sse(a) < sse(b) else (a, hi)
    d_lin = (lo + hi) / 2
    mean_r = sum(r) / len(r)
    ss_tot = sum((ri - mean_r) ** 2 for ri in r) or 1.0
    return d_lin, 1 - sse(d_lin) / ss_tot, 1 - sse(d_log) / ss_tot


def sse_band(acc, frac=1.05) -> tuple[float, float]:
    """Range of d whose log-space SSE is within `frac` of the minimum.

    The width of this band is the fit's own resolution -- the interval it cannot
    tell apart. Any downstream claim that flips inside it is not a finding.
    """
    pts = [(h, math.log(a / acc[0])) for h, a in enumerate(acc) if a > 0]

    def sse(log_d):
        return sum((y - log_d * h) ** 2 for h, y in pts)

    best = sse(sum(h * y for h, y in pts) / (sum(h * h for h, _ in pts) or 1.0))
    ds = [i / 1000 for i in range(500, 951)
          if sse(math.log(i / 1000)) <= frac * best]
    return min(ds), max(ds)


def bootstrap_d(rows, reps=BOOT_REPS, seed=BOOT_SEED) -> list[float]:
    """Refit d on `reps` resamples of the SEQUENCES, returned sorted.

    Resampling prefixes would be wrong: consecutive prefixes of one sequence
    share 7 of their 8 targets, so they are not independent draws and a
    prefix-level interval would be far too narrow. The 544 prefixes come from
    29 sequence clusters, and 29 is much closer to the effective sample size.
    """
    rng = random.Random(seed)
    out = []
    for _ in range(reps):
        acc = accuracy_from([rng.choice(rows) for _ in rows])
        if acc and acc[0] > 0 and acc[1] > 0:
            out.append(fit_decay(acc)[0])
    return sorted(out)


def loso_d(rows) -> list[float]:
    """Refit d with each sequence left out in turn -- how much one cluster moves it."""
    return [fit_decay(accuracy_from(rows[:i] + rows[i + 1:]))[0]
            for i in range(len(rows))]


def reliable_horizon(d, conf) -> int:
    """The furthest step whose horizon confidence still clears `conf`.

    Mirrors `rollout._headline`, which quotes the last step where
    `d ** (step - 1) >= RELIABLE_CONFIDENCE`.
    """
    h = 1
    while d ** h >= conf:
        h += 1
    return h


def verified_split(quiet=False):
    """Rebuild the split and refuse to hand it back unless it reproduces
    `reports/prediction_eval.md`. This gate is what makes the decay figure mean
    anything: without it the fit could silently be measured on a different corpus."""
    train, test, manual, stats = split()
    vocab = {t for s in train for t in s}
    acc1, n1, oov1 = one_step(test, vocab)
    ok = (n1 == PUBLISHED["n"] and oov1 == PUBLISHED["oov"]
          and abs(acc1[1] - PUBLISHED["top1"]) < 0.5
          and abs(acc1[5] - PUBLISHED["top5"]) < 0.5)
    if not ok:
        raise SystemExit(
            "split does NOT reproduce reports/prediction_eval.md -- the decay fit "
            f"would be measured against a different corpus. got n={n1} oov={oov1} "
            f"top-1 {acc1[1]:.1f} top-5 {acc1[5]:.1f}, expected {PUBLISHED}")
    if not quiet:
        print(f"split rebuilt: {stats['split']} · vocab {len(vocab)}")
        print(f"one-step on test: top-1 {acc1[1]:.1f}% top-3 {acc1[3]:.1f}% "
              f"top-5 {acc1[5]:.1f}% (n={n1}, oov={oov1})")
        print("verified: this split reproduces reports/prediction_eval.md")
    return train, test, manual, vocab, stats, acc1, n1, oov1


def measure(quiet=False) -> dict:
    """Run the whole experiment and return every number the report quotes."""
    from src.shared.rollout import RELIABLE_CONFIDENCE
    train, test, manual, vocab, stats, acc1, n1, oov1 = verified_split(quiet)

    acc, n, oov, rows = horizon_accuracy(test, vocab)
    d, r2, r2_anchored = fit_decay(acc)
    d_lin, r2_lin, r2_lin_of_d_log = fit_decay_linear(acc, d)
    m_acc, m_n, _, _ = horizon_accuracy(manual, vocab, max_h=4)

    boots = bootstrap_d(rows)
    loso = loso_d(rows)
    horizon = reliable_horizon(d, RELIABLE_CONFIDENCE)
    counts = sorted((r[0] for r in rows), reverse=True)
    band_lo, band_hi = sse_band(acc)

    return {
        "stats": stats, "acc1": acc1, "n1": n1, "oov1": oov1,
        "acc": acc, "n": n, "oov": oov, "rows": rows,
        "n_points": sum(1 for a in acc if a > 0),
        "n_seqs": len(rows), "n_test_seqs": len(test),
        "counts": counts, "top5": sum(counts[:5]), "biggest": counts[0],
        "d": d, "r2": r2, "r2_anchored": r2_anchored,
        "d_lin": d_lin, "r2_lin": r2_lin, "r2_lin_of_d_log": r2_lin_of_d_log,
        "boot_lo": boots[int(0.025 * len(boots))],
        "boot_hi": boots[int(0.975 * len(boots))],
        "boot_flip": sum(1 for b in boots
                         if reliable_horizon(b, RELIABLE_CONFIDENCE) == horizon),
        "boot_reps": len(boots),
        "boot_horizons": Counter(reliable_horizon(b, RELIABLE_CONFIDENCE)
                                 for b in boots),
        "loso_lo": min(loso), "loso_hi": max(loso),
        "band_lo": band_lo, "band_hi": band_hi,
        "reliable": RELIABLE_CONFIDENCE, "horizon": horizon,
        "d_min": RELIABLE_CONFIDENCE ** (1 / (horizon - 1)),
        "d_lin_horizon": reliable_horizon(d_lin, RELIABLE_CONFIDENCE),
        "m_acc": m_acc, "m_n": m_n,
    }


def main() -> None:
    from src.shared.rollout import RELIABLE_CONFIDENCE
    if "--verify" in sys.argv:
        verified_split()
        return

    R = measure()
    for h, a in enumerate(R["acc"], 1):
        print(f"  step {h}: top-3 {a:5.1f}%  (ratio {a / R['acc'][0]:.3f}, "
              f"fitted {R['d'] ** (h - 1):.3f})")
    print(f"fitted STEP_DECAY = {R['d']:.4f}  "
          f"(R^2 = {R['r2']:.3f} on the {R['n_points'] - 1} decaying points; "
          f"{R['r2_anchored']:.3f} if the r(1)=1 anchor is counted)")
    print(f"regression: {R['n_points']} points, 1 parameter · "
          f"accuracies averaged over {R['n']} prefixes from {R['n_seqs']} sequences")
    print(f"sequence bootstrap 95%: [{R['boot_lo']:.3f}, {R['boot_hi']:.3f}]  "
          f"LOSO: [{R['loso_lo']:.3f}, {R['loso_hi']:.3f}]")
    print(f"linear-space alternative: d = {R['d_lin']:.4f} "
          f"(R^2_lin {R['r2_lin']:.3f} vs {R['r2_lin_of_d_log']:.3f} for the log fit)")
    print(f"reliable horizon {R['horizon']} needs d >= {R['d_min']:.6f}; "
          f"shipped {round(R['d'], 2)} clears by {round(R['d'], 2) - R['d_min']:.5f} "
          f"({100 * R['boot_flip'] / R['boot_reps']:.0f}% of bootstrap replicates agree)")
    assert RELIABLE_CONFIDENCE == R["reliable"]

    write_report(R)
    print(f"-> {REPORT.relative_to(ROOT)}")


def write_report(R) -> None:
    acc, d, n = R["acc"], R["d"], R["n"]
    stats = R["stats"]
    rows = "\n".join(
        f"| {h} | {a:.1f}% | {a / acc[0]:.3f} | {d ** (h - 1):.3f} | "
        f"{a / acc[0] - d ** (h - 1):+.3f} | {R['oov'][h - 1]} |"
        for h, a in enumerate(acc, 1))
    manual_line = (
        "top-3 at steps 1-4: " + " · ".join(f"{a:.1f}%" for a in R["m_acc"])
        + f" (n = {R['m_n']} prefixes)") if R["m_acc"] else (
        "no prefix was long enough to roll 4 steps")
    shipped = round(d, 2)
    boot_pct = 100 * R["boot_flip"] / R["boot_reps"]
    boot_dist = "\n".join(
        f"| step {h} | {c} | {100 * c / R['boot_reps']:.1f}% |"
        for h, c in sorted(R["boot_horizons"].items()))
    boot_dist = ("| reliable horizon | replicates | share |\n|---|---|---|\n"
                 + boot_dist)

    REPORT.write_text(f"""# Profile-association rollout diagnostic -- not a chronological forecast

> **Runtime status: disabled.** These measurements roll forward ATT&CK profiles
> sorted by a tactic heuristic, not observed attacker timelines. They describe
> how quickly that profile-position ranking degrades; they do not validate what
> an attacker will do next. `src/shared/predictor.py` keeps chronological output
> disabled until an independent timeline benchmark beats temporal baselines.

`src/shared/rollout.py` renders a horizon confidence of `STEP_DECAY ** (step-1)`
only after the temporal gate passes. This is the historical diagnostic behind
that otherwise-dormant constant.

**Result: fitted `{d:.4f}`, shipped as `STEP_DECAY = {shipped}`** (was `0.62`,
which had no experiment behind it). The fit is a regression with **{R['n_points']} data points and
1 free parameter** -- one top-3 accuracy per horizon -- and those {R['n_points']} accuracies were
each averaged over **{n} held-out prefixes drawn from {R['n_seqs']} test sequences**.
R² = **{R['r2']:.3f}** on the decaying points of the log-ratio fit.

Those are three different numbers and they are not interchangeable:

| number | what it is |
|---|---|
| **{R['n_points']}** | data points in the regression -- its actual n |
| **{n}** | held-out prefixes the {R['n_points']} accuracies were averaged from; never a row in the fit |
| **{R['n_seqs']}** | sequences those {n} prefixes come from -- the closest thing here to an effective sample size |

Earlier versions of this report printed "n = {n}" wherever a regression's n
belongs -- in this file, in the `STEP_DECAY` comment block, and in the
`method.decay` string that ships in the API payload. That overstated the
regression's n by a factor of {n // R['n_points']}. `fit_decay()` takes one argument, a list of
{R['n_points']} accuracies; no prefix count enters the least squares at any point.

Shipped rounded to 2dp on purpose: `src/shared/rollout.py` renders this number to
the user, and the sequence-level bootstrap below puts the 95% interval at
[{R['boot_lo']:.3f}, {R['boot_hi']:.3f}] -- a spread of {R['boot_hi'] - R['boot_lo']:.2f}. The extra digits would be precision the
experiment did not earn. **Read "The reliable horizon is a coin flip" below
before quoting anything downstream of this constant**, because the rounding to
{shipped} is what keeps the reliable horizon at step {R['horizon']}, by {shipped - R['d_min']:.5f}.

## What was measured

For each prefix of a held-out sequence, `simulate_progression` is rolled forward
{MAX_H} steps and asked: is the technique that ACTUALLY came at offset *h* among the
top-{TOP_K} the rollout renders at step *h*? That is the same metric and the same
top-3 shape as the published one-step {PUBLISHED['top3']:.1f}%, extended along the horizon -- so
step 1 here is directly comparable to the number the module already cites.

Accuracy at every horizon is measured over **the same fixed set of prefixes** --
only those with at least {MAX_H} real techniques left to check against. A shrinking
population would mix horizon decay with "long sequences behave differently".

That restriction moves the step-1 number: **{acc[0]:.1f}%** here versus {R['acc1'][3]:.1f}% over
all {R['n1']} prediction points, because prefixes near the end of a sequence (and every
sequence shorter than {MAX_H + 1}) are excluded. Only the *ratios* feed the fit, so this
does not bias the decay -- but it does mean {acc[0]:.1f}% is not a new headline accuracy
and must not be quoted as one. The headline stays {PUBLISHED['top3']:.1f}%.

## Provenance of the data

`data/processed/engine2/sequences.json` is gitignored, but it is a deterministic
function of the committed `data/processed/mitre_attack/attack_lookups.pkl` and a
seeded shuffle (`SEED = 42` in `src/engine2/build_sequences.py`), so the split is
reconstructable from committed artifacts alone. `scripts/eval_rollout_decay.py`
**verifies** the reconstruction before reporting any decay figure -- it re-runs the
one-step evaluation and refuses to continue unless it lands on
`reports/prediction_eval.md`:

| | published | reproduced here |
|---|---|---|
| sequences | 205 (140/30/35) | {stats['n_sequences']} ({stats['split']['train']}/{stats['split']['val']}/{stats['split']['test']}) |
| prediction points | {PUBLISHED['n']} | {R['n1']} |
| OOV (counted as misses) | {PUBLISHED['oov']} | {R['oov1']} |
| top-1 | {PUBLISHED['top1']:.1f}% | {R['acc1'][1]:.1f}% |
| top-3 | {PUBLISHED['top3']:.1f}% | {R['acc1'][3]:.1f}% |
| top-5 | {PUBLISHED['top5']:.1f}% | {R['acc1'][5]:.1f}% |

top-3 differs by 0.4pp -- three prediction points out of {R['n1']}. Runtime association
ranking breaks model-weight ties by technique id; `build_predictor`'s ranker leaves tied
techniques in dict order. Same corpus, same model, different coin-flip on ties.

This split verification is genuinely non-circular and it is the part of this
report to trust most: the reconstruction is checked against numbers published
before it, and the script exits rather than reporting a decay figure if it misses.

## Measured decay

| step | top-3 accuracy | observed ratio to step 1 | fitted `{d:.4f}^(h-1)` | residual | OOV at this offset |
|---|---|---|---|---|---|
{rows}

Fit: least squares for `acc(h)/acc(1) = d^(h-1)` on the log scale, anchored at
`r(1) = 1` so it matches how the constant is used (`STEP_DECAY ** (step-1)` is
exactly 1.0 at step 1). **These {R['n_points']} rows are the entire regression.**

## Fit quality -- read this before quoting the number

### R² = {R['r2']:.3f}, not {R['r2_anchored']:.3f}

The anchored fit passes through `(h=0, log(acc[0]/acc[0])) = (0, 0.0)` by
construction. That point is a tautology: it is the definition of the ratio, not
an observation. It cannot move the slope -- it contributes zero to both the
numerator and the denominator of the least-squares estimate, which is why `d` is
**identical** either way -- but it sits exactly on the line while lying far from
the mean of the y values, so it adds nothing to `ss_res` and about 1.07 to
`ss_tot`. That is R² inflation with no explanatory work behind it.

| R² on the log-ratio scale | value |
|---|---|
| counting the `r(1) = 1` anchor (previously reported) | {R['r2_anchored']:.3f} |
| **on the {R['n_points'] - 1} decaying points only (reported now)** | **{R['r2']:.3f}** |

The anchor stays *in the fit* -- it is a real constraint, the curve genuinely
must pass through 1.0 at step 1 -- but it is out of the reported R², because the
question R² answers here is "how well does this curve explain the decay?", and
the anchor is not part of the decay.

### A linear-space fit does better and picks a different d

The same {R['n_points']} ratios, least-squares in linear space rather than log space:

| fit | d | R² on the linear ratio scale |
|---|---|---|
| **log space (shipped)** | **{d:.4f}** | {R['r2_lin_of_d_log']:.3f} |
| linear space | {R['d_lin']:.4f} | **{R['r2_lin']:.3f}** |

On the ratio scale the data are actually measured on, the linear fit is the
better one. Log space was kept anyway, and the reason is not that it fits better:

- The constant is **used** multiplicatively (`STEP_DECAY ** (step-1)`), so the
  error that matters is relative, not absolute. Log space weights a 10% relative
  miss the same at step 8 as at step 2; linear space weights step 2's absolute
  residual roughly 5x harder than step 8's and effectively stops fitting the tail
  -- which is exactly the region the constant exists to discount.
- Linear space would make the tail nearly unconstrained, and the tail is where a
  forecast misleads.

That is a defensible choice, not an obviously correct one, and it is worth
knowing that **the choice of fit space, not the data, is what decides d here** --
by more than the sequence bootstrap's own resolution. It also changes the
downstream story: at d = {R['d_lin']:.4f} the reliable horizon is step {R['d_lin_horizon']}, not step {R['horizon']}. See below.

### The {n} prefixes are not {n} independent observations

They come from **{R['n_seqs']} of the {R['n_test_seqs']} test sequences** (the other {R['n_test_seqs'] - R['n_seqs']} are shorter than {MAX_H + 1}
techniques and contribute nothing), and they are distributed very unevenly:

- the largest single sequence supplies **{R['biggest']} of {n}** prefixes,
- the top 5 sequences supply **{R['top5']} of {n} ({100 * R['top5'] / n:.0f}%)**.

Worse, prefixes *within* a sequence overlap almost completely: two consecutive
prefixes of the same sequence are scored against 7 of the same 8 ground-truth
targets. Treating {n} as a sample size would be treating {n} heavily-overlapping
views of {R['n_seqs']} sequences as {n} independent draws. **The effective sample size is
closer to the ~{R['n_seqs']} sequence clusters than to {n}**, and the top-heavy distribution
means even {R['n_seqs']} is generous.

So the interval below is computed by resampling **sequences**, not prefixes:

| estimate | d |
|---|---|
| point estimate | {d:.4f} |
| sequence bootstrap, 95% ({R['boot_reps']} replicates, seed {BOOT_SEED}) | **[{R['boot_lo']:.3f}, {R['boot_hi']:.3f}]** |
| leave-one-sequence-out, full spread | [{R['loso_lo']:.3f}, {R['loso_hi']:.3f}] |

The bootstrap interval is wide -- **{R['boot_hi'] - R['boot_lo']:.2f} wide, on a quantity whose entire useful
range is about 0.6 to 0.9** -- but it is not so noisy as to be useless: it rules
out d below ~0.72 and above ~0.81, and it is the honest width to attach to the
2dp shipped value. The leave-one-sequence-out spread is much narrower, which is
what you would expect when one dropped cluster out of {R['n_seqs']} is being replaced by
nothing rather than by a resample; the bootstrap is the figure to quote.

### The reliable horizon is a coin flip -- read this before quoting step {R['horizon']}

`src/shared/rollout.py` sets `RELIABLE_CONFIDENCE = {R['reliable']}` and quotes the
furthest step whose confidence still clears it. That makes step {R['horizon']} reliable exactly
when `d^{R['horizon'] - 1} >= {R['reliable']}`, i.e. when `d >= {R['reliable']}^(1/{R['horizon'] - 1}) = {R['d_min']:.6f}`.

    shipped d       = {shipped}
    d^{R['horizon'] - 1}             = {shipped ** (R['horizon'] - 1):.5f}
    threshold       = {R['reliable']}
    margin          = {shipped - R['d_min']:.5f}

**The claim "the reliable horizon moved from step 3 to step {R['horizon']}" rests on {shipped - R['d_min']:.5f}.**

That margin is far smaller than the fit's own resolution, in every direction we
can measure it:

| perturbation | d | reliable horizon |
|---|---|---|
| shipped | {shipped} | {R['horizon']} |
| raw fitted | {d:.4f} | {reliable_horizon(d, R['reliable'])} |
| bootstrap 2.5% | {R['boot_lo']:.3f} | {reliable_horizon(R['boot_lo'], R['reliable'])} |
| bootstrap 97.5% | {R['boot_hi']:.3f} | {reliable_horizon(R['boot_hi'], R['reliable'])} |
| linear-space fit | {R['d_lin']:.4f} | {R['d_lin_horizon']} |
| one 2dp tick down | {shipped - 0.01:.2f} | {reliable_horizon(shipped - 0.01, R['reliable'])} |

Across the {R['boot_reps']} sequence-bootstrap replicates the reliable horizon lands:

{boot_dist}

**Step {R['horizon']} wins {boot_pct:.1f}% of the time and step {R['horizon'] - 1} wins {100 * R['boot_horizons'][R['horizon'] - 1] / R['boot_reps']:.1f}%.** That is a coin flip. And any d in
[{R['band_lo']:.3f}, {R['band_hi']:.3f}] is within 5% of the minimum SSE -- that band is the fit's own
resolution, and it **straddles** the flip point {R['d_min']:.4f} rather than sitting on one
side of it. The flip is inside the interval the fit cannot resolve.

This same report justifies rounding to 2dp on the grounds that the extra digits
would be "precision the experiment did not earn". That cannot stand alongside an
unqualified step-{R['horizon']} claim: `{shipped}` versus `{R['d_min']:.4f}` is a difference in the *third*
decimal, decided by the *fourth*. If the 4th significant figure is not earned,
neither is any conclusion that turns on it. The qualified version, which is what
should be quoted:

> The measured decay is gentler than the made-up 0.62 it replaced, and under it
> the reliable horizon is **plausibly** step {R['horizon']} rather than step 3 -- but step {reliable_horizon(R['boot_lo'], R['reliable'])} is
> about equally consistent with the same data, and picking the linear-space fit
> instead would give step {R['d_lin_horizon']}. The horizon moved *somewhere north of 3*. Which
> side of {R['horizon']} it lands on is not established by this experiment.

`RELIABLE_CONFIDENCE` was deliberately left at {R['reliable']} rather than retuned after this
measurement, which is the right call -- moving a threshold to preserve a
conclusion is what this file exists to avoid. But it does mean the threshold and
the fitted constant now sit {shipped - R['d_min']:.5f} apart, and nothing about that gap is robust.

### Shape and circularity

- A geometric decay is a *model choice*, not something the data forced on us. The
  residual column shows where it fits badly. Real decay is steepest between steps
  1 and 2 and then flattens, because a rollout that survives its first step has
  usually locked onto a sequence the model has genuinely seen. A single geometric
  constant cannot express that shape and under-states the early drop.
- The held-out sequences are ordered by the ATT&CK kill-chain tactic heuristic
  (see `src/engine2/build_sequences.py`), so some of the retained accuracy at
  longer horizons is the ordering being re-learned rather than real transitions.
  The decay is a *ratio* to step 1 on the same corpus, so this largely cancels --
  but it does not fully cancel, and the true decay is plausibly steeper.

## ⚠️ The caveat that matters most

Non-circular cross-check on the 4 hand-verified CERT-In sequences
(`data/manual/cert_in_sequences.json`, ordered by the real reported timeline
rather than by the kill-chain heuristic): **{manual_line}**.

Read that honestly: on the only genuinely non-circular data in the repo, this
rollout has **no measurable skill past step 1**. Accuracy does not decay at
d = {shipped} there -- it goes to zero. n = {R['m_n']} prefixes from 4 sequences is far too small
to fit a decay curve on, which is exactly why the shipped constant is fitted on
the held-out split instead. But it is not too small to be a warning,
and it points the same way as the bullets above: **{shipped} is an upper bound on how
well this holds up, not a central estimate.**

The one-step CERT-In figure already published in `reports/prediction_eval.md`
(11.1% top-3, versus 38.2% on the auto split) says the same thing at h = 1. This
measurement extends that gap along the horizon rather than resolving it. Getting
a trustworthy multi-step decay needs more hand-verified report-ordered sequences;
until then, treat any step beyond the first as a lead to check, never a forecast.

## What this constant does and does not mean

It is the measured rate at which THIS model's top-3 accuracy falls off as the
horizon grows, on the same held-out split that produced the 38.2% headline. It is
not a probability that a forecast is correct, and it is not a confidence interval.
It is a decay rate with an experiment behind it, which is the whole and only claim.

Regenerate: `python3 scripts/eval_rollout_decay.py`
""", encoding="utf-8")


if __name__ == "__main__":
    main()
