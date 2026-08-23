# Rollout horizon decay -- measured, not assumed

`src/shared/rollout.py` renders a horizon confidence of `STEP_DECAY ** (step-1)`
on every forecast. This is the measurement behind that constant.

**Result: fitted `0.7726`, shipped as `STEP_DECAY = 0.77`** (was `0.62`,
which had no experiment behind it), fitted on **n = 544 held-out prefixes**,
R² = **0.870** on the log-ratio fit.

Shipped rounded to 2dp on purpose: a fit at R² = 0.870 over 544 prefixes does not
support four significant figures, and `src/shared/rollout.py` renders this number
to the user. The extra digits would be precision the experiment did not earn.

## What was measured

For each prefix of a held-out sequence, `simulate_progression` is rolled forward
8 steps and asked: is the technique that ACTUALLY came at offset *h* among the
top-3 the rollout renders at step *h*? That is the same metric and the same
top-3 shape as the published one-step 38.1%, extended along the horizon -- so
step 1 here is directly comparable to the number the module already cites.

Accuracy at every horizon is measured over **the same fixed set of prefixes** --
only those with at least 8 real techniques left to check against. A shrinking
population would mix horizon decay with "long sequences behave differently".

That restriction moves the step-1 number: **45.0%** here versus 38.5% over
all 780 prediction points, because prefixes near the end of a sequence (and every
sequence shorter than 9) are excluded. Only the *ratios* feed the fit, so this
does not bias the decay -- but it does mean 45.0% is not a new headline accuracy
and must not be quoted as one. The headline stays 38.1%.

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
| sequences | 205 (140/30/35) | 205 (140/30/35) |
| prediction points | 780 | 780 |
| OOV (counted as misses) | 45 | 45 |
| top-1 | 23.1% | 23.1% |
| top-3 | 38.1% | 38.5% |
| top-5 | 44.4% | 44.4% |

top-3 differs by 0.4pp -- three prediction points out of 780. `predictor.rank_next`
breaks probability ties by technique id; `build_predictor`'s ranker leaves tied
techniques in dict order. Same corpus, same model, different coin-flip on ties.

## Measured decay

| step | top-3 accuracy | observed ratio to step 1 | fitted `0.7726^(h-1)` | residual | OOV at this offset |
|---|---|---|---|---|---|
| 1 | 45.0% | 1.000 | 1.000 | +0.000 | 25 |
| 2 | 30.0% | 0.665 | 0.773 | -0.107 | 26 |
| 3 | 22.4% | 0.498 | 0.597 | -0.099 | 27 |
| 4 | 14.3% | 0.318 | 0.461 | -0.143 | 26 |
| 5 | 15.1% | 0.335 | 0.356 | -0.022 | 26 |
| 6 | 11.8% | 0.261 | 0.275 | -0.014 | 26 |
| 7 | 9.9% | 0.220 | 0.213 | +0.008 | 28 |
| 8 | 9.7% | 0.216 | 0.164 | +0.052 | 28 |

Fit: least squares for `acc(h)/acc(1) = d^(h-1)` on the log scale, forced through
`r(1) = 1` so it matches how the constant is used (`STEP_DECAY ** (step-1)` is
exactly 1.0 at step 1).

## Fit quality -- read this before quoting the number

- **R² = 0.870** on the log-ratio fit, n = 544 prefixes.
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
rather than by the kill-chain heuristic): **top-3 at steps 1-4: 5.6% · 0.0% · 0.0% · 0.0% (n = 18 prefixes)**.

Read that honestly: on the only genuinely non-circular data in the repo, this
rollout has **no measurable skill past step 1**. Accuracy does not decay at
d = 0.77 there -- it goes to zero. n = 18 prefixes from 4 sequences is far too small
to fit a decay curve on, which is exactly why the shipped constant is fitted on
the 544-prefix held-out split instead. But it is not too small to be a warning,
and it points the same way as the bullet above: **0.77 is an upper bound on how
well this holds up, not a central estimate.**

The one-step CERT-In figure already published in `reports/prediction_eval.md`
(10.0% top-3, versus 38.1% on the auto split) says the same thing at h = 1. This
measurement extends that gap along the horizon rather than resolving it. Getting
a trustworthy multi-step decay needs more hand-verified report-ordered sequences;
until then, treat any step beyond the first as a lead to check, never a forecast.

## What this constant does and does not mean

It is the measured rate at which THIS model's top-3 accuracy falls off as the
horizon grows, on the same held-out split that produced the 38.1% headline. It is
not a probability that a forecast is correct, and it is not a confidence interval.
It is a decay rate with an experiment behind it, which is the whole and only claim.

Regenerate: `python3 scripts/eval_rollout_decay.py`
