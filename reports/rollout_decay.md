# Rollout horizon decay -- measured, not assumed

`src/shared/rollout.py` renders a horizon confidence of `STEP_DECAY ** (step-1)`
on every forecast. This is the measurement behind that constant.

**Result: fitted `0.7726`, shipped as `STEP_DECAY = 0.77`** (was `0.62`,
which had no experiment behind it). The fit is a regression with **8 data points and
1 free parameter** -- one top-3 accuracy per horizon -- and those 8 accuracies were
each averaged over **544 held-out prefixes drawn from 29 test sequences**.
R² = **0.739** on the decaying points of the log-ratio fit.

Those are three different numbers and they are not interchangeable:

| number | what it is |
|---|---|
| **8** | data points in the regression -- its actual n |
| **544** | held-out prefixes the 8 accuracies were averaged from; never a row in the fit |
| **29** | sequences those 544 prefixes come from -- the closest thing here to an effective sample size |

Earlier versions of this report printed "n = 544" wherever a regression's n
belongs -- in this file, in the `STEP_DECAY` comment block, and in the
`method.decay` string that ships in the API payload. That overstated the
regression's n by a factor of 68. `fit_decay()` takes one argument, a list of
8 accuracies; no prefix count enters the least squares at any point.

Shipped rounded to 2dp on purpose: `src/shared/rollout.py` renders this number to
the user, and the sequence-level bootstrap below puts the 95% interval at
[0.720, 0.804] -- a spread of 0.08. The extra digits would be precision the
experiment did not earn. **Read "The reliable horizon is a coin flip" below
before quoting anything downstream of this constant**, because the rounding to
0.77 is what keeps the reliable horizon at step 5, by 0.00084.

## What was measured

For each prefix of a held-out sequence, `simulate_progression` is rolled forward
8 steps and asked: is the technique that ACTUALLY came at offset *h* among the
top-3 the rollout renders at step *h*? That is the same metric and the same
top-3 shape as the published one-step 38.2%, extended along the horizon -- so
step 1 here is directly comparable to the number the module already cites.

Accuracy at every horizon is measured over **the same fixed set of prefixes** --
only those with at least 8 real techniques left to check against. A shrinking
population would mix horizon decay with "long sequences behave differently".

That restriction moves the step-1 number: **45.0%** here versus 38.6% over
all 777 prediction points, because prefixes near the end of a sequence (and every
sequence shorter than 9) are excluded. Only the *ratios* feed the fit, so this
does not bias the decay -- but it does mean 45.0% is not a new headline accuracy
and must not be quoted as one. The headline stays 38.2%.

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
| prediction points | 777 | 777 |
| OOV (counted as misses) | 45 | 45 |
| top-1 | 23.2% | 23.2% |
| top-3 | 38.2% | 38.6% |
| top-5 | 44.5% | 44.5% |

top-3 differs by 0.4pp -- three prediction points out of 777. `predictor.rank_next`
breaks probability ties by technique id; `build_predictor`'s ranker leaves tied
techniques in dict order. Same corpus, same model, different coin-flip on ties.

This split verification is genuinely non-circular and it is the part of this
report to trust most: the reconstruction is checked against numbers published
before it, and the script exits rather than reporting a decay figure if it misses.

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

Fit: least squares for `acc(h)/acc(1) = d^(h-1)` on the log scale, anchored at
`r(1) = 1` so it matches how the constant is used (`STEP_DECAY ** (step-1)` is
exactly 1.0 at step 1). **These 8 rows are the entire regression.**

## Fit quality -- read this before quoting the number

### R² = 0.739, not 0.870

The anchored fit passes through `(h=0, log(acc[0]/acc[0])) = (0, 0.0)` by
construction. That point is a tautology: it is the definition of the ratio, not
an observation. It cannot move the slope -- it contributes zero to both the
numerator and the denominator of the least-squares estimate, which is why `d` is
**identical** either way -- but it sits exactly on the line while lying far from
the mean of the y values, so it adds nothing to `ss_res` and about 1.07 to
`ss_tot`. That is R² inflation with no explanatory work behind it.

| R² on the log-ratio scale | value |
|---|---|
| counting the `r(1) = 1` anchor (previously reported) | 0.870 |
| **on the 7 decaying points only (reported now)** | **0.739** |

The anchor stays *in the fit* -- it is a real constraint, the curve genuinely
must pass through 1.0 at step 1 -- but it is out of the reported R², because the
question R² answers here is "how well does this curve explain the decay?", and
the anchor is not part of the decay.

### A linear-space fit does better and picks a different d

The same 8 ratios, least-squares in linear space rather than log space:

| fit | d | R² on the linear ratio scale |
|---|---|---|
| **log space (shipped)** | **0.7726** | 0.914 |
| linear space | 0.7407 | **0.942** |

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
downstream story: at d = 0.7407 the reliable horizon is step 4, not step 5. See below.

### The 544 prefixes are not 544 independent observations

They come from **29 of the 35 test sequences** (the other 6 are shorter than 9
techniques and contribute nothing), and they are distributed very unevenly:

- the largest single sequence supplies **85 of 544** prefixes,
- the top 5 sequences supply **308 of 544 (57%)**.

Worse, prefixes *within* a sequence overlap almost completely: two consecutive
prefixes of the same sequence are scored against 7 of the same 8 ground-truth
targets. Treating 544 as a sample size would be treating 544 heavily-overlapping
views of 29 sequences as 544 independent draws. **The effective sample size is
closer to the ~29 sequence clusters than to 544**, and the top-heavy distribution
means even 29 is generous.

So the interval below is computed by resampling **sequences**, not prefixes:

| estimate | d |
|---|---|
| point estimate | 0.7726 |
| sequence bootstrap, 95% (2000 replicates, seed 42) | **[0.720, 0.804]** |
| leave-one-sequence-out, full spread | [0.756, 0.779] |

The bootstrap interval is wide -- **0.08 wide, on a quantity whose entire useful
range is about 0.6 to 0.9** -- but it is not so noisy as to be useless: it rules
out d below ~0.72 and above ~0.81, and it is the honest width to attach to the
2dp shipped value. The leave-one-sequence-out spread is much narrower, which is
what you would expect when one dropped cluster out of 29 is being replaced by
nothing rather than by a resample; the bootstrap is the figure to quote.

### The reliable horizon is a coin flip -- read this before quoting step 5

`src/shared/rollout.py` sets `RELIABLE_CONFIDENCE = 0.35` and quotes the
furthest step whose confidence still clears it. That makes step 5 reliable exactly
when `d^4 >= 0.35`, i.e. when `d >= 0.35^(1/4) = 0.769161`.

    shipped d       = 0.77
    d^4             = 0.35153
    threshold       = 0.35
    margin          = 0.00084

**The claim "the reliable horizon moved from step 3 to step 5" rests on 0.00084.**

That margin is far smaller than the fit's own resolution, in every direction we
can measure it:

| perturbation | d | reliable horizon |
|---|---|---|
| shipped | 0.77 | 5 |
| raw fitted | 0.7726 | 5 |
| bootstrap 2.5% | 0.720 | 4 |
| bootstrap 97.5% | 0.804 | 5 |
| linear-space fit | 0.7407 | 4 |
| one 2dp tick down | 0.76 | 4 |

Across the 2000 sequence-bootstrap replicates the reliable horizon lands:

| reliable horizon | replicates | share |
|---|---|---|
| step 3 | 15 | 0.8% |
| step 4 | 924 | 46.2% |
| step 5 | 1050 | 52.5% |
| step 6 | 11 | 0.6% |

**Step 5 wins 52.5% of the time and step 4 wins 46.2%.** That is a coin flip. And any d in
[0.765, 0.780] is within 5% of the minimum SSE -- that band is the fit's own
resolution, and it **straddles** the flip point 0.7692 rather than sitting on one
side of it. The flip is inside the interval the fit cannot resolve.

This same report justifies rounding to 2dp on the grounds that the extra digits
would be "precision the experiment did not earn". That cannot stand alongside an
unqualified step-5 claim: `0.77` versus `0.7692` is a difference in the *third*
decimal, decided by the *fourth*. If the 4th significant figure is not earned,
neither is any conclusion that turns on it. The qualified version, which is what
should be quoted:

> The measured decay is gentler than the made-up 0.62 it replaced, and under it
> the reliable horizon is **plausibly** step 5 rather than step 3 -- but step 4 is
> about equally consistent with the same data, and picking the linear-space fit
> instead would give step 4. The horizon moved *somewhere north of 3*. Which
> side of 5 it lands on is not established by this experiment.

`RELIABLE_CONFIDENCE` was deliberately left at 0.35 rather than retuned after this
measurement, which is the right call -- moving a threshold to preserve a
conclusion is what this file exists to avoid. But it does mean the threshold and
the fitted constant now sit 0.00084 apart, and nothing about that gap is robust.

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
rather than by the kill-chain heuristic): **top-3 at steps 1-4: 5.9% · 0.0% · 0.0% · 0.0% (n = 17 prefixes)**.

Read that honestly: on the only genuinely non-circular data in the repo, this
rollout has **no measurable skill past step 1**. Accuracy does not decay at
d = 0.77 there -- it goes to zero. n = 17 prefixes from 4 sequences is far too small
to fit a decay curve on, which is exactly why the shipped constant is fitted on
the held-out split instead. But it is not too small to be a warning,
and it points the same way as the bullets above: **0.77 is an upper bound on how
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
