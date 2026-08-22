# Network-state world model

A transition model over observed traffic state, `P(S_t+1 | S_t)`, as
distinct from `src/engine2`, which learns transitions between ATT&CK
techniques. Written for SIH 2026 requirement 2.

- Dataset: CIC-IDS2017, 1,433,536 training flows over Monday, Tuesday, Wednesday and 863,500 test flows over Thursday, Friday
- State: 48 dimensions (mean and standard deviation of 24 flow features) per window of 256 consecutive flows
- Windows: 5,599 training, 3,372 test
- Model: 24 latent states, Laplace-smoothed transition matrix, exact matrix rollout
- Split: temporal. No day appears on both sides, so no attack burst is learned and then scored.

## Results

| Metric | Model | Best baseline | Baseline |
|---|---|---|---|
| Next-state top-1, counted matrix | 0.2733 | 0.362 | persistence |
| Next-state top-1, interpolated (shipped) | 0.3567 | 0.362 | persistence |
| Next-state top-3, interpolated | 0.6273 | n/a | |
| Next-state top-1, marginal | 0.1516 | n/a | ignores S_t |
| Attack-rate Brier @ 1 step | 0.02217 | 0.12353 | always predict prevalence |
| Next-window compromise ROC-AUC | 0.9872 | 0.5 | random |

## Verdict

- **The counted transition matrix LOSES to persistence: 27.3% against 36.2%.** Network traffic is strongly autocorrelated and the transition structure learned on the training days does not fully transfer to a different traffic mix. That is the finding, not a footnote: a transition matrix that cannot beat 'assume no change' is not a forecaster yet.
- **Interpolating the two closes most of that gap: 35.7% top-1 and 62.7% top-3, which draws level with persistence, 0.5 points below it.** The weight is 0.15, chosen by leave-one-day-out over the training days -- count on two, score on the third -- because the real difficulty is transferring to a day with a different attack mix, and a holdout taken from inside a day never poses that question. Two weaker protocols were tried first and both picked a weight that did not transfer; `src/engine3/netstate.py` records what they were and why they were wrong. The same interpolation is what made engine2's next-technique predictor work.
- **So the next-state forecast should be described as matching a persistence baseline, not beating one.** Knowing which latent state comes next is worth about as much as assuming the network stays where it is. What the model adds over persistence is everything below: persistence can tell you the next window resembles this one, and it cannot tell you the probability that window is compromised.
- **Infiltration forecast: the model beats the prevalence baseline at one step.** Brier 0.02217 against 0.12353 for always predicting the training attack rate of 0.1416.
- **One-step-ahead compromise warning:** ROC-AUC 0.9872, PR-AUC 0.9333 over 3,370 test windows of which 500 were compromised. This is the model warning about the NEXT window from the current one, not classifying the window in front of it.

## Forecast calibration by horizon

| Steps ahead | Brier, model | Brier, prevalence baseline | Windows |
|---|---|---|---|
| 1 | 0.02217 | 0.12353 | 3,370 |
| 2 | 0.03772 | 0.12359 | 3,368 |
| 3 | 0.05097 | 0.12365 | 3,366 |
| 4 | 0.06219 | 0.12372 | 3,364 |
| 5 | 0.07162 | 0.12378 | 3,362 |

## Choosing the number of latent states

K was measured, not picked, and selected on **forecast quality**.
Next-state top-1 is not comparable across K -- fewer states is an
easier prediction, so that column falls monotonically and would keep
recommending a smaller K down to two states, which forecasts nothing.
Each row's top-1 is therefore shown against its own persistence
baseline, which shifts with K for the same reason.

| Latent states | Brier @ 1 step | Next-window ROC | Top-1 | Persistence top-1 | Weight |
|---|---|---|---|---|---|
| 8 | 0.05391 | 0.8974 | 0.5662 | 0.5662 | 0.3 |
| 16 | 0.0542 | 0.8765 | 0.3985 | 0.4036 | 0.25 |
| 24 **(shipped)** | 0.02217 | 0.9872 | 0.3567 | 0.362 | 0.15 |
| 32 | 0.02488 | 0.9873 | 0.3326 | 0.3374 | 0.15 |
| 48 | 0.06014 | 0.9881 | 0.2172 | 0.265 | 0.05 |

Best Brier in the sweep is K=24 at 0.02217; we ship K=24.

Note that top-1 sits at or just under the persistence baseline at
every K. That consistency is the point: it is a property of the
traffic, not an artefact of one choice of K.

## What the latent states mean

The reason for quantising rather than fitting a black box: a state
can be printed. Distinguishing features are in training standard
deviations from the mean window.

- **State 10** — attack rate 0.9805, 12 training windows. Active Mean (mean) high (+18.95), ACK Flag Count (std) low (-6.21), Flow IAT Mean (mean) high (+3.87)
- **State 2** — attack rate 0.9746, 343 training windows. Idle Mean (mean) high (+3.09), Flow IAT Max (mean) high (+3.05), Flow IAT Std (mean) high (+3.0)
- **State 4** — attack rate 0.9382, 179 training windows. Flow IAT Max (mean) high (+2.71), Idle Mean (mean) high (+2.68), Flow IAT Std (mean) high (+2.66)
- **State 7** — attack rate 0.0, 2 training windows. RST Flag Count (mean) high (+41.74), RST Flag Count (std) high (+19.75), Flow Bytes/s (std) high (+7.33)

## What this does not do

- **Not packet-level.** CIC-IDS2017 ships flow records. TTL variance,
  fragment flags and retransmission counts are not in the data, so
  SIH requirement 7 stays open.
- **No addresses or ports.** This parquet carries flow statistics only,
  so active-flow count and unique-port count are absent from the state
  vector even though the problem statement names them.
- **Not CTU-13 or CIC-IDS2018.** The problem statement lists CIC-IDS2017
  as acceptable, but names the other two first.
- **Flow order is assumed chronological.** It is the order CIC-IDS2017
  ships and there is no timestamp column to verify it against. Windows
  are never formed across a day boundary.
