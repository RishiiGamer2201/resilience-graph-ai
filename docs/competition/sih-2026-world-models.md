# SIH 2026 — "World Models for predictive cyber defence": what we have, what we lack

An honest gap analysis of nextATT&CKs against the NCIIPC problem statement on
learning network behaviour and forecasting attacker progression.

`as_of: 2026-08-22` (updated after closing the network-state gap)

**Summary judgement.** The central gap is now closed, with a caveat worth more
than the closure. `src/engine3/netstate.py` learns `P(S_t+1 | S_t)` over an
observed traffic feature vector on CIC-IDS2017 — the state space the PS asks
for, not the ATT&CK technique space of `src/engine2`. It forecasts a compromise
in the next window at ROC-AUC **0.987** and beats the prevalence baseline on
Brier by 5.6x. But its **next-state prediction only draws level with a
persistence baseline** (top-1 0.357 against 0.362), which means it is a strong
risk model and a weak state forecaster. That is written into
`reports/netstate.md` rather than left out, and it is the first thing to fix.

What remains genuinely absent is packet-level analysis (requirements 7 and 8)
and results on CTU-13 or CIC-IDS2018 (requirement 9).

---

## Requirement-by-requirement

| # | PS requirement | Status | Evidence / gap |
|---|---|---|---|
| 1 | Represent network state as feature vectors or graphs | **Yes** | `src/engine3/netstate.py`: a 48-dimensional traffic state vector per window of 256 consecutive flows — TCP flag distribution, IAT statistics, bidirectional ratios, packet-length distribution, TCP window sizes and throughput, each as a window mean and standard deviation. Plus the original 7 behavioural auth features and the NetworkX host/identity graph |
| 2 | Learn state-transition dynamics (LSTM / Transformer / GNN / latent) | **Yes, with a stated weakness** | A **discrete latent state-space model** — one of the four families the PS names. 24 latent states over the traffic vectors, Laplace-smoothed transition matrix, trained Mon-Wed and tested Thu-Fri so no day appears on both sides. K was selected on forecast quality, not on top-1, because top-1 across different K is not comparable. **The honest weakness:** next-state top-1 is 0.357 against a persistence baseline of 0.362, so it matches 'assume no change' rather than beating it. Full workings and three rejected lambda-fitting protocols in `reports/netstate.md`. The technique-space Markov (38.1% top-3 vs 7.1%) and the published LSTM negative (27.2%) remain in `src/engine2` |
| 3 | Forecast future states; estimate probability of attacker progression | **Yes, in both state spaces** | Over traffic state: exact K-step matrix rollout in `engine3` (`p0 @ T^k`, no sampling), one-step Brier **0.022 vs 0.124** for the prevalence baseline, next-window compromise ROC-AUC **0.987**, calibration published per horizon out to 5 steps. Over technique state: `src/shared/rollout.py` beam rollout with a monotone cumulative probability, separately-reported decaying horizon confidence and a reliable-horizon rule |
| 4 | Map predicted behaviour to MITRE ATT&CK stages | **Yes** | Every predicted step carries its ATT&CK tactic; every emitted ID is validated against parsed STIX (100% ID validity, `reports/ps7_eval.md`) |
| 5 | Explainability via attention or feature attribution | **Yes** | **EXACT Shapley values** per feature (`src/shared/attribution.py`), surfaced in stage 4 of the explainability trace. Seven features means 128 coalitions, so the full enumeration is computed rather than approximated — no sampling error, and the efficiency axiom is asserted at runtime. Plus the 11-stage provenance trace and per-factor attribution in vulnerability scoring |
| 6 | Flow-level features (TCP flags, IAT statistics, bidirectional ratios) | **Yes, in engine3** | All three are in the engine3 state vector by name: FIN/SYN/RST/PSH/ACK/URG flag counts, Flow IAT mean/std/max/min, Down/Up ratio and forward/backward packet rates. Not in the *live demo* path, which ingests authentication logs — see the integration note below |
| 7 | Packet-level features (TTL variance, TCP window, fragment flags, payload distribution, port-scan signatures, retransmissions) | **Absent** | Nothing packet-level anywhere in the codebase |
| 8 | PCAP ingestion via Scapy or PyShark | **Absent** | We ingest CSV only |
| 9 | CIC-IDS2018 or CTU-13 | **Absent** | We use CIC-IDS2017 (engine1 and engine3), UNSW-NB15 and LANL. The PS names 2018 and CTU-13 explicitly, though it also lists ours as acceptable |
| 10 | Benchmark vs a logistic-regression baseline on the same features | **Yes, and we lose it** | `scripts/eval_lr_baseline.py`. Supervised LR on the identical seven features reaches TPR@1%FPR **0.919 vs our 0.901** and PR-AUC **0.088 vs 0.009**. Published in `reports/lr_baseline.md` with its three qualifiers: LR trains on labels a novel campaign would not have, the stratified split puts one campaign on both sides, and at a usable threshold LR collapses (F1 0.004 at 3.1% FPR) |
| 11 | Offline demo interface, no cloud APIs | **Yes** | React SPA + FastAPI in one container, runs with no key and no network |
| 12 | Fully open source | **Yes** | No paid dependency in the required path |

---

## The gap that mattered, and what is left of it

The thesis of the problem statement:

> a world model learns the transition dynamics `P(S_t+1 | S_t)`: given the
> current observed network state (active flows, flag distributions, port
> activity, packet timing), what is the probability distribution over future
> states

`src/engine3/netstate.py` now does this. `S_t` is a 48-dimensional traffic
vector per window of 256 consecutive CIC-IDS2017 flows; the dynamics are a
24-state latent transition matrix; the rollout is `p0 @ T^k`, exact rather than
sampled, so a K-step forecast is deterministic and carries no sampling error.
Each latent state holds its measured attack prevalence, so a distribution over
future states reads directly as an infiltration probability.

**What it does well.** Warning that the NEXT window is compromised: ROC-AUC
0.987, PR-AUC 0.933 over 3,370 held-out windows. One-step Brier 0.022 against
0.124 for always predicting the base rate. Both on days the model never saw.

**What it does badly, and this is the honest headline.** Predicting *which*
latent state comes next: top-1 0.357 against a persistence baseline of 0.362.
The counted matrix alone managed only 0.273. Network traffic is strongly
autocorrelated and the transition structure learned Mon-Wed does not transfer
cleanly to a different attack mix, so the single most useful fact about the next
window is that it resembles this one. Interpolating the matrix with persistence
recovers most of the gap but does not clear it.

So: a good risk model over network state, a mediocre state forecaster. Both
halves are in `reports/netstate.md`, together with three lambda-fitting
protocols we tried and rejected, two of which produced a confident number that
did not transfer.

**What would actually improve it**, in order: a sequence model with more than
one step of memory (the current matrix is first-order, and an attack ramp is not
Markovian in a single window); a time-based rather than count-based window, which
needs a timestamp column CIC-IDS2017 does not ship; and per-host state, which
needs the address columns this parquet drops.

### Integration note

Engine3 is trained, evaluated and committed, but it is **not in the live demo
path** and the app does not pretend otherwise. The demo scenarios are
authentication logs; this model consumes flow records. Wiring an endpoint the
SPA never calls is exactly the failure ADR 0007 was written about. The measured
results appear on the scoreboard and in `RESULTS.md`; the model runs from
`scripts/eval_netstate.py`.

## Ranked by value per unit of effort

| Gap | Effort | Value for this PS | Verdict |
|---|---|---|---|
| ~~Logistic-regression baseline~~ | done | — | **Closed.** And it beat us; see requirement 10 |
| ~~SHAP attribution on the detector~~ | done | — | **Closed.** Exact Shapley, not approximated |
| ~~K-step forward simulation~~ | done | — | **Closed.** `src/shared/rollout.py`, requirement 3 |
| ~~Network-state transition model~~ | done | — | **Closed** on CIC-IDS2017. `src/engine3/netstate.py`, requirements 1, 2, 3 and 6 |
| PCAP ingestion + packet features (Scapy) | 2–3 days | Unlocks requirements 7 and 8 outright | **Do it** if targeting this PS |
| Beat persistence on next-state prediction | 2–3 days | The one measured weakness in engine3 | **Do it** — a higher-order or sequence model over the latent states |
| Re-run engine3 on CTU-13 / CIC-IDS2018 | 2–3 days | Requirement 9, and evidence the model is not CIC-IDS2017-specific | **Do it** if targeting this PS |
| GNN over the flow graph | 1 week+ | One named option among several; LSTM/Transformer are equally acceptable and we already have sequence-model experience | **Skip** unless time is abundant |
| Streamlit demo | — | We already have a better offline interface | **Skip** |

---

## What we should lead with, and what we must not claim

**Lead with**, because it is measured and most entries will not have it:

- honest uncertainty — probability and confidence reported separately, a decaying
  horizon, and a rule that stops us quoting the least reliable number;
- attack-stage mapping with 100% ID validity against parsed ATT&CK STIX;
- a published negative result (the LSTM lost at 27.2%) and an anti-circularity
  baseline built specifically to catch us cheating;
- end-to-end explainability from one raw log line to the proposed action;
- fully offline, no key, one container.

**Do not claim**, because it is not true today:

- that engine3 beats a persistence baseline at next-state prediction. It does
  not; it draws level. It beats the prevalence baseline at forecasting
  compromise, which is a different and weaker claim;
- that engine3 runs in the live demo. It does not — the demo ingests auth logs
  and engine3 consumes flow records;
- packet-level analysis of any kind;
- results on CTU-13 or CIC-IDS2018;
- that we beat a supervised baseline on this dataset. We do not. Logistic
  regression on the same features ranks better, and the reasons that matters
  less than it looks are written down rather than left out.

Six requirements have closed: network-state representation (1), transition
dynamics (2), forecasting (3), forward simulation (3), exact Shapley attribution
(5), flow-level features (6) and the logistic-regression benchmark (10).
Requirement 2 closed with a measured weakness rather than a clean win, and the
weakness is the interesting part: a first-order transition matrix over quantised
traffic states is a good risk model and a mediocre forecaster, and we can show
exactly how mediocre. What stays open is packet-level analysis (7, 8) and the
two datasets the PS names first (9).
