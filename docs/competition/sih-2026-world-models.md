# SIH 2026 — "World Models for predictive cyber defence": what we have, what we lack

An honest gap analysis of nextATT&CKs against the NCIIPC problem statement on
learning network behaviour and forecasting attacker progression.

`as_of: 2026-08-22` (updated after closing the network-state gap)

**Summary judgement.** The central gap is now closed, with a caveat worth more
than the closure. `src/engine3/netstate.py` learns `P(S_t+1 | S_t)` over an
observed traffic feature vector on CIC-IDS2017 — the state space the PS asks
for, not the ATT&CK technique space of `src/engine2`. It forecasts a compromise
in the next window at ROC-AUC **0.987**, beats the prevalence baseline on Brier
by 5.6x, and beats a persistence baseline at next-state prediction (**0.396
against 0.362**) once it is allowed to adapt causally to the stream in front of
it. Purely offline it only draws with persistence at 0.357.
`reports/netstate.md` carries both figures and the two failed attempts between
them.

Packet-level features and PCAP ingestion (requirements 7 and 8) are now
implemented in `src/engine3/packets.py`, with the honest caveat that no
detection accuracy is claimed for them: no labelled capture ships with this
repository. What remains genuinely absent is requirement 9, CTU-13 and
CIC-IDS2018 — which is also what would turn the packet path from *implemented*
into *measured*.

---

## Requirement-by-requirement

| # | PS requirement | Status | Evidence / gap |
|---|---|---|---|
| 1 | Represent network state as feature vectors or graphs | **Yes** | `src/engine3/netstate.py`: a 48-dimensional traffic state vector per window of 256 consecutive flows — TCP flag distribution, IAT statistics, bidirectional ratios, packet-length distribution, TCP window sizes and throughput, each as a window mean and standard deviation. Plus the original 7 behavioural auth features and the NetworkX host/identity graph |
| 2 | Learn state-transition dynamics (LSTM / Transformer / GNN / latent) | **Yes, with a stated weakness** | A **discrete latent state-space model** — one of the four families the PS names. 24 latent states over the traffic vectors, Laplace-smoothed transition matrix, trained Mon-Wed and tested Thu-Fri so no day appears on both sides. K was selected on forecast quality, not on top-1, because top-1 across different K is not comparable. Next-state top-1 **0.396 against a persistence baseline of 0.362** with causal online adaptation, and 0.357 -- a draw -- without it. A second-order model was tried first and was worse (0.236). An oracle matrix counted on the test days reaches 0.448, which is how the limit was established as transfer between days rather than model capacity. Full workings, and three rejected lambda-fitting protocols, in `reports/netstate.md`. The technique-space Markov (38.1% top-3 vs 7.1%) and the published LSTM negative (27.2%) remain in `src/engine2` |
| 3 | Forecast future states; estimate probability of attacker progression | **Yes, in both state spaces** | Over traffic state: exact K-step matrix rollout in `engine3` (`p0 @ T^k`, no sampling), one-step Brier **0.022 vs 0.124** for the prevalence baseline, next-window compromise ROC-AUC **0.987**, calibration published per horizon out to 5 steps. Over technique state: `src/shared/rollout.py` beam rollout with a monotone cumulative probability, separately-reported decaying horizon confidence and a reliable-horizon rule |
| 4 | Map predicted behaviour to MITRE ATT&CK stages | **Yes** | Every predicted step carries its ATT&CK tactic; every emitted ID is validated against parsed STIX (100% ID validity, `reports/ps7_eval.md`) |
| 5 | Explainability via attention or feature attribution | **Yes** | **EXACT Shapley values** per feature (`src/shared/attribution.py`), surfaced in stage 4 of the explainability trace. Seven features means 128 coalitions, so the full enumeration is computed rather than approximated — no sampling error, and the efficiency axiom is asserted at runtime. Plus the 11-stage provenance trace and per-factor attribution in vulnerability scoring |
| 6 | Flow-level features (TCP flags, IAT statistics, bidirectional ratios) | **Yes, in engine3** | All three are in the engine3 state vector by name: FIN/SYN/RST/PSH/ACK/URG flag counts, Flow IAT mean/std/max/min, Down/Up ratio and forward/backward packet rates. Not in the *live demo* path, which ingests authentication logs — see the integration note below |
| 7 | Packet-level features (TTL variance, TCP window, fragment flags, payload distribution, port-scan signatures, retransmissions) | **Implemented, not measured** | `src/engine3/packets.py`: **30 features**, covering every category the PS names. `ttl_var` / `ttl_mean` / `ttl_unique`; `tcp_window_mean` / `_std` / `_zero_rate`; `frag_rate` / `dont_fragment_rate` / `more_fragments_rate`; `payload_mean` / `_std` / `_zero_rate` / `_entropy`; `unique_dst_ports` / `unique_dst_hosts` / `syn_without_ack_rate` / `ports_per_host` / `portscan_score`; `retransmission_rate`. **No detection accuracy is claimed** — no labelled capture is bundled. What is verified is that each feature computes what it claims, against frames whose properties the test chose (29 tests) |
| 8 | PCAP ingestion via Scapy or PyShark | **Yes, two readers** | **Scapy** when installed (pcapng, unusual link types, malformed frames) and a **stdlib reader** parsing classic pcap with `struct` alone, so the slim deployed image keeps every packet feature with no new dependency. The two are cross-checked on the same file in `tests/test_packets.py` and must agree exactly, which is how a real bug was caught (see below) |
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

**What took three attempts.** Predicting *which* latent state comes next. The
counted matrix alone managed 0.273 against a persistence baseline of 0.362, nine
points behind. Interpolating with persistence lifted it to 0.357, a draw.

A second-order context was the obvious next move, since an order-1 matrix cannot
distinguish "we have been sitting in state B" from "we just arrived in B from
A", and those have different futures. It was **worse**: 0.236 alone, and
leave-one-day-out gave it a weight of zero. Momentum was not the missing
ingredient.

What settled it was building an oracle on purpose: a first-order matrix counted
on the test days themselves, which reaches **0.448**. That is the ceiling for
any first-order model over these latent states, and it beats persistence by 8.6
points. So such a model *can* win, and ours was not winning because the
structure learned Monday-Wednesday does not transfer to Thursday-Friday. The
limit was transfer, not capacity, and that changes what to build.

Transfer is fixable at deployment and needs no labels. Traffic arrives and you
observe its transitions, so you may count them. `OnlineTracker` predicts the
next state and only then is told what happened; the offline prior enters as 2.0
pseudo-counts, so it dominates early in a stream and hands over as live evidence
accumulates. Strictly causal, with a test that fails if evidence from after the
current window ever leaks backwards. **0.396 against persistence at 0.362**, and
below the oracle, which is where an honest causal model has to sit.

Hyperparameters were fitted leave-one-day-out on the training days. Reading them
off the test days instead would have scored 0.4243; that number appears nowhere
except as a note on what tuning on the test set buys.

**What would still improve it**, in order: a labelled packet capture, because
`src/engine3/packets.py` already emits the same window vector and the model
would take it unchanged; closing the remaining five points to the oracle; a
time-based rather than count-based window, which needs a timestamp column
CIC-IDS2017 does not ship; and per-host state, which needs the address columns
this parquet drops but a PCAP does carry.

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
| ~~PCAP ingestion + packet features~~ | done | — | **Closed.** `src/engine3/packets.py`, requirements 7 and 8. Two cross-checked readers, 30 features, 29 tests |
| Point the packet path at a labelled capture | 1 day once the data is in hand | Turns requirement 7 from *implemented* into *measured* | **Do it** — this is data, not code |
| ~~Beat persistence on next-state prediction~~ | done | — | **Closed** by causal online adaptation, 0.396 vs 0.362. A higher-order model was tried first and lost |
| Close the remaining gap to the oracle, 0.396 → 0.448 | 3–5 days | Five points of headroom that provably exist | **Optional** — the oracle proves they are reachable |
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

- that engine3's **offline** matrix beats a persistence baseline at next-state
  prediction. It does not; it draws level at 0.357 against 0.362. The 0.396
  figure needs the online tracker, which needs a live stream to adapt to, so it
  is a claim about deployment rather than about the static model;
- that the online number is near a ceiling. An oracle matrix counted on the test
  days reaches 0.448, so about five points provably remain;
- that engine3 runs in the live demo. It does not — the demo ingests auth logs
  and engine3 consumes flow records;
- any measured detection performance on packet data. The features are
  implemented and their correctness is tested against frames we constructed;
  accuracy is **Not measured**, because no labelled capture ships here;
- results on CTU-13 or CIC-IDS2018;
- that we beat a supervised baseline on this dataset. We do not. Logistic
  regression on the same features ranks better, and the reasons that matters
  less than it looks are written down rather than left out.

Eight requirements have closed: network-state representation (1), transition
dynamics (2), forecasting and forward simulation (3), exact Shapley attribution
(5), flow-level features (6), packet-level features (7), PCAP ingestion (8) and
the logistic-regression benchmark (10).
Requirement 2 closed with a measured weakness rather than a clean win, and the
weakness is the interesting part: a first-order transition matrix over quantised
traffic states is a good risk model and a mediocre forecaster, and we can show
exactly how mediocre.

What stays open is requirement 9, the two datasets the PS names first, and it is
now the single thing standing between *implemented* and *measured* for the
packet path: CTU-13 and CIC-IDS2018 ship the labelled captures that
`python -m scripts.eval_pcap <file>` needs in order to produce a real number.
