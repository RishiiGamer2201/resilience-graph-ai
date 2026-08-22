# SIH 2026 — "World Models for predictive cyber defence": what we have, what we lack

An honest gap analysis of nextATT&CKs against the NCIIPC problem statement on
learning network behaviour and forecasting attacker progression.

`as_of: 2026-08-22`

**Summary judgement.** We are strong on the half most teams get wrong — attack-stage
mapping, explainability, honest uncertainty, offline operation, real benchmark
evidence — and weak on the half the PS is actually named after. Our transition
model is over **ATT&CK techniques**, not over **network state**. The PS asks for
`P(S_t+1 | S_t)` where `S_t` is a traffic feature vector or flow graph. That is
the central gap, and no amount of polish elsewhere substitutes for it.

---

## Requirement-by-requirement

| # | PS requirement | Status | Evidence / gap |
|---|---|---|---|
| 1 | Represent network state as feature vectors or graphs | **Partial** | 7 behavioural features per authentication event (`lanl_detect.engineer`), plus a NetworkX host/identity graph. But this is auth-log state, not traffic state |
| 2 | Learn state-transition dynamics (LSTM / Transformer / GNN / latent) | **Partial** | Interpolated Markov over 205 real ATT&CK sequences, measured **38.1% top-3 vs 7.1%** kill-chain baseline. An LSTM over MiniLM embeddings was tried and **lost at 27.2%** — published as a negative in `reports/model_experiments.md`. No GNN, no Transformer, and the transitions are between *techniques*, not *network states* |
| 3 | Forecast future states; estimate probability of attacker progression | **Now present** | `src/shared/rollout.py`: K-step beam rollout producing a monotone cumulative infiltration probability with separately-reported decaying horizon confidence, and a reliable-horizon rule so the headline is never the least trustworthy number. Forecasts technique states, not traffic states |
| 4 | Map predicted behaviour to MITRE ATT&CK stages | **Yes** | Every predicted step carries its ATT&CK tactic; every emitted ID is validated against parsed STIX (100% ID validity, `reports/ps7_eval.md`) |
| 5 | Explainability via attention or feature attribution | **Partial** | 11-stage provenance trace (`explain.py`), per-factor attribution with facts in vulnerability scoring, claims carrying missing evidence and benign alternatives. **No SHAP values and no attention weights** — the PS names both, and "black-box outputs without interpretability are not acceptable" |
| 6 | Flow-level features (TCP flags, IAT statistics, bidirectional ratios) | **Partial** | Engine 1 trains on CIC-IDS2017 flow features, but the *live* pipeline ingests authentication logs with 7 behavioural features. Flags, IAT variance and directionality are not in the runtime path |
| 7 | Packet-level features (TTL variance, TCP window, fragment flags, payload distribution, port-scan signatures, retransmissions) | **Absent** | Nothing packet-level anywhere in the codebase |
| 8 | PCAP ingestion via Scapy or PyShark | **Absent** | We ingest CSV only |
| 9 | CIC-IDS2018 or CTU-13 | **Absent** | We use CIC-IDS2017, UNSW-NB15 and LANL. The PS names 2018 and CTU-13 explicitly, though it also lists ours as acceptable |
| 10 | Benchmark vs a logistic-regression baseline on the same features | **Partial** | We benchmark against random, a rule baseline and IsolationForest. **Not** against logistic regression, which the PS names specifically |
| 11 | Offline demo interface, no cloud APIs | **Yes** | React SPA + FastAPI in one container, runs with no key and no network |
| 12 | Fully open source | **Yes** | No paid dependency in the required path |

---

## The one gap that matters

Everything else on this list is a few days of work. This one is the thesis of the
problem statement:

> a world model learns the transition dynamics `P(S_t+1 | S_t)`: given the
> current observed network state (active flows, flag distributions, port
> activity, packet timing), what is the probability distribution over future
> states

Our Markov learns `P(technique_t+1 | technique_t, technique_t-1)`. That is a
genuine, measured transition model — and it is a transition model over the
**wrong state space** for this PS. A technique is a label an analyst assigns
after the fact; the PS wants dynamics over the raw observable.

**What closing it actually requires**

1. Define `S_t` as a fixed-width traffic feature vector per time window: TCP flag
   distribution, active flow count, unique port count, byte and packet rates,
   IAT mean/variance, bidirectional ratio, plus packet-level TTL variance and
   window-size statistics.
2. Train a sequence model on `(S_t) -> (S_t+1)` over CIC-IDS2018 or CTU-13 with
   the attack-timeline annotations as ground truth for the infiltration label.
3. Roll it forward K windows and read the infiltration probability off the
   predicted trajectory — the beam-search and honest-decay machinery in
   `rollout.py` transfers directly; only the state space and the model change.

Steps 1 and 2 are the real work. Step 3 already exists.

---

## Ranked by value per unit of effort

| Gap | Effort | Value for this PS | Verdict |
|---|---|---|---|
| Logistic-regression baseline on the existing features | hours | The PS names it explicitly and we already have the harness | **Do it** — cheapest possible point |
| SHAP attribution on the autoencoder detector | 1 day | PS says black-box output is unacceptable; we have deterministic attribution but not the named technique | **Do it** |
| PCAP ingestion + packet features (Scapy) | 2–3 days | Unlocks requirements 7 and 8 outright | **Do it** if targeting this PS |
| Network-state transition model on CTU-13 / CIC-IDS2018 | 4–7 days | The thesis of the PS | **Required** to be credible here |
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

- that we have a world model over network state — we have one over ATT&CK
  techniques, and the distinction is exactly what this PS is testing;
- packet-level analysis of any kind;
- SHAP or attention-based attribution;
- results on CTU-13 or CIC-IDS2018.

The forward-simulation work landed today (`rollout.py`) makes requirement 3 real.
It does not make requirement 2 real, and a judge for this PS will ask about
requirement 2 first.
