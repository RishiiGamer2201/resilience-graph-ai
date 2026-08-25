# nextATT&CKs, Results

ET AI Hackathon 2026, Problem Statement 7. Every number below is produced by an
evaluation script and read from `reports/metrics.json`,
`reports/scaling_measurements.json` and the live analysis cache. Nothing is
hand-typed. Regenerate with `python -m scripts.make_results_md`.

Headline: unsupervised detection on a real red-team campaign at ROC-AUC
0.992, catching 616 of 702 attack events at a 1% false-positive
rate, with the whole campaign collapsed from 2,732 events into
one correlated incident and a single best host to isolate.

## 1. Detection (Engine 1)

Unsupervised, benign-trained. Labels used for evaluation only, never for
training. We report PR-AUC and TPR at a fixed false-positive rate, never
accuracy (meaningless at 0.006% attack prevalence).

| Dataset | Metric | Result |
|---|---|---|
| LANL (real red-team) | ROC-AUC | **0.992** |
| LANL | TPR @ 1% FPR | **87.7%** (616 of 702 caught) |
| LANL | TPR @ 5% FPR | 96.6% (678 of 702 caught) |
| LANL | Behavioural-only ROC (NTLM removed) | 0.906 |
| LANL | **Behavioural-only TPR @ 1% FPR (NTLM removed)** | **22.8%** (down from 87.7%) |
| CIC-IDS2017 | PR-AUC, autoencoder | 0.570 |
| CIC-IDS2017 | PR-AUC, IsolationForest | 0.473 |
| CIC-IDS2017 | PR-AUC, rule baseline | 0.098 (worse than random) |
| CIC-IDS2017 | PR-AUC, random baseline | 0.155 |
| UNSW-NB15 | ROC-AUC | 0.829 |
| UNSW-NB15 | PR-AUC | 0.867 |

Shipped detector: benign-trained **autoencoder**, chosen over an IsolationForest
by measurement. ROC-AUC barely separates them (0.992 vs
0.988); the deciding number is the 1% false-positive operating
point an analyst runs at, where the autoencoder catches 616 of 702 red-team
events against 361 of 702 for the forest. The autoencoder trains offline
and is exported to NumPy weights, so the deployed image needs no deep-learning
framework and no GPU.

The supervised baseline, and we lose it. A logistic regression trained **with**
the red-team labels on the identical seven features reaches TPR@1%FPR
0.9194 against our 0.9005, and PR-AUC
0.0878 against 0.0088, on a stratified 70/30 split of
3,366,571 held-out rows. Three things qualify that and none of them erase
it: the autoencoder never sees a label, so it is the one that still works on a
campaign nobody has labelled yet; a stratified split puts the same campaign on
both sides, which flatters a supervised model; and at an actual decision
threshold the regression is unusable, F1 0.004 at a
3.1% false-positive rate. Full workings in
`reports/lr_baseline.md`. The 90.0% on this split is not
the 87.7% headline above, which comes from the day-wise
protocol in `reports/lanl_redteam_detection.md`; the two are not comparable.

The NTLM ablation, and it goes against us. 100% of red-team logins used the
older NTLM protocol versus about 6% of benign, so `is_ntlm` is a powerful signal
and a trivially evadable one -- the attacker switches to Kerberos. Removing it
and scoring on behaviour alone leaves ROC-AUC almost intact at
0.906, but **TPR at the 1% false-positive operating point
collapses from 87.7% to
22.8%** -- a
74% relative
drop. ROC-AUC integrates over every threshold including ones no analyst would
run at, which is why it barely moves; the operating point is where the detector
is actually used, and there NTLM is carrying most of the result.

An earlier version of this section reported only the ROC number and concluded
that detection was "driven by generalisable behaviour, not one brittle
artifact." That conclusion does not survive its own ablation. The honest
statement is that this detector is substantially dependent on one evadable
protocol flag, that the behavioural features alone are a much weaker detector
than the headline suggests, and that fixing it means adding signal -- Kerberos
service-ticket behaviour, process and flow telemetry -- not re-describing the
existing result.

## 2. ATT&CK association ranking and attribution (Engine 2)

Rank techniques associated with the observed ATT&CK set. The model is trained
on group/campaign profiles sorted by a tactic heuristic, not 205 observed attack
timelines.

| Method | Top-3 accuracy | Status |
|---|---|---|
| Most-frequent baseline | 4.9% | baseline |
| Kill-chain order baseline | 7.1% | baseline built to beat us |
| LSTM over MiniLM embeddings | 29.3% | lost, documented negative |
| Markov, first order | 36.7% | previous shipped |
| **Interpolated Markov** | **38.2%** | **shipped** |

Profile-position comparison: the sequences are tactic-ordered, so a model can
partly re-learn that order. The shipped model beats the kill-chain baseline by
**5.4x** on this association task, but that does not establish chronological
technique-to-technique transitions. The
neural models (LSTM 29.3%, and a bidirectional LSTM at 20.0% in
`reports/model_experiments.md`) both lost at this data scale, so we ship the
simpler winner.

For every context, interpolation weights are renormalized across only the
unigram, first-order and second-order components that contain data. The complete
candidate distribution sums to one. These values are normalized model weights,
not observed frequencies, calibrated confidence, or next-move probabilities.

Independent chronological gate: on 4 source-provenanced CERT-In timelines,
top-3 is
11.1% versus 38.2%
on the tactic-sorted profile set. The sequence-bootstrap improvement over the
strongest temporal baseline includes zero, so next-move forecasting is disabled.

Attribution: transparent weighted retrieval over 172 MITRE group profiles
(coverage 0.55, Jaccard 0.20, semantic similarity 0.25), with a printed
justification. Not a trained classifier, and we say so. Technique embeddings
separate same-tactic pairs at cosine 0.412 versus
0.327 for random pairs.

## 3. World model over network state (Engine 3)

`P(S_t+1 | S_t)` where `S_t` is observed traffic, not an ATT&CK label. Written
for the SIH 2026 problem statement, which asks for transition dynamics over
network state specifically. `S_t` is a 48-dimensional vector per
window of 256 consecutive CIC-IDS2017 flows: TCP flag distribution,
inter-arrival-time statistics, bidirectional ratios, packet-length distribution,
TCP window sizes and throughput, each as a window mean and standard deviation.
The dynamics are a 24-state latent transition matrix; a K-step
rollout is `p0 @ T^k`, exact rather than sampled.

Trained Monday-Wednesday, tested Thursday-Friday. A temporal split, so no attack
burst appears on both sides.

| Metric | Model | Baseline | |
|---|---|---|---|
| Next-window compromise, ROC-AUC | **0.9872** | _not measured_ | persistence (current window's attack rate) |
| Next-window compromise, PR-AUC | 0.9333 | | |
| Attack-rate Brier @ 1 step | **0.02217** | 0.12353 | always predict prevalence |
| Next-state top-1, online adaptive | **0.3964** | 0.362 | persistence |
| Next-state top-1, offline | 0.3567 | 0.362 | persistence |
| Next-state top-1, counted matrix only | 0.2733 | 0.362 | persistence |
| Next-state top-1, second order | 0.2357 | 0.362 | persistence |
| Next-state top-1, oracle (cheats) | 0.4475 | 0.362 | ceiling for any order-1 model |

**Forecasting compromise works well.** ROC-AUC 0.9872 at
warning that the NEXT window is compromised, over 3,372
held-out windows, and a one-step Brier score
5.6x better than always predicting
the base rate.

**Predicting which state comes next took three attempts and the failures are
worth more than the result.** Offline, the model draws with persistence:
0.3567 against 0.362, with the raw counted
matrix nine points behind at 0.2733. A second-order model,
the obvious candidate since an order-1 matrix cannot tell "we have been sitting
in state B" from "we just arrived in B from A", was worse still at
0.2357, and leave-one-day-out gave it a weight of zero. What
settled it was an oracle: a first-order matrix counted on the test days
themselves reaches 0.4475, beating persistence outright. So a
first-order model over these latent states CAN win, and ours did not. The limit
was transfer between days, not model capacity.

Transfer is fixable at deployment and needs no labels. Traffic arrives and you
observe its transitions, so you may count them. `OnlineTracker` predicts the
next state and only then is told what happened, blending the offline prior in as
2.0 pseudo-counts so it dominates early in a stream and
hands over as evidence accumulates. Strictly causal, and there is a test that
fails if future evidence ever leaks backwards. That scores **0.3964
against persistence at 0.362**, and sits below the oracle,
where an honest causal model has to sit. Hyperparameters were fitted
leave-one-day-out; reading them off the test days instead would have scored
0.4243, and that number is not used anywhere.

`reports/netstate.md` has the per-horizon calibration, the latent-state
descriptions, the K sweep and three rejected lambda-fitting protocols. Engine 3
is **not in the live demo path**: the demo scenarios are authentication logs and
this model consumes flow records.

### Packet-level features

`src/engine3/packets.py` reads a capture file and extracts
**30 packet-level features** per window, emitting the same
60-dimensional vector the flow model uses, so a PCAP feeds the world
model above unchanged. Covered: TTL mean, variance and cardinality; TCP window
mean, deviation and zero rate; fragment, don't-fragment and more-fragments
rates; payload length mean, deviation, zero rate and Shannon entropy; the TCP
flag distribution; a port-scan signature built from unique destination ports,
ports per host and SYN-without-ACK rate; and a retransmission rate counted from
repeated (flow, sequence) pairs carrying payload.

Two readers: a stdlib reader (Scapy not installed here). Classic pcap parses with `struct` alone, so the slim
deployed image keeps every packet feature without a new dependency; Scapy is
used when present because it handles pcapng and awkward link types properly.
The two are cross-checked on the same file and must agree exactly. That check
earned its keep immediately: the stdlib reader had been parsing the leading
bytes of a non-first IP fragment as a TCP header, inventing ports and sequence
numbers out of payload continuation and manufacturing retransmissions from them.

**Detection accuracy on packet data is Not measured.** No labelled capture
ships with this repository, so there is no honest number and none is given. What
is verified is that every feature computes what it claims, against frames whose
properties the tests chose: 29 tests in `tests/test_packets.py`. Running
`python -m scripts.eval_pcap <file>` against a labelled capture produces a real
number with no code changes.


## 4. Operational output (live campaign analysis)

Live run of the full LANL red-team campaign through the complete pipeline.

| Output | Value |
|---|---|
| Events analysed, alerts, incidents | 2,732 then 1,243 then 51 |
| Compromised accounts | 104 |
| Attack graph | 473 hosts, 484 movements, 4 attacker pivots |
| Critical assets reachable | 16 |
| Total exposure | 469 hosts |
| Isolate the single best choke point | severs 452 hosts |

## 5. Performance and scalability

Full pipeline measured at nine input sizes on a laptop CPU, no GPU, best of 3
after warm-up.

| Events in one request | End-to-end time | Alerts |
|---|---|---|
| 2,732 | 0.131 s | 1,243 |
| 10,000 | 0.508 s | 4,808 |
| 20,000 | 0.956 s | 9,458 |
| 50,000 | 2.186 s | 22,661 |

The shipped demo campaign (2,732 events) completes in
0.131 s; the documented 50,000-event cap completes in
2.186 s. In-memory graph analytics are comfortable to about
50,000 events per analysis; beyond that we shard or move to a graph database.

## 6. PS7 operational evidence

Measured by `scripts/eval_ps7.py` over every shipped scenario, and by
`scripts/eval_retrieval.py` over the evidence gold set. Both run from a fresh
clone with no dataset download.

| Measure | Result |
|---|---|
| ATT&CK mapping coverage (alerts carrying a technique) | 100.0% |
| Technique-ID validity against the parsed ATT&CK STIX | 100.0% |
| Event to technique precision | Not measured (no per-event ATT&CK ground truth exists in these datasets) |
| SOAR playbook coverage of observed tactics | 100.0% |
| MITRE mitigation coverage of observed techniques | 100.0% |
| Actions executed against real systems | 0 (by design) |
| Investigation latency, p50 then p95 | 208 ms then 1793 ms |
| Evidence recall@1 then recall@5 (lexical, the shipped backend) | 64.3% then 85.7% |
| Evidence MRR (lexical, the shipped backend) | 0.738 |
| Citation integrity failures | 0 |
| Audit tampering detected | yes |
| Unauthorised approval blocked server side | yes |
| Mean time to respond | Not measured (every action is simulated, so there is no repair to time) |

**Which retriever produced those rows: the lexical one, and it is the one that
ships.** `requirements-deploy.txt` deliberately excludes `chromadb` and
`sentence-transformers`, so the deployed container answers every query from the
bundled BM25 index. The retrieval rows above are the numbers that container
produces, not a better number measured on a machine with more installed.

A semantic retriever (MiniLM + ChromaDB) does score better on a shared subset,
and it is **full install only, not in the deployed image**:

| Retriever | Recall@1 | Recall@5 | MRR | p50 | In the deployed image |
|---|---|---|---|---|---|
| Lexical BM25, bundled | 60.0% | 80.0% | 0.683 | 2.7 ms | **yes, this is what ships** |
| MiniLM + ChromaDB | 70.0% | 100.0% | 0.850 | 6.3 ms | no, full install only |

Scored over 10 shared queries at k=5; the
4 queries answerable only from the bundled index
are excluded from both sides. Full workings in `reports/retrieval_compare.md`.

The cost of shipping the weaker one is
20 percentage points of recall@5.
The reason is measured, not assumed: `sentence-transformers` pulls torch for
1.09 GB of installed dependencies against a 512 MB free-tier instance, and the
query path loads MiniLM at request time from a weights file that is neither
vendored nor pre-fetched, so the first query in a fresh container would reach out
to HuggingFace and break the offline guarantee. ADR 0008 records the decision and
what would reverse it.

## 7. Engineering

- 672 automated tests, no network required (pipeline correctness, multi-pivot
  graph, cross-screen consistency, calibration spread, intelligence mapping
  precision, evidence retrieval and citation integrity, prompt-injection handling,
  RBAC denials, audit tamper detection, digital-twin non-mutation, vulnerability
  monotonicity, workflow boundedness and degradation, SSRF guards, and the SPA
  payload contract).
- One container: FastAPI serves the built SPA from the same origin. Verify it with
  `scripts/verify.ps1 -Docker` (or `bash scripts/verify.sh --docker`), which builds
  the image and smoke-tests the running container.
- Drift-proof metrics: eval scripts write `reports/metrics.json`, the UI reads
  it, and `scripts/audit_stale.py` fails if any doc cites an out-of-date number.

## Source files

| What | File |
|---|---|
| Canonical metrics (machine-readable) | `reports/metrics.json` |
| LANL detection report | `reports/lanl_redteam_detection.md` |
| CIC-IDS2017 report | `reports/evaluation_report.md` |
| UNSW-NB15 report | `reports/unsw_evaluation.md` |
| Predictor report | `reports/prediction_eval.md` |
| Model bake-off (all variants) | `reports/model_experiments.md` |
| Attribution report | `reports/attribution_eval.md` |
| Scaling measurements | `reports/scaling_measurements.json` |
| PS7 operational evaluation | `reports/ps7_eval.md` |
| Evidence retrieval evaluation | `reports/retrieval_eval.md` |
| Evidence index composition | `reports/evidence_index.md` |
