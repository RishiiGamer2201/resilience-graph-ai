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

The NTLM ablation: 100% of red-team logins used the older NTLM protocol versus
about 6% of benign, a powerful but evadable signal. Removing it and scoring on
behaviour alone still gives ROC-AUC 0.906, so detection is
driven by generalisable behaviour, not one brittle artifact.

## 2. Prediction and attribution (Engine 2)

Predict the attacker's next ATT&CK technique from the sequence so far, learned
from 205 real attack sequences.

| Method | Top-3 accuracy | Status |
|---|---|---|
| Most-frequent baseline | 4.9% | baseline |
| Kill-chain order baseline | 7.1% | baseline built to beat us |
| LSTM over MiniLM embeddings | 27.2% | lost, documented negative |
| Markov, first order | 36.5% | previous shipped |
| **Interpolated Markov** | **38.1%** | **shipped** |

Anti-circularity: the sequences are tactic-ordered, so a model could cheat by
re-learning that order. The shipped model beats the kill-chain baseline by
**5.4x**, evidence it predicts real technique-to-technique transitions. The
neural models (LSTM 27.2%, and a bidirectional LSTM at 20.0% in
`reports/model_experiments.md`) both lost at this data scale, so we ship the
simpler winner.

Non-circular India test: on 4 analyst-verified CERT-In sequences ordered by the
real reported timeline (not our heuristic), top-3 is
10.0% versus 38.1%
on the auto-ordered set. Real orderings are harder; we publish both.

Attribution: transparent weighted retrieval over 172 MITRE group profiles
(coverage 0.55, Jaccard 0.20, semantic similarity 0.25), with a printed
justification. Not a trained classifier, and we say so. Technique embeddings
separate same-tactic pairs at cosine 0.412 versus
0.327 for random pairs.

## 3. Operational output (live campaign analysis)

Live run of the full LANL red-team campaign through the complete pipeline.

| Output | Value |
|---|---|
| Events analysed, alerts, incidents | 2,732 then 1,243 then 1 |
| Compromised accounts | 104 |
| Attack graph | 473 hosts, 484 movements, 4 attacker pivots |
| Critical assets reachable | 16 |
| Total exposure | 469 hosts |
| Isolate the single best choke point | severs 463 hosts |

## 4. Performance and scalability

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

## 5. PS7 operational evidence

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
| Investigation latency, p50 then p95 | 51 ms then 224 ms |
| Evidence recall@1 then recall@5 | 64.3% then 85.7% |
| Evidence MRR | 0.717 |
| Citation integrity failures | 0 |
| Audit tampering detected | yes |
| Unauthorised approval blocked server side | yes |
| Mean time to respond | Not measured (every action is simulated, so there is no repair to time) |

## 6. Engineering

- 168 automated tests, no network required (pipeline correctness, multi-pivot
  graph, cross-screen consistency, calibration spread, intelligence mapping
  precision, evidence retrieval and citation integrity, prompt-injection handling,
  RBAC denials, audit tamper detection, digital-twin non-mutation, vulnerability
  monotonicity, workflow boundedness and degradation, SSRF guards, and the SPA
  payload contract).
- Browser end-to-end across 15 user flows, 14 passed.
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
