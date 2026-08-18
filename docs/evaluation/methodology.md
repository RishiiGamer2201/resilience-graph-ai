# Evaluation methodology

How every number in this product is produced, and why the ones that are missing are
missing.

**Rule: no number appears in the UI, a report or a pitch unless a script wrote it to
`reports/metrics.json`.** The scoreboard reads that file. `scripts/audit_stale.py`
fails if any document cites a value that no longer matches.

---

## The harness

| Script | Writes | What it measures |
|---|---|---|
| `src/engine1/anomaly.py` | `engine1.cicids` | PR-AUC on CIC-IDS2017 against random and rule baselines |
| `src/engine1/lanl_detect.py` | `engine1.lanl` | ROC-AUC, TPR at 1% and 5% FPR, the NTLM ablation |
| `src/engine1/eval_unsw.py` | `engine1.unsw` | ROC-AUC / PR-AUC on the official UNSW-NB15 split |
| `src/engine2/build_predictor.py` | `engine2.predictor` | top-3 for every predictor variant plus both baselines |
| `src/engine2/build_embeddings.py` | `engine2.embeddings` | same-tactic vs random cosine separation |
| `scripts/eval_retrieval.py` | `retrieval.gold_set` | recall@1, recall@5, MRR, citation integrity |
| `scripts/eval_ps7.py` | `ps7.*` | mapping coverage and ID validity, SOAR coverage, MTTD, latency percentiles, audit tamper detection, RBAC denial |

The first five need the ~11 GB raw datasets and the full dependency set. **The last
two run from a fresh clone with no downloads** — they are the operational half, and
they are the ones a judge can reproduce in thirty seconds:

```powershell
python -m scripts.eval_ps7 --runs 3
python -m scripts.eval_retrieval
```

---

## Choices that matter

### Why never accuracy
LANL red-team prevalence is 0.006%. "Always benign" scores 99.994%. CIC-IDS2017 is
roughly 85/15. Accuracy on either is a number that cannot be wrong and therefore
cannot be informative. We report:

- **PR-AUC** for imbalanced flow detection;
- **TPR at a fixed FPR** for the operating point an analyst actually runs at — this
  is the number that decides whether a SOC can staff the alerts;
- **ROC-AUC** alongside, never alone, because it flatters everything at this
  prevalence.

### Every metric carries a baseline
A lone number is not evidence. Each card names what it is beating:

| Metric | Baseline | Why that baseline |
|---|---|---|
| TPR @ 1% FPR | IsolationForest at the same point | the model we replaced, so the comparison is a real decision we made |
| CIC-IDS2017 PR-AUC | rule baseline (0.098) and random (0.155) | the rule baseline scores *worse than random*, which is the honest finding |
| Next-technique top-3 | kill-chain-order baseline (7.1%) | built specifically to catch us re-learning tactic order |
| Evidence recall@5 | recall@1 | shows how much of the win is ranking versus retrieval |
| MTTD | Mandiant M-Trends 2024 median dwell (~10 days) | **a citation, not our measurement**, and labelled as such everywhere |

### No temporal leakage
CIC-IDS2017 splits by day. UNSW-NB15 keeps the official split. Attack sequences split
at sequence level, never at prediction-point level. Behavioural features are computed
per account in chronological order, using only what had happened *so far*.

### Sub-technique credit in retrieval scoring
A query for "repeated failed logins guessing passwords" that returns
`T1110.001 Password Guessing` is scored correct against an expected `T1110 Brute
Force`, because it is a sub-technique of the expected parent. An unrelated technique
never counts. Scoring the family as a miss would understate the retriever; scoring
anything as a pass would overstate it. The rule is stated in
`reports/retrieval_eval.md` and implemented in one function a reviewer can read.

### Deterministic scoring anchors
Anomaly scores are calibrated against **fixed** anchors (`api/cache/score_ref.json`:
benign p50 → 0, benign p99 → 50, extreme → 100), not per-batch min/max. A score of 62
means the same thing on your upload as on ours, and matches what `/api/score-event`
returns for the same feature vector. The alert threshold of 50 *is* the 1%
false-positive line — it is not a round number someone liked.

---

## What we do not measure, and why

These render as **Not measured** on the scoreboard with the reason attached. They are
not oversights.

**Mean time to respond (MTTR).** Every action is simulated and human-gated. With no
execution there is no repair to time. PS7 asks for MTTR; producing one would mean
inventing the headline number, which is the single most tempting dishonesty available
to this project.

**Event-to-technique precision.** No public dataset we use — LANL, CIC-IDS2017,
UNSW-NB15 — labels individual events with an ATT&CK technique. We report what we can
compute instead: mapping *coverage* (100% of correlated alerts carry a technique) and
*ID validity* (100% of emitted IDs exist in the parsed ATT&CK STIX, which is how a
hallucinated technique would surface).

**Attribution accuracy as a headline.** The profile-retrieval eval is near-trivial by
construction — techniques come from the same group profiles being matched. The report
exists (`reports/attribution_eval.md`); we deliberately do not put a percentage on a
card, and "100% attribution" is on the scoreboard's list of refused claims.

**Real-world false-positive rate in a live SOC.** We have no live SOC. The 1% FPR
figure is a chosen operating point on labelled benchmark data, not an observed
production rate.

**CVSS-weighted vulnerability severity.** CISA KEV publishes no CVSS and the NVD API
is rate-limited. The factor is reported as `unknown`, dropped from the weighted
average, and reflected in a lower confidence — never scored zero.

---

## Reproducing the operational numbers

```powershell
python -m scripts.eval_ps7 --runs 3        # -> reports/ps7_eval.md
python -m scripts.eval_retrieval           # -> reports/retrieval_eval.md
python -m scripts.make_results_md          # -> RESULTS.md, from the metrics store
python -m scripts.audit_stale              # fails if any doc drifted
python -m pytest tests/ -q                 # 134 tests
```

Latency figures depend on the machine; everything else is deterministic and should
reproduce byte-for-byte, except where a rebuilt evidence index has picked up a newer
CISA KEV catalogue.

## Where the evidence lives

| Report | Contents |
|---|---|
| `reports/metrics.json` | canonical machine-readable store — the single source of truth |
| `reports/ps7_eval.md` | PS7 operational metrics, per scenario |
| `reports/retrieval_eval.md` | retrieval gold set, per query, including misses |
| `reports/lanl_redteam_detection.md` | LANL detection and the NTLM ablation |
| `reports/evaluation_report.md` | CIC-IDS2017 |
| `reports/unsw_evaluation.md` | UNSW-NB15 |
| `reports/prediction_eval.md` | next-technique prediction and baselines |
| `reports/model_experiments.md` | every variant tried, including the losers |
| `reports/attribution_eval.md` | actor attribution |
| `reports/evidence_index.md` | corpus composition and source status |
| `reports/scaling_measurements.json` | pipeline timing at nine input sizes |
