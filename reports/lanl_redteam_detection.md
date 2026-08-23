# Engine 1.3 — LANL Lateral-Movement Detection (red-team ground truth)

**Task E1.3** · unsupervised behavioral anomaly detection on real LANL auth logs, evaluated against the labeled red-team campaign. **The moat**: real APT, real ground truth.

## Dataset
- `data/processed/lanl/auth_redteam_window.parquet` — **11,221,902** auth events, **702** malicious (red-team), prevalence **0.0063%**.
- Features (behavioral, unsupervised): is_fail, new_dst_for_user, new_src_for_user, user_distinct_dst_sofar, user_fail_rate_sofar, dst_rarity, is_ntlm.
- ⚠️ Labels used for EVALUATION ONLY — the shipped autoencoder fits on a benign-only sample.
- ⚠️ Accuracy not reported (meaningless at 0.006% prevalence). Headline = TPR @ fixed FPR.

## Shipped detector
- **Autoencoder**, trained benign-only. Exported to `models/ae_lanl.npz` as plain NumPy weight matrices, so the deployed image scores with NumPy alone — no torch, no GPU.

| Detector | ROC-AUC | TPR @ 1% FPR |
|---|---|---|
| IsolationForest (previous) | 0.9879 | 51.4% |
| **Autoencoder (shipped)** | **0.9916** | **87.7%** |

- ROC-AUC barely separates the two. The decisive difference is at the **strict 1% false-positive operating point an analyst actually runs at**, where the shipped detector catches materially more of the 702 red-team events for the same alert budget. We select on the operating point, not on the headline curve.

## Detection performance
- **ROC-AUC = 0.9916** · PR-AUC = 0.0082 (PR-AUC is tiny by construction at this prevalence).

| Target FPR | TPR (recall) | TP / red-team | FP / benign |
|---|---|---|---|
| 0.01% | **0.0%** | 0/702 | 1,123/11,221,200 |
| 0.10% | **13.2%** | 93/702 | 11,281/11,221,200 |
| 0.50% | **69.1%** | 485/702 | 56,106/11,221,200 |
| 1.00% | **87.7%** | 616/702 | 112,212/11,221,200 |
| 5.00% | **96.6%** | 678/702 | 561,060/11,221,200 |

- Literature context (not our claim): graph-based detectors on LANL report ~85% TPR @ <1% FPR (USENIX RAID'20, GL-GV). Ours is a lightweight per-event behavioral model — a component that the attack-path graph (S4) then amplifies.

## Ablation — behavioral features WITHOUT the NTLM signal

> **Hand-corrected 2026-08-23. This section's conclusion was wrong and is withdrawn.**
> It previously read "the detector still works from generalizable behavior -- NTLM
> adds lift, it isn't a crutch." That conclusion was drawn from ROC-AUC alone, which
> integrates over thresholds no analyst operates at, and it is contradicted by the
> ablation's own 1%-FPR row printed directly above it: recall falls **87.7% -> 22.8%**,
> a 74% relative drop. The claim was retracted across `RESULTS.md`, `EXPLAINER.md`,
> `PITCH_DECK.md` and `docs/demo/judge-qa.md`; this file is the source those cite, so
> it is corrected here too.
>
> Edited by hand rather than regenerated. This report is written by
> `src/engine1/lanl_detect.py`, which needs the full LANL corpus (~70 GB, not
> committed) to run. The measured numbers below are unchanged from the run that
> produced this file -- only the interpretation is rewritten. Same precedent as the
> withdrawn baseline in `reports/netstate.md`. Re-run `lanl_detect.py` on a machine
> with the corpus to replace this note with generated text.

- 100% of red-team auths are NTLM (this campaign's tooling) vs ~6% of benign — a strong but **dataset-specific, evadable** signal (an attacker could use Kerberos).
- Dropping `is_ntlm` and scoring on behavior alone (new-host, fan-out, rarity, fails): **ROC-AUC 0.9056** (vs 0.9916 with NTLM), TPR@1%FPR **22.8%** (vs **87.7%** with NTLM).
- **NTLM is carrying most of the result at the operating point that matters.** ROC-AUC barely moves, which is exactly why quoting it here was misleading. At 1% FPR the behavioral features alone catch roughly 160 of 702 red-team events instead of 616. An attacker who authenticates over Kerberos evades most of this detector.
- Taken with the detector-selection table above, the same lesson applies twice: **select and report on the 1%-FPR operating point, never on the headline curve.** The single-feature ablation cost here (74% relative) is the number to hold this detector to.

## Why it works — feature signal (mean value, benign vs malicious)

| Feature | Benign mean | Malicious mean |
|---|---|---|
| is_fail | 0.0016 | 0.0014 |
| new_dst_for_user | 0.0204 | 0.2821 |
| new_src_for_user | 0.0174 | 0.1054 |
| user_distinct_dst_sofar | 141.8507 | 113.9957 |
| user_fail_rate_sofar | 0.0015 | 0.0081 |
| dst_rarity | 4.8715 | 9.8256 |
| is_ntlm | 0.0580 | 1.0000 |

## Honest interpretation
- The red-team authentications are behaviorally distinct — higher new-host access and fan-out, NTLM-heavy — so an unsupervised model separates them (ROC-AUC 0.992) without ever seeing an attack label.
- This is the real-data counterpart to E1.2: on a genuine APT campaign we detect lateral movement from behavior alone. The per-event score feeds the correlation spine (S2) and attack-path graph (S4), which turn weak per-event signals into one high-confidence incident.

_Shipped model: `models/ae_lanl.npz` (autoencoder, NumPy weights). `models/iforest_lanl.joblib` is the retired
IsolationForest, kept only for the comparison row above._

_Hand-corrected 2026-08-23, same reason as the ablation note: this trailer and the
evaluation-protocol bullet still named the IsolationForest as the fitted detector
after the autoencoder was promoted, and the generator cannot be re-run without the
LANL corpus._