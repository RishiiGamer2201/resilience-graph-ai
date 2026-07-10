# Engine 1 — Anomaly Detection Evaluation (CIC-IDS2017)

**Task E1.2** · unsupervised anomaly detection on real network flows, evaluated with imbalance-robust metrics against two trivial baselines.

## 1. Dataset
- Source: `data/processed/cicids2017/flows.parquet` — **2,094,130** flows in this experiment, 77 numeric flow features.
- Class balance overall: ~85.4% benign / 14.6% attack (extreme imbalance).
- ⚠️ **Accuracy is deliberately NOT reported** — an all-benign guess scores ~84.5% on the test set yet catches zero attacks.

## 2. Train / test split (by DAY — no random shuffle, no leakage)
- **Train (benign-only):** Mon–Wed benign flows = **1,230,630** rows (label==0 only). Attack rows on those days are discarded — the model never sees an attack.
  - Monday: 458,831, Tuesday: 380,564, Wednesday: 391,235 benign rows.
- **Test (full):** Thu–Fri = **863,500** rows (**729,914** benign / **133,586** attack; prevalence = 15.47%).
- Attack families present in the TEST set (all unseen in training): Infiltration, DDoS, Bot, PortScan, Web Attack - Brute Force, Web Attack - XSS, Web Attack - Sql Injection.
- ⚠️ **No SMOTE / resampling.** Training is benign-only & unsupervised, so resampling the (absent) attack class is inapplicable by construction.

## 3. Operating point
- PR-AUC and ROC-AUC are threshold-free.
- Precision / recall / F1 are reported at a **~1% false-positive budget**: the threshold = 99th percentile of each detector's score on TRAIN-benign (chosen without ever looking at test labels).

## 4. Results — Random vs Rule vs IsolationForest

| Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | Alert rate |
|---|---|---|---|---|---|---|
| Random | 0.1547 | 0.4999 | 0.1530 | 0.0099 | 0.0186 | 1.00% |
| Rule (Flow Packets/s) | 0.0978 | 0.2523 | 0.0026 | 0.0002 | 0.0003 | 0.93% |
| IsolationForest | 0.4730 | 0.8257 | 0.5628 | 0.1672 | 0.2579 | 4.60% |
| Autoencoder | 0.5696 | 0.8364 | 0.7451 | 0.3920 | 0.5138 | 8.14% |

- Random-baseline PR-AUC ≈ prevalence (0.1547) — the theoretical floor.

## 5. Lift over baselines (the actual Technical-Excellence claim)
- IsolationForest PR-AUC = **0.4730**.
- **3.1× lift over the Random baseline** (PR-AUC 0.1547).
- **4.8× lift over the Rule baseline** (Flow Packets/s threshold, PR-AUC 0.0978).

## 6. Per-attack-type recall (IsolationForest @ ~1% FPR)

| Attack family | Count | Caught | Recall |
|---|---|---|---|
| Infiltration | 36 | 16 | 0.444 |
| DDoS | 128,014 | 22,242 | 0.174 |
| Bot | 1,437 | 44 | 0.031 |
| PortScan | 1,956 | 38 | 0.019 |
| Web Attack - Brute Force | 1,470 | 0 | 0.000 |
| Web Attack - XSS | 652 | 0 | 0.000 |
| Web Attack - Sql Injection | 21 | 0 | 0.000 |

## 7. Honest interpretation
- The detector is trained **benign-only / unsupervised** and never sees an attack label at train time; labels are used strictly for evaluation. This sidesteps the 85/15 imbalance trap by design, which is why we **avoid accuracy entirely** and headline **PR-AUC**.
- The result that matters is **lift**: IsolationForest beats the random floor by **3.1×** on PR-AUC (and the naive volumetric rule, which is actually *worse than random* here — ROC-AUC 0.25 — because stealthy attacks have LOW packet rates). Real signal, not a lone accuracy number.
- **Best model: Autoencoder** (PR-AUC 0.570, ROC-AUC 0.836, 3.7× over random) — the benign-trained autoencoder edges out IsolationForest.
- Recall at the strict ~1% FPR operating point is **modest** (best family: Infiltration (0.44)); most families are only partially flagged and stealthy web attacks are missed by the flow-only view. This is the honest limitation that motivates E1.3 (LANL lateral-movement on real red-team labels) and the correlation spine — single-flow anomaly scoring is a component, not the whole story.

_Artifacts: model `models\iforest_cicids.joblib`, PR curve `reports\pr_curve_cicids.png`._