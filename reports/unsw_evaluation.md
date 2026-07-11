# UNSW-NB15 benign-only anomaly evaluation

The official train/test split is preserved. IsolationForest and preprocessing fit only on benign official-training rows; labels/categories are evaluation-only.

- Train benign rows: **56,000** · test rows: **82,332** · test attack prevalence: **55.06%**
- Feature count: **42**; identifier `id` and label-derived `attack_cat` excluded.
- Threshold: 99th percentile of benign-training anomaly scores (no test-label selection).

| Method | PR-AUC | ROC-AUC | Precision | Recall | F1 | Alert rate |
|---|---:|---:|---:|---:|---:|---:|
| Random | 0.5508 | 0.5002 | 0.5692 | 0.0103 | 0.0203 | 1.00% |
| Rule (sbytes) | 0.4765 | 0.3006 | 0.6844 | 0.0233 | 0.0451 | 1.87% |
| IsolationForest | 0.8674 | 0.8286 | 0.9656 | 0.2333 | 0.3758 | 13.30% |

- IsolationForest PR-AUC lift: **1.57×** over random and **1.82×** over the `sbytes` rule.

## Per-attack-category recall (IsolationForest)

| Category | Count | Caught | Recall |
|---|---:|---:|---:|
| Generic | 18,871 | 10,092 | 0.535 |
| Worms | 44 | 4 | 0.091 |
| DoS | 4,089 | 127 | 0.031 |
| Exploits | 11,132 | 272 | 0.024 |
| Backdoor | 583 | 6 | 0.010 |
| Fuzzers | 6,062 | 59 | 0.010 |
| Reconnaissance | 3,496 | 15 | 0.004 |
| Analysis | 677 | 0 | 0.000 |
| Shellcode | 378 | 0 | 0.000 |