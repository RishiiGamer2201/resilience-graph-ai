# UNSW-NB15 preparation

The official training/testing split is preserved; no rows are shuffled, synthesized, or moved between splits.

| Split | Raw rows | Clean rows | Duplicates removed | Benign | Attack | Model features |
|---|---:|---:|---:|---:|---:|---:|
| Train | 175,341 | 175,341 | 0 | 56,000 | 119,341 | 42 |
| Test | 82,332 | 82,332 | 0 | 37,000 | 45,332 | 42 |

`id` and `attack_cat` are excluded from model features. `label` and `attack_cat` remain in parquet solely for evaluation and reporting.