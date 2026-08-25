# Engine 2.4 — ATT&CK Technique-Association Ranker

Rank a held-out profile technique from a partial tactic-sorted profile. Test = 777 prediction points across 35 held-out sequences (vocab 566, OOV next-techniques counted as misses: 45).

| Method | top-1 | top-3 | top-5 |
|---|---|---|---|
| Most-frequent (baseline) | 1.9% | 4.9% | 8.6% |
| Markov 1st-order (previous) | 22.9% | 36.7% | 44.7% |
| Markov interpolated λ=(0.2, 0.3, 0.5) (SHIPPED) | 23.2% | 38.2% | 44.5% |
| Kill-chain order (baseline ⚠️) | 3.6% | 7.1% | 9.3% |
| LSTM (embeddings) | 13.9% | 29.3% | 37.6% |

## Interpretation (data-driven)
- **Interpolation mass is preserved:** for each prefix, stored lambdas are renormalized across the unigram, first-order and second-order components that have data. The complete candidate distribution therefore sums to 1. Its values are normalized model weights, not observed frequencies, calibrated confidence, or future probabilities.
- **Shipped association ranker: Markov interpolated λ=(0.2, 0.3, 0.5) (SHIPPED)** — best profile-position top-3 (38.2%) on this data.
- **Profile-position comparison:** shipped ranker top-3 (38.2%) is **5.4× the kill-chain-order baseline** (7.1%). The rows are ATT&CK group/campaign profiles sorted by a tactic heuristic, not observed timelines. Beating this baseline supports **association ranking only**; it does not establish real chronological transitions.
- **Neural is not justified here (honest negative result):** the LSTM (29.3% top-3) is 0.80× Markov — it beats the naive baselines but not the transition model at this data scale. Kept as a documented comparison, not the deliverable.
- Top-1 is a hard bar with a 566-way vocabulary and 140 training profiles; **top-3/top-5 describe held-out profile positions**, not the probability of an attacker making a next move.

## Independent chronological gate — CERT-In / India timelines
- Shipped Markov model on **4 hand-curated** report-ordered sequences (27 prediction points, 6 OOV): **top-1 3.7% · top-3 11.1% · top-5 11.1%**.
- Strongest baseline: **most_frequent**; gain: **3.7 points**; sequence-bootstrap 95% interval: **[-22.2, 25.0] points**.
- **Chronological next-move output enabled: false.** Chronological next-move prediction is disabled: the source-provenanced timeline benchmark does not yet show a statistically reliable improvement over the strongest baseline.

_Shipped: `models/next_technique_markov.pkl` · LSTM comparison: `models\next_technique_lstm.pt` · sequences E2.2 · embeddings E2.3._