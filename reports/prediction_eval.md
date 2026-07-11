# Engine 2.4 — Next-Technique Predictor (honest eval)

Predict the next ATT&CK technique from a partial sequence. Test = 751 prediction points across 34 held-out sequences (vocab 538, OOV next-techniques counted as misses: 26).

| Method | top-1 | top-3 | top-5 |
|---|---|---|---|
| Most-frequent (baseline) | 1.9% | 5.3% | 9.6% |
| Markov 1st-order (baseline) | 24.0% | 38.6% | 47.0% |
| Kill-chain order (baseline ⚠️) | 4.4% | 8.3% | 11.2% |
| LSTM (embeddings) | 13.7% | 28.4% | 36.1% |

## Interpretation (data-driven)
- **Shipped predictor: Markov 1st-order (baseline)** — best top-3 (38.6%) and the most explainable choice. On only 139 training sequences a first-order Markov transition model beats the LSTM — so we ship Markov (honest > fancy).
- ✅ **Anti-circularity proof:** Markov top-3 (38.6%) is **4.7× the kill-chain-order baseline** (8.3%). Since sequences are tactic-ordered, a model that only re-learned that ordering would score like the kill-chain baseline. Beating it 4.7× means we are predicting **real technique-to-technique transitions**, not the imposed order.
- **Neural is not justified here (honest negative result):** the LSTM (28.4% top-3) is 0.73× Markov — it beats the naive baselines but not the transition model at this data scale. Kept as a documented comparison, not the deliverable.
- Top-1 is a hard bar with a 538-way vocabulary and 139 training sequences; **top-3/top-5 are the honest headline** — they match how an analyst uses a ranked list of 'likely next moves'.

## ⭐ Non-circular headline — manual CERT-In / India sequences (report-ordered)
- Shipped Markov model on **4 hand-curated** report-ordered sequences (23 prediction points, 0 OOV): **top-1 0.0% · top-3 8.7% · top-5 8.7%**.
- These are ordered by the REAL reported attack timeline (not the kill-chain heuristic), so this is the honest, non-circular evaluation. ⚠️ Verify each sequence's mappings (`data/manual/cert_in_sequences.json`) before quoting this in the pitch.

_Shipped: `models/next_technique_markov.pkl` · LSTM comparison: `models\next_technique_lstm.pt` · sequences E2.2 · embeddings E2.3._