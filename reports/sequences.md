# Engine 2 — attack sequence dataset

- Sequences: **199** (145 groups + 54 campaigns, >= 6 techniques)
- Prediction vocabulary: **575** distinct techniques
- Length: min 6 · mean 28.6 · max 130
- Split (sequence-level): {'train': 139, 'val': 30, 'test': 30}
- All auto-ordered by kill-chain tactic order (is_manual=False).
- TODO: add 3-5 hand-curated CERT-In advisory sequences (is_manual=True).

⚠️ Anti-circularity: predictor must beat a kill-chain-order baseline + a
most-frequent baseline (see E2.4), since ordering here is heuristic.