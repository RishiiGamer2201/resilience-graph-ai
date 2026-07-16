# Engine 2 — attack sequence dataset

- Sequences: **205** = 145 groups + 56 campaigns (auto, kill-chain-ordered) + **4 manual** (E2.2b, report-ordered, forced into TEST).
- Manual sequences verified by an analyst: **4/4** (flip `verified` in `data/manual/cert_in_sequences.json` after checking mappings).
- Prediction vocabulary: **622** distinct techniques
- Length: min 5 · mean 28.3 · max 131
- Split (sequence-level): {'train': 140, 'val': 30, 'test': 35}

## Honest split disclosure
- **Auto** sequences (groups/campaigns) are ordered by the kill-chain tactic heuristic — a model could partly re-learn that ordering (circularity risk).
- **Manual** sequences are ordered by the REAL reported timeline of India-relevant campaigns (APT36, RedEcho, ransomware, exploit→exfil) and live only in TEST, so accuracy on them is the non-circular headline.

⚠️ Anti-circularity: predictor must beat a kill-chain-order baseline + a most-frequent baseline (see E2.4).