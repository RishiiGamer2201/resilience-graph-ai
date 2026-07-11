# Engine 2 — technique embeddings

- Model: `all-MiniLM-L6-v2` (384-d, pretrained; no fine-tuning).
- Techniques embedded: **794**.

## Sanity check (same-tactic techniques should cluster)
- Mean cosine, **same-tactic** pairs: **0.403**
- Mean cosine, random pairs: 0.330
- Gap: **+0.074** (PASS — same-tactic techniques are closer).