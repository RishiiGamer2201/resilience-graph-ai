# Engine 2 — technique embeddings

- Model: `all-MiniLM-L6-v2` (384-d, pretrained; no fine-tuning).
- Techniques embedded: **918**.

## Sanity check (same-tactic techniques should cluster)
- Mean cosine, **same-tactic** pairs: **0.412**
- Mean cosine, random pairs: 0.327
- Gap: **+0.084** (PASS — same-tactic techniques are closer).