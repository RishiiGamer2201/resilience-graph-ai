# Engine 2.5 — ATT&CK actor-profile similarity and attribution gate

This is transparent profile retrieval over public ATT&CK group technique usage, not a trained classifier or independent incident-telemetry benchmark.

- ATT&CK group profiles: **175**
- Groups evaluated using a deterministic 60% observed / 40% withheld profile split: **169**
- Top-1 retrieval: **100.0%**
- Top-3 retrieval: **100.0%**
- Mean reciprocal rank: **1.000**

## Runtime attribution decision

- Independently labelled incident-attribution benchmark: **not available (0 incidents)**
- Calibrated score and top-two-margin thresholds: **not available**
- Runtime actor attribution: **disabled; returns `unattributed`**
- Safety floors: zero exact overlap always abstains; one observed/common technique always abstains.
- Ranked names are exposed only as **similar public ATT&CK profiles**, with the score, exact evidence count, margin, alternatives, negative evidence and abstention reason.

The 100% self-profile retrieval result above cannot calibrate attribution: each test row is a partial copy of the same public profile being retrieved, not an independent incident with a verified actor label.

Scores combine observed-technique coverage (55%), Jaccard overlap (20%), and embedding semantic similarity (25%). Optional Markov next-technique evidence is capped at 20% of the final score.