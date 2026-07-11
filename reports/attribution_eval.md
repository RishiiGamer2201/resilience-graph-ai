# Engine 2.5 — ATT&CK actor-profile attribution

This is transparent profile retrieval over public ATT&CK group technique usage, not a trained classifier or independent incident-telemetry benchmark.

- ATT&CK group profiles: **172**
- Groups evaluated using a deterministic 60% observed / 40% withheld profile split: **168**
- Top-1 retrieval: **100.0%**
- Top-3 retrieval: **100.0%**
- Mean reciprocal rank: **1.000**

Scores combine observed-technique coverage (55%), Jaccard overlap (20%), and embedding semantic similarity (25%). Optional Markov next-technique evidence is capped at 20% of the final score.