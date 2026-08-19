# Retrieval head-to-head: lexical vs semantic

Evaluated: 2026-08-19 22:36 IST  ·  k=5  ·  10 shared gold queries (4 excluded: answerable only by the bundled index)

| Metric | Lexical (BM25, bundled) | Semantic (MiniLM + ChromaDB) |
|---|---|---|
| Recall@1 | 0.6 | 0.7 |
| Recall@5 | 0.8 | 1.0 |
| MRR | 0.6833 | 0.85 |
| Latency p50 (ms) | 2.7 | 6.3 |
| Latency max (ms) | 34.1 | 7.2 |
| Requires | nothing (bundled, offline, no dependency) | chromadb + sentence-transformers |

Scored on what the retrieved chunk REFERS to (ATT&CK technique family, or publisher), because the two indexes use different chunk ids. The four analyst-verified CERT-In advisories exist only in the bundled index and are excluded from both sides.

## Per query

| Query | Expected | Lexical rank | Semantic rank |
|---|---|---|---|
| how do attackers reuse stolen password hashes to move between hosts | `attack:T1550.002` | 1 | 2 |
| adversary logs in with a legitimate account instead of malware | `attack:T1078` | MISS | 1 |
| lateral movement using remote services like SMB and RDP | `attack:T1021` | 1 | 2 |
| repeated failed logins guessing passwords | `attack:T1110` | 1 | 1 |
| collecting data from internal wikis and databases | `attack:T1213` | 3 | 1 |
| stealing data out over the command and control channel | `attack:T1041` | 2 | 1 |
| enumerating other machines on the network | `attack:T1018` | MISS | 2 |
| what does MITRE recommend to mitigate pass the hash | `attack:T1550.002` | 1 | 1 |
| actively exploited vulnerability that CISA requires federal agencies to patch | `any CISA doc` | 1 | 1 |
| known exploited Microsoft Windows privilege escalation flaw | `any CISA doc` | 1 | 1 |
