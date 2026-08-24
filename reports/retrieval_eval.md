# Evidence retrieval evaluation

Evaluated: 2026-08-25 03:52 IST  ·  corpus 1545 chunks  ·  k=5

| Metric | Value |
|---|---|
| Queries | 14 |
| Recall@1 | 0.643 |
| Recall@5 | 0.857 |
| MRR | 0.738 |
| Citation integrity failures | 0 |

## Per-query

| Query | Expected | Rank | Top hit |
|---|---|---|---|
| how do attackers reuse stolen password hashes to move between hosts | `attack:T1550.002` | 1 | MITRE ATT&CK T1550.002 — Pass the Hash |
| adversary logs in with a legitimate account instead of malware | `attack:T1078` | MISS | MITRE ATT&CK T1654 — Log Enumeration |
| lateral movement using remote services like SMB and RDP | `attack:T1021` | 1 | MITRE ATT&CK T1021 — Remote Services |
| repeated failed logins guessing passwords | `attack:T1110` | 1 | MITRE ATT&CK T1110.001 — Password Guessing |
| collecting data from internal wikis and databases | `attack:T1213` | 3 | MITRE ATT&CK T1590.002 — DNS |
| stealing data out over the command and control channel | `attack:T1041` | 2 | MITRE ATT&CK T1646 — Exfiltration Over C2 Channel |
| enumerating other machines on the network | `attack:T1018` | MISS | CISA KEV CVE-2026-22769 — Dell RecoverPoint for Virtual Machines (RP4VMs) |
| what does MITRE recommend to mitigate pass the hash | `attack:T1550.002` | 1 | MITRE ATT&CK T1550.002 — Pass the Hash |
| WhatsApp distributed VBScript loader taking over remote management tools | `certin:0` | 1 | Malware Campaign spreading through WhatsApp Attachments |
| Android banking trojan disguised as an RTO eChallan alert | `certin:1` | 1 | Sophisticated RTO/eChallan themed Android Malware Campaign targeting Sensitive Information |
| malicious npm and PyPI packages in a software supply chain attack | `certin:2` | 2 | MITRE ATT&CK T1195.001 — Compromise Software Dependencies and Development Tools |
| Fortigate SSL VPN administrator credential exposure | `certin:3` | 1 | Potential Exposure of FortiGate Administrative and VPN Credentials (FortiBleed) |
| actively exploited vulnerability that CISA requires federal agencies to patch | `any CISA doc` | 1 | CISA KEV CVE-2025-20333 — Cisco Secure Firewall Adaptive Security Appliance and Secure Firewall Threat Defense |
| known exploited Microsoft Windows privilege escalation flaw | `any CISA doc` | 1 | CISA KEV CVE-2021-43226 — Microsoft Windows |

Hand-written gold set over the bundled corpus. Small by construction; reported as-is rather than inflated with auto-generated queries that restate the document they came from.

Scoring: a technique query is correct if the retrieved chunk is the expected technique or another member of the same technique family (a sub-technique of the expected parent). Unrelated techniques never count.

Known limitation: this is a lexical retriever. A fully paraphrased query that shares no vocabulary with the document ("logs in with a legitimate account instead of malware" vs "Valid Accounts") still misses. The documented upgrade path is a local embedding re-rank over the ATT&CK chunks using the MiniLM technique embeddings this repo already ships; it is not enabled because it needs the encoder in the deploy image, which the slim runtime deliberately excludes.

Retriever: BM25 over chunk text plus an exact-identifier boost for ATT&CK technique IDs and CVE IDs. No embedding model, no vector database, no network at query time.
