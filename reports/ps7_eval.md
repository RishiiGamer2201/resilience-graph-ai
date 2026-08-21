# PS7 operational evaluation

Evaluated: 2026-08-21 20:07 IST  ·  2 run(s) per scenario

## Per scenario

| Scenario | Events | Alerts | Incidents | MTTD | Exposure | Likelihood | Evidence conf. | Actionable claims | Citations | Actions (gated) | Executed | Median latency |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aiims_ransomware | 125 | 125 | 1 | immediate | 100.0 | 52.6 | 73.4 | 0/2 | 6 | 5 (4) | 0 | 4851 ms |
| cbse_exam_breach | 127 | 127 | 1 | immediate | 100.0 | 52.6 | 73.5 | 0/2 | 6 | 5 (4) | 0 | 115 ms |
| lanl_campaign_all | 2732 | 1243 | 1 | immediate | 80.0 | 60.0 | 85.0 | 1/4 | 6 | 5 (4) | 0 | 1216 ms |
| lanl_redteam_u66 | 215 | 208 | 1 | immediate | 5.0 | 60.0 | 85.0 | 1/3 | 6 | 5 (4) | 0 | 121 ms |

## ATT&CK mapping

- alerts carrying a technique: **100.0%** (320 of 320)
- emitted technique IDs valid against the canonical ATT&CK lookups: **100.0%** (invalid: none)
- event->technique precision: **Not measured** — Not measured: no public dataset used here carries a per-event ATT&CK technique label, so event->technique precision cannot be computed. We report coverage and ID validity, which we can.

## SOAR coverage

- observed tactics with a playbook action: **100.0%** (Credential Access, Initial Access, Lateral Movement)
- observed techniques with real MITRE mitigations: **100.0%**
- actions executed against a real system: **0** (by design — every action is simulated and human-gated)

## Latency

- p50 **121 ms**, p95 **1223 ms**, max 9589 ms over 8 runs (full 7-node investigation, warm process, laptop CPU, no GPU)

## MTTD / MTTR

- MTTD: seconds from the first event in the log to the first correlated alert. Per scenario: aiims_ransomware 0s, cbse_exam_breach 0s, lanl_campaign_all 0s, lanl_redteam_u66 0s
- MTTR: **Not measured.** Every response action in this product is SIMULATED and human-gated. With no execution there is no repair to time. Claiming an MTTR improvement would be fabricating the headline number PS7 asks for.

## Auditability and authorisation

- hash chain verifies: **True**; tampering detected: **True** (`record 1 (analysis.completed): content hash mismatch — this record's contents were altered after it was written`)
- viewer denied `approve_critical`: **True**; crown-jewel action gated: **True**; low-impact pre-approved: **True**
